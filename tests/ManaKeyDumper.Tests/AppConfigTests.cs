using GenshinSniffer;
using GenshinSniffer.Utilities;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 游戏路径解析测试。
///
/// 实际使用中「手上只有目录、没有 exe 全路径」很常见（切换器/资源包就是按目录给的），
/// 以前传目录会被判成"未找到游戏"。另外双击启动**没法传参数**，所以还有一条
/// exe 同目录 `game_path.txt` 的来源 —— 个人路径必须留在本地文件里，不能进公开仓库。
/// </summary>
public sealed class AppConfigTests : IDisposable {

    private readonly string _dir = Directory.CreateTempSubdirectory("gmk-appconfig-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private string MakeExe(string name) {
        var path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, [0x4D, 0x5A]);   // 只要求"文件存在"；内容不参与解析
        return path;
    }

    private string MakeConfigFile(params string[] lines) {
        var path = Path.Combine(_dir, "game_path.txt");
        File.WriteAllLines(path, lines);
        return path;
    }

    [Fact]
    public void ExePath_IsResolvedToFullPath() {
        var exe = MakeExe("YuanShen.exe");

        var resolved = AppConfig.ResolveExplicit(exe);

        Assert.Equal(Path.GetFullPath(exe), resolved);
    }

    [Fact]
    public void DirectoryWithCnClient_ResolvesToYuanShen() {
        var exe = MakeExe("YuanShen.exe");

        var resolved = AppConfig.ResolveExplicit(_dir);

        Assert.Equal(Path.GetFullPath(exe), resolved);
    }

    [Fact]
    public void DirectoryWithGlobalClientOnly_ResolvesToGenshinImpact() {
        var exe = MakeExe("GenshinImpact.exe");

        var resolved = AppConfig.ResolveExplicit(_dir);

        Assert.Equal(Path.GetFullPath(exe), resolved);
    }

    /// <summary>两服都在同一目录时按 ExeNames 顺序取国服（RVA 常量集不同，选错会崩游戏）。</summary>
    [Fact]
    public void DirectoryWithBothClients_PrefersCnClient() {
        var cn = MakeExe("YuanShen.exe");
        MakeExe("GenshinImpact.exe");

        var resolved = AppConfig.ResolveExplicit(_dir);

        Assert.Equal(Path.GetFullPath(cn), resolved);
    }

    [Fact]
    public void QuotedPath_IsAccepted() {
        var exe = MakeExe("YuanShen.exe");

        var resolved = AppConfig.ResolveExplicit($"\"{exe}\"");

        Assert.Equal(Path.GetFullPath(exe), resolved);
    }

    [Fact]
    public void EmptyDirectory_ResolvesToNull_NotToSomeOtherPath() {
        Assert.Null(AppConfig.ResolveExplicit(_dir));
    }

    [Fact]
    public void NonexistentPath_ResolvesToNull() {
        Assert.Null(AppConfig.ResolveExplicit(Path.Combine(_dir, "no-such-place")));
        Assert.Null(AppConfig.ResolveExplicit("   "));
    }

    [Fact]
    public void ServiceLabel_DistinguishesBothClients() {
        Assert.Contains("国服", AppConfig.ServiceLabel(@"E:\x\YuanShen.exe"), StringComparison.Ordinal);
        Assert.Contains("国际服", AppConfig.ServiceLabel(@"E:\x\GenshinImpact.exe"), StringComparison.Ordinal);
        Assert.Contains("未知", AppConfig.ServiceLabel(@"E:\x\Other.exe"), StringComparison.Ordinal);
    }

    // ---------------- 双击免输入用的 game_path.txt ----------------

    /// <summary>
    /// 逻辑链的最后一环：启动器读的那个文件，必须真的是"exe 同目录的 game_path.txt"。
    /// 双击时没有参数，BaseDirectory 就是 exe 所在目录（run\），所以这条断言把
    /// 「双击 → 找到 run\game_path.txt → 解析出游戏」这条链闭合上。
    /// </summary>
    [Fact]
    public void GamePathFile_IsNextToTheExe() {
        Assert.Equal(
            Path.Combine(Paths.BaseDirectory, "game_path.txt"),
            Paths.GamePathFile);
        Assert.StartsWith(Paths.BaseDirectory, Paths.GamePathFile, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ConfigFile_WithDirectory_ResolvesToExe() {
        var exe = MakeExe("YuanShen.exe");
        var config = MakeConfigFile(_dir);   // 目录形态要能用（双击场景最常见）

        Assert.Equal(Path.GetFullPath(exe), AppConfig.ResolveFromConfigFile(config));
    }

    [Fact]
    public void ConfigFile_WithExePath_Resolves() {
        var exe = MakeExe("GenshinImpact.exe");
        var config = MakeConfigFile(exe);

        Assert.Equal(Path.GetFullPath(exe), AppConfig.ResolveFromConfigFile(config));
    }

    [Fact]
    public void ConfigFile_SkipsCommentsAndBlankLines() {
        var exe = MakeExe("YuanShen.exe");
        var config = MakeConfigFile(
            "# 原神 7.1 国服（这行是注释）",
            "",
            "   ",
            _dir,
            "# 后面的都不看了");

        Assert.Equal(Path.GetFullPath(exe), AppConfig.ResolveFromConfigFile(config));
    }

    [Fact]
    public void ConfigFile_WithQuotedPath_Resolves() {
        var exe = MakeExe("YuanShen.exe");
        var config = MakeConfigFile($"\"{exe}\"");

        Assert.Equal(Path.GetFullPath(exe), AppConfig.ResolveFromConfigFile(config));
    }

    [Fact]
    public void ConfigFile_WithoutUsableLine_ReturnsNull() {
        Assert.Null(AppConfig.ResolveFromConfigFile(MakeConfigFile("# 只有注释", "", "   ")));
        Assert.Null(AppConfig.ResolveFromConfigFile(MakeConfigFile(Path.Combine(_dir, "no-such-dir"))));
    }

    /// <summary>
    /// 命令行参数必须压过 game_path.txt：手工指定了一次却被配置文件悄悄改写，
    /// 是最容易让人怀疑"工具坏掉了"的一类问题。
    /// </summary>
    [Fact]
    public void ExplicitArgument_WinsOverConfigFile() {
        var exe = MakeExe("YuanShen.exe");
        WithConfigFile(Path.Combine(_dir, "no-such-dir"), () => {
            var resolved = AppConfig.GetGamePath(exe, out var source);

            Assert.Equal(Path.GetFullPath(exe), resolved);
            Assert.Equal("命令行参数", source);
        });
    }

    [Fact]
    public void NoArgument_UsesConfigFileAsAuthoritativeSource() {
        var exe = MakeExe("YuanShen.exe");
        WithConfigFile(_dir, () => {
            var resolved = AppConfig.GetGamePath(null, out var source);

            Assert.Equal(Path.GetFullPath(exe), resolved);
            Assert.Equal("game_path.txt", source);
        });
    }

    /// <summary>配置文件写了但内容无效时，必须直接失败并说明来源，不能悄悄换成别的路径。</summary>
    [Fact]
    public void InvalidConfigFile_DoesNotFallBackSilently() {
        WithConfigFile(Path.Combine(_dir, "no-such-dir"), () => {
            var resolved = AppConfig.GetGamePath(null, out var source);

            Assert.Null(resolved);
            Assert.Contains("game_path.txt", source, StringComparison.Ordinal);
        });
    }

    /// <summary>临时顶掉 exe 同目录的 game_path.txt（这两个用例必须碰真实路径来源），结束还原。</summary>
    private static void WithConfigFile(string content, Action body) {
        var configFile = Paths.GamePathFile;
        var existed = File.Exists(configFile);
        var backup = existed ? File.ReadAllText(configFile) : null;
        try {
            File.WriteAllText(configFile, content);
            body();
        } finally {
            if (existed) {
                File.WriteAllText(configFile, backup!);
            } else if (File.Exists(configFile)) {
                File.Delete(configFile);
            }
        }
    }

}
