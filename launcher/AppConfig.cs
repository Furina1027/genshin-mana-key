using System.Diagnostics;

namespace GenshinSniffer.Utilities;

/// <summary>
/// 定位原神主程序：命令行参数 → 常见安装路径。
/// 国服 YuanShen.exe 与国际服 GenshinImpact.exe 都支持（DLL 端已经有两套 RVA，启动器这边也要认）。
///
/// 为什么不再"用运行中的进程取路径"当目标路径：本启动器必须以**挂起方式自己创建进程**
/// （要在反作弊 HoYoKProtect 落地前抢到全权限句柄），游戏已经在跑就是错误状态，
/// 拿它的路径也没用。所以运行中的实例只用来给用户一句提示（见 GetRunningGamePath），
/// 不再参与目标路径判定 —— 原来那个分支在主流程里永远走不到，属于死逻辑。
/// </summary>
internal static class AppConfig {

    /// <summary>国服/国际服主程序名（顺序即探测顺序：国服优先）。</summary>
    private static readonly string[] ExeNames = ["YuanShen.exe", "GenshinImpact.exe"];

    /// <summary>
    /// 通用候选路径 —— 只保留官方默认安装目录（两服 × 两个常见盘），
    /// 不含任何个人机器路径；找不到就交给用户显式传参，绝不瞎猜安装位置。
    /// </summary>
    private static readonly string[] Candidates = [
        @"C:\Program Files\Genshin Impact\Genshin Impact Game\YuanShen.exe",
        @"C:\Program Files\Genshin Impact\Genshin Impact Game\GenshinImpact.exe",
        @"D:\Genshin Impact\Genshin Impact Game\YuanShen.exe",
        @"D:\Genshin Impact\Genshin Impact Game\GenshinImpact.exe",
    ];

    /// <summary>
    /// 定位游戏主程序，优先级：命令行参数 → exe 同目录的 <c>game_path.txt</c> → 通用默认路径。
    ///
    /// 参数可以是 exe 全路径，也可以只给**安装目录**：实际使用中很多人手上只有目录
    /// （例如 `D:\Games\Genshin Impact\Genshin Impact Game`），以前传目录会被判成"未找到游戏"。
    ///
    /// 显式来源（参数或配置文件）**一旦给出就以它为准**，解析不出来直接失败，
    /// 不再静默回退到别的路径 —— 用户明明指了路却跑了另一个客户端，比报错更难查。
    /// <paramref name="source"/> 回传用了哪个来源，供日志说明。
    /// </summary>
    public static string? GetGamePath(string? argPath, out string source) {
        if (!string.IsNullOrWhiteSpace(argPath)) {
            var fromArg = ResolveExplicit(argPath);
            source = fromArg == null ? $"命令行参数（无效：{argPath.Trim()}）" : "命令行参数";
            return fromArg;
        }

        var configFile = Paths.GamePathFile;
        if (File.Exists(configFile)) {
            var fromFile = ResolveFromConfigFile(configFile);
            source = fromFile == null
                ? $"{Path.GetFileName(configFile)}（内容无效）"
                : Path.GetFileName(configFile);
            return fromFile;
        }

        foreach (var candidate in Candidates) {
            if (File.Exists(candidate)) {
                source = "默认安装路径";
                return candidate;
            }
        }
        source = "未找到";
        return null;
    }

    /// <summary>
    /// 从本地路径文件解析目标：取第一条非空、不以 <c>#</c> 开头的行，允许写目录或 exe 全路径。
    /// 抽成"吃文件路径"的形式是为了能直接用临时文件单测（不依赖真实安装位置）。
    /// </summary>
    internal static string? ResolveFromConfigFile(string configFile) {
        foreach (var raw in File.ReadAllLines(configFile)) {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') {
                continue;
            }
            return ResolveExplicit(line);
        }
        return null;
    }

    /// <summary>
    /// 把显式参数解析成 exe 全路径：本身就是 exe 就用它；是目录就在目录里找两服的主程序；
    /// 都不成立返回 null（由调用方明确报错，绝不静默换成别的路径）。
    /// </summary>
    internal static string? ResolveExplicit(string argPath) {
        // 从资源管理器"复制文件路径"粘进来会带引号，cmd 之外的地方不会自动剥掉
        var trimmed = argPath.Trim().Trim('"');
        if (trimmed.Length == 0) {
            return null;
        }
        if (File.Exists(trimmed)) {
            return Path.GetFullPath(trimmed);
        }
        if (Directory.Exists(trimmed)) {
            foreach (var name in ExeNames) {
                var candidate = Path.Combine(trimmed, name);
                if (File.Exists(candidate)) {
                    return Path.GetFullPath(candidate);
                }
            }
        }
        return null;
    }

    /// <summary>按 exe 名判断客户端服务，供日志与进程判断使用（两服 RVA 不同，混淆会直接崩游戏）。</summary>
    public static string ServiceLabel(string exePath) {
        var name = Path.GetFileName(exePath);
        if (string.Equals(name, "YuanShen.exe", StringComparison.OrdinalIgnoreCase)) {
            return "国服 YuanShen.exe";
        }
        if (string.Equals(name, "GenshinImpact.exe", StringComparison.OrdinalIgnoreCase)) {
            return "国际服 GenshinImpact.exe";
        }
        return "未知客户端（不是 YuanShen.exe / GenshinImpact.exe）";
    }

    /// <summary>
    /// 游戏是否在运行。给了 exePath 就只判这一个客户端
    /// （否则"国际服开着、要注入国服"会被误拦）。
    /// </summary>
    public static bool IsGameRunning(string? exePath = null) {
        string[] names = exePath == null ? ExeNames : [Path.GetFileName(exePath)];
        foreach (var name in names) {
            if (IsProcessRunning(Path.GetFileNameWithoutExtension(name))) {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// 运行中游戏实例的可执行文件全路径 —— **只用于提示**（"你大概是这个路径，把它当参数传进来"），
    /// 不作为注入目标。找不到返回 null。
    /// </summary>
    public static string? GetRunningGamePath() {
        foreach (var name in ExeNames) {
            var processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name));
            try {
                foreach (var process in processes) {
                    var path = process.GetFileName(); // ProcessExtensions：GetModuleFileNameEx（比 MainModule 稳）
                    if (!string.IsNullOrEmpty(path)) {
                        return path;
                    }
                }
            } finally {
                DisposeAll(processes);
            }
        }
        return null;
    }

    private static bool IsProcessRunning(string baseName) {
        var processes = Process.GetProcessesByName(baseName);
        try {
            return processes.Length > 0;
        } finally {
            // Process 持有内核句柄，用完必须释放（每个实例一个句柄，不释放就是句柄泄漏）
            DisposeAll(processes);
        }
    }

    private static void DisposeAll(Process[] processes) {
        foreach (var process in processes) {
            process.Dispose();
        }
    }

}
