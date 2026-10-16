namespace GenshinSniffer;

/// <summary>
/// 所有产物的统一路径。
///
/// 为什么要有这个类：以前 mana_keys.log / dumper.log 用"当前工作目录"，
/// 而 paired_keys.json / dump\ 用 AppContext.BaseDirectory —— 只要不是从 exe 目录启动
/// （快捷方式、计划任务、别的 cmd 里带路径调用），产物就会散落到两个地方，
/// 用户拿着 README 去 run\ 找 mana_keys.log 会找不到。
/// 现在四个产物全部锚定在 exe 所在目录（与 run_genshin_mana_key.cmd 的 cd /d %~dp0 一致）。
/// </summary>
internal static class Paths {

    /// <summary>exe 所在目录（NativeAOT 单文件下就是启动器自己的目录）。</summary>
    public static string BaseDirectory => AppContext.BaseDirectory;

    /// <summary>诊断日志（曾用相对路径写在当前工作目录，现在搬回 exe 目录，内容格式不变、依旧可直接读）。</summary>
    public static string DumperLog => Path.Combine(BaseDirectory, "dumper.log");

    /// <summary>原始上报日志（MANAKEY* / MANAFILE* 行）。</summary>
    public static string KeysLog => Path.Combine(BaseDirectory, "mana_keys.log");

    /// <summary>配对结果（累积密钥库，原子写）。</summary>
    public static string PairedKeys => Path.Combine(BaseDirectory, "paired_keys.json");

    /// <summary>0xFD blob 转储目录。</summary>
    public static string DumpDirectory => Path.Combine(BaseDirectory, "dump");

    /// <summary>
    /// 本地游戏路径文件（与 exe 同目录，双击免输入用）。
    ///
    /// 为什么不写进源码：这是个人安装路径，进仓库就等于提交到公开的 GitHub。
    /// 而双击启动又没法传命令行参数 —— 折中就是它：一个**本地**文件，
    /// 且 run\ 已被 .gitignore 覆盖（另外 .gitignore 里也单独列了这个文件名兜底）。
    /// 内容写游戏目录或 exe 全路径都行，支持 # 注释与空行。
    /// </summary>
    public static string GamePathFile => Path.Combine(BaseDirectory, "game_path.txt");

}
