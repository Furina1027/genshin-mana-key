namespace GenshinSniffer;

/// <summary>
/// 环境变量开关集中地（A13）。
///
/// 为什么要集中并打印：这些开关原来散在 Awake 与属性里，事后翻日志最常见的疑问就是
/// "这轮到底开没开 GMK_FULL" —— 而日志里看不出来。现在统一读一次、启动时打一行组合。
///
/// 为什么不用静态字段初始化：静态构造一旦抛异常，类型会被 CLR 永久标记为不可用
/// （A9 的教训）。这里改成 int 缓存 + Volatile，读失败最多返回 false，不会毒化类型。
/// 另外缓存在这里也是必要的：钩子回调里每次去查进程环境块是纯浪费。
/// </summary>
internal static class Options {

    private static int _fullDiagnostics = -1;
    private static int _fsWatcher = -1;
    private static int _bcrypt = -1;

    /// <summary>
    /// GMK_FULL=1：启用 8 个诊断钩子 + 对象扫描/dump。
    /// 默认关 —— 实测默认运行会产生 14 处 il2cpp 代码补丁，而 v3 已证明大面积补丁会让视频放不出来。
    /// </summary>
    public static bool FullDiagnostics => ReadSwitch(ref _fullDiagnostics, "GMK_FULL");

    /// <summary>
    /// GMK_FS=1：启用 CRI FS 侦察线程。默认关 —— 实测只要这个线程存在，视频就无法播放
    /// （v3/v4 两次验证，机制未知，疑似反作弊监控注入模块创建的新线程）。
    /// </summary>
    public static bool FsWatcher => ReadSwitch(ref _fsWatcher, "GMK_FS");

    /// <summary>
    /// bcrypt.dll 钩子（GMK_BC=0 可关，默认开）。
    ///
    /// 为什么不跟诊断钩子一起默认关：它改的是**系统库** bcrypt.dll，不是游戏 exe 的 il2cpp 段，
    /// 不增加 A1 关心的"il2cpp 补丁面积"；而实测日志（run/dumper.log）里
    /// MANAKEY2/3/N2/N3 与 DECKEY 全部 0 条、唯一真正产出密钥的就是这条 BCKEY 路径。
    /// 若把它一起门控掉，默认运行就一个密钥都拿不到。留这个开关是为了万一
    /// "bcrypt 补丁也影响播放"时能一键排除（未实测，见报告的存疑项）。
    /// </summary>
    public static bool BcryptHook => ReadSwitchInverted(ref _bcrypt, "GMK_BC");

    private static bool ReadSwitch(ref int cache, string name) {
        var value = Volatile.Read(ref cache);
        if (value < 0) {
            value = Environment.GetEnvironmentVariable(name) == "1" ? 1 : 0;
            Volatile.Write(ref cache, value);
        }
        return value == 1;
    }

    /// <summary>GMK_BC=0 可关（默认开，见 BcryptHook）。</summary>
    private static bool ReadSwitchInverted(ref int cache, string name) {
        var value = Volatile.Read(ref cache);
        if (value < 0) {
            value = Environment.GetEnvironmentVariable(name) == "0" ? 0 : 1;
            Volatile.Write(ref cache, value);
        }
        return value == 1;
    }

    /// <summary>启动日志用：把当前生效的开关组合汇总成一行，便于事后对日志。</summary>
    public static string Describe() =>
        $"Options: GMK_FULL={(FullDiagnostics ? 1 : 0)}(诊断钩子) GMK_FS={(FsWatcher ? 1 : 0)}(FS 侦察线程) " +
        $"GMK_BC={(BcryptHook ? 1 : 0)}(bcrypt 系统库钩子)";
}
