namespace GenshinSniffer;

/// <summary>
/// 环境变量开关集中地（A13）。
///
/// 为什么要集中并打印：事后翻日志最常见的疑问就是"这轮到底开没开 GMK_FS/GMK_BC"
/// —— 而日志里看不出来。现在统一读一次、启动时打一行组合。
/// （v20 起没有诊断钩子了，GMK_FULL 已随诊断代码一起删除。）
///
/// 为什么不用静态字段初始化：静态构造一旦抛异常，类型会被 CLR 永久标记为不可用
/// （A9 的教训）。这里改成 int 缓存 + Volatile，读失败最多返回 false，不会毒化类型。
/// 另外缓存在这里也是必要的：钩子回调里每次去查进程环境块是纯浪费。
/// </summary>
internal static class Options {

    private static int _fsWatcher = -1;
    private static int _bcrypt = -1;
    private static int _reuse = -1;

    /// <summary>
    /// GMK_FS=1：启用 CRI FS 侦察线程。默认关 —— 实测只要这个线程存在，视频就无法播放
    /// （v3/v4 两次验证，机制未知，疑似反作弊监控注入模块创建的新线程）。
    /// </summary>
    public static bool FsWatcher => ReadSwitch(ref _fsWatcher, "GMK_FS");

    /// <summary>
    /// bcrypt.dll 钩子（GMK_BC=0 可关，默认开）。
    ///
    /// 为什么默认开：它改的是**系统库** bcrypt.dll，不是游戏 exe 的 il2cpp 段，
    /// 不增加"il2cpp 补丁面积"；而实测日志（run/dumper.log）里
    /// MANAKEY2/3/N2/N3 与 DECKEY 全部 0 条、唯一真正产出密钥的就是这条 BCKEY 路径。
    /// 若把它门控掉，默认运行就一个密钥都拿不到。留这个开关是为了万一
    /// "bcrypt 补丁也影响播放"时能一键排除（未实测，见报告的存疑项）。
    /// </summary>
    public static bool BcryptHook => ReadSwitchInverted(ref _bcrypt, "GMK_BC");

    /// <summary>
    /// <c>GMK_REUSE=1</c> 打开"跨视频复用密钥"的抢跑补报（**默认关**）。
    ///
    /// 为什么默认关（实测 2026-10-16 23:35 的日志）：CRI 的 CriCipher 虽然是全局单例，
    /// 但每个视频开始播放时**都会重新建一次密钥对象**（BCryptGenerateSymmetricKey 照样被调用，
    /// 哪怕字节完全相同）—— 那轮四个视频 SLT / RTF_Girl / TFR_Girl / UR_Girl 各自都报了 BCKEY 行，
    /// 所以"按文件名归属"靠 BCKEY 自身就够了。补报反而会在换视频的瞬间把**上一个视频的**钥匙
    /// 顶着新文件名报出去：UR_Girl 那轮先报 F5AC（错，抢跑）、同一秒又报 F9E9（对），
    /// 前台就多出一条错误的"已配对"。更糟的是真钥匙若没来得及到（游戏恰好在这一瞬退出），
    /// 那条错误密钥会永久留在密钥库里。
    /// 保留开关是为了极端场景兜底：万一某个视频一条 BCKEY 都没有，设 GMK_REUSE=1 再开补报。
    /// </summary>
    public static bool KeyReuse => ReadSwitch(ref _reuse, "GMK_REUSE");

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
        $"Options: GMK_FS={(FsWatcher ? 1 : 0)}(FS 侦察线程) " +
        $"GMK_BC={(BcryptHook ? 1 : 0)}(bcrypt 系统库钩子) GMK_REUSE={(KeyReuse ? 1 : 0)}(跨视频同钥补报,默认关)";
}
