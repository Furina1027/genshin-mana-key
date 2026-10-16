using System.Diagnostics;
using System.Text;

namespace GenshinSniffer;

/// <summary>
/// 诊断日志：控制台 + dumper.log（**这两路格式与写法保持原样，一行都不少**）
/// + 游戏窗口左下角的实时遮罩。
///
/// 三路的差异是有意的：
///   · dumper.log / 控制台 —— `[MM-dd HH:mm:ss] 消息`，带日期、不带级别，**所有**日志都写；
///   · 遮罩（前台）      —— `[HH:mm:ss INF] 消息`，照 BetterGI 的日志遮罩，带级别，
///     而且**只有 <see cref="Pair"/>（配对成功）那一行会上去**，其余日志一律不上屏。
/// 排障看文件，游戏里只想确认"配上没有"看遮罩 —— 两条路各司其职。
///
/// 为什么用长驻 StreamWriter：原来是每条日志 File.AppendAllText（反复 open/close 文件，
/// 每次都进内核）+ Console.WriteLine。单轮 300 多条还好，但 GMK_FULL 诊断下每秒几十条时
/// 光开关文件就成了主要瓶颈，还会和配对写盘抢 IO。
/// 现在持有长驻句柄、AutoFlush=false，按「条数或时间」批量冲刷 ——
/// 代价是崩溃时最多丢最后几十行（重要节点可以显式 Flush）。
///
/// 线程安全：所有状态都在 LockObj 下访问（管道读取线程和游戏退出回调会同时写日志）。
/// 文件用 FileShare.ReadWrite 打开：运行中 dumper.log 依旧可以被记事本/其它工具读到。
/// </summary>
internal static class Log {

    /// <summary>攒够这么多行就冲刷一次（兼顾吞吐与"崩溃时丢的日志不超过几十行"）。</summary>
    private const int FlushEveryLines = 32;

    /// <summary>距上次冲刷超过这么久也冲一次（日志稀疏时不会长期看不见新内容）。</summary>
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(2);

    private static readonly object LockObj = new();
    private static readonly Stopwatch SinceFlush = Stopwatch.StartNew();
    private static StreamWriter? _writer;
    private static int _pendingLines;
    private static bool _fileLogDisabled;
    private static bool _shutdown;
    private static bool _consoleEnabled;

    /// <summary>
    /// 是否往控制台写。启动器现在是 **GUI 子系统（WinExe）**，双击时压根没有控制台窗口，
    /// 所以默认 false；只有 `GMK_CONSOLE=1` 时才会去分配一个（见 <see cref="AttachConsoleIfRequested"/>）。
    /// **文件日志一行都不受影响**（dumper.log 始终是全集）。
    /// </summary>
    public static bool ConsoleEnabled {
        get => _consoleEnabled;
        set => _consoleEnabled = value;
    }

    /// <summary>
    /// `GMK_CONSOLE=1` 时分配一个控制台并把 Console.Out 重新绑上去（排障用）。
    ///
    /// 为什么用"按需分配"而不是"隐藏已有控制台"：隐藏是"窗口先出现再藏起来"，双击时仍会闪一下；
    /// 编成 WinExe 后进程本身没有控制台窗口，需要时才临时分配，**全程不会有任何窗口残留**。
    /// </summary>
    public static void AttachConsoleIfRequested() {
        if (Environment.GetEnvironmentVariable("GMK_CONSOLE") != "1") {
            return;
        }
        if (!OverlayNative.AllocConsole()) {
            return;   // 已经有控制台（从终端直接跑）或分配失败：保持默认
        }
        Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
        _consoleEnabled = true;
    }

    /// <summary>正常日志（遮罩前缀 `INF`）。**只进后台**（控制台 + dumper.log），不上遮罩。</summary>
    public static void Write(string message) => WriteCore(LogLevel.Info, message, front: false);

    /// <summary>降级但仍能继续（未采纳 / 未配对 / 某路失败后按兜底继续）。**只进后台**。</summary>
    public static void Warn(string message) => WriteCore(LogLevel.Warn, message, front: false);

    /// <summary>致命或主链路已断（注入失败 / 管道不可用 / 结果写不进去）。**只进后台** —— 这类错误有 MessageBox 兜底。</summary>
    public static void Error(string message) => WriteCore(LogLevel.Error, message, front: false);

    /// <summary>
    /// 配对成功 —— **这是唯一会出现在游戏窗口左下角遮罩上的日志**。
    ///
    /// 前台只留这一行是刻意的：遮罩贴在游戏画面上，管道诊断那几十行没人会看，
    /// 真正要一眼确认的只有"这个视频配上密钥了没有"。
    /// 后台照旧写标准格式 —— `dumper.log` 里一行都不少，只是不再出现在屏幕上。
    /// </summary>
    public static void Pair(string message) => WriteCore(LogLevel.Info, message, front: true);

    /// <summary>
    /// 唯一的写入口。两路输出刻意用**不同的格式和内容**：
    ///   · 后台（控制台 + dumper.log）：`[MM-dd HH:mm:ss] 消息`，**所有**日志都写，格式本次改动一个字节没动；
    ///   · 前台（遮罩）：只有 <see cref="Pair"/> 那一行会上去，格式是 BGI 式 `[HH:mm:ss INF] 消息`。
    /// 级别只体现在前台那一路，后台不带级别字段。
    /// </summary>
    private static void WriteCore(LogLevel level, string message, bool front) {
        var now = DateTime.Now;
        var fileLine = $"[{now:MM-dd HH:mm:ss}] {message}";
        lock (LockObj) {
            if (_consoleEnabled) {
                try {
                    Console.WriteLine(fileLine);
                } catch (Exception e) when (e is IOException or ObjectDisposedException) {
                    // 控制台被重定向到已关闭的管道时不能把主流程带走
                }
            }
            if (!_shutdown && !_fileLogDisabled) {
                try {
                    _writer ??= OpenWriter();
                    _writer.WriteLine(fileLine);
                    if (++_pendingLines >= FlushEveryLines || SinceFlush.Elapsed >= FlushInterval) {
                        FlushLocked();
                    }
                } catch (Exception e) when (e is IOException or UnauthorizedAccessException or NotSupportedException) {
                    // 日志写不进去不该拖垮工具（旧实现就是 try{}catch{}），但只静默一次：
                    // 关掉文件日志，避免每行都去撞同一个错误
                    _fileLogDisabled = true;
                }
            }
        }
        if (!front) {
            return;   // 普通日志到此为止：只进后台，不上遮罩
        }
        // 前台遮罩：**放在锁外**。它要拿 OverlayWindow 自己的锁，在持有 LockObj 时嵌套进去
        // 会凭空造出一条锁序；而且写盘被关掉（_fileLogDisabled/_shutdown）也不该影响遮罩显示。
        OverlayWindow.PushPairing(now, level, message);
    }

    /// <summary>立刻把缓冲区刷到盘（退出前、或需要马上看到日志时调用）。</summary>
    public static void Flush() {
        lock (LockObj) {
            FlushLocked();
        }
    }

    /// <summary>冲刷并关闭文件句柄 —— 主流程 finally 里必须调，否则最后一批日志留在缓冲区里。</summary>
    public static void Shutdown() {
        lock (LockObj) {
            _shutdown = true;
            FlushLocked();
            try {
                _writer?.Dispose();
            } catch (Exception e) when (e is IOException or ObjectDisposedException) {
                // 关闭失败无所谓，进程马上要退了
            }
            _writer = null;
        }
    }

    private static StreamWriter OpenWriter() {
        // FileMode.Append + FileShare.ReadWrite：多实例/其它进程同时读不冲突
        var stream = new FileStream(Paths.DumperLog, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        return new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)) { AutoFlush = false };
    }

    private static void FlushLocked() {
        _pendingLines = 0;
        SinceFlush.Restart();
        try {
            _writer?.Flush();
        } catch (Exception e) when (e is IOException or ObjectDisposedException) {
            _fileLogDisabled = true;
        }
    }

}
