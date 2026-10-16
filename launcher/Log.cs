using System.Diagnostics;
using System.Text;

namespace GenshinSniffer;

/// <summary>
/// 诊断日志：控制台 + dumper.log。
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

    public static void Write(string message) {
        // 带日期：dumper.log 是追加写的，只有 HH:mm:ss 时两次运行会混在一起分不清（实测踩过）
        var line = $"[{DateTime.Now:MM-dd HH:mm:ss}] {message}";
        lock (LockObj) {
            try {
                Console.WriteLine(line);
            } catch (Exception e) when (e is IOException or ObjectDisposedException) {
                // 控制台被重定向到已关闭的管道时不能把主流程带走
            }
            if (_shutdown || _fileLogDisabled) {
                return;
            }
            try {
                _writer ??= OpenWriter();
                _writer.WriteLine(line);
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
