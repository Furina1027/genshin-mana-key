using System.IO.Pipes;

namespace GenshinSniffer;

/// <summary>
/// 与启动器之间的命名管道客户端（仅保留 dumper 需要的子集）：
///   DLL→启动器 0xFE  请求恢复主线程
///   DLL→启动器 0xFC  状态/密钥上报（"MANAKEY {X16}" 行写入 mana_keys.log）
/// </summary>
internal static class Goshujin {

    private static NamedPipeClientStream _pipeStream = null!;
    private static BinaryWriter _pipeWriter = null!;
    private static Lock _lock = null!;
    private static int _writeFailures;

    /// <summary>
    /// 管道写失败次数。游戏/启动器先退出时写管道必然失败，这是**预期内**的，所以不给它抛异常的机会；
    /// 但也不能完全静默（A8）—— 计数会随 Application 的会话结束汇总行一起上报。
    /// </summary>
    public static int WriteFailures => Volatile.Read(ref _writeFailures);

    public static void Init(string pipeName = "GenshinManaKeyPipe") {
        _lock = new Lock();
        _pipeStream = new NamedPipeClientStream(pipeName);
        _pipeWriter = new BinaryWriter(_pipeStream);
        _pipeStream.Connect();
    }

    public static void ResumeMainThread() {
        _pipeWriter.Write((byte) 0xFE);
    }

    public static void Report(string message) {
        try {
            using (_lock.EnterScope()) {
                _pipeWriter.Write((byte) 0xFC);
                _pipeWriter.Write(message);
            }
        } catch (IOException) {
            Interlocked.Increment(ref _writeFailures);
        }
    }

    /// <summary>二进制转储: 0xFD + 文件名 + 长度 + 数据（launcher 写入 run\dump\）</summary>
    public static void ReportBlob(string filename, ReadOnlySpan<byte> data) {
        try {
            using (_lock.EnterScope()) {
                _pipeWriter.Write((byte) 0xFD);
                _pipeWriter.Write(filename);
                _pipeWriter.Write(data.Length);
                _pipeWriter.Write(data);
                _pipeWriter.Flush();
            }
        } catch (IOException) {
            Interlocked.Increment(ref _writeFailures);
        }
    }

}
