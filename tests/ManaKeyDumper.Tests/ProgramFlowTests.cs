using System.Reflection;
using System.Text.Json;
using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// Program 的接线测试：一条上报进来，最终**真的落到产物文件**。
///
/// 2026-10-16 实机验证暴露的正是这一环断掉：密钥已经抓到（`BCKEY #1 file=Cs_….usm
/// len=16 F5AC…`），`file=` 归属也对，但 `paired_keys.json` 没生成 —— 因为 BCKEY 被
/// 当作普通日志打掉了，没进配对状态机。纯逻辑测试（KeyPairingTests）覆盖不到
/// 「状态机的输出确实被写盘」这一步，这里用反射调私有的 HandleMessage 把它钉住。
/// </summary>
public sealed class ProgramFlowTests : IDisposable {

    private static readonly MethodInfo Handle = typeof(Program)
        .GetMethod("HandleMessage", BindingFlags.NonPublic | BindingFlags.Static)
        ?? throw new InvalidOperationException("找不到 Program.HandleMessage（改过签名？）");

    private readonly string _paired = Paths.PairedKeys;
    private readonly string _keysLog = Paths.KeysLog;
    private readonly byte[]? _pairedBackup;
    private readonly byte[]? _keysLogBackup;

    public ProgramFlowTests() {
        _pairedBackup = File.Exists(_paired) ? File.ReadAllBytes(_paired) : null;
        _keysLogBackup = File.Exists(_keysLog) ? File.ReadAllBytes(_keysLog) : null;
        if (File.Exists(_paired)) {
            File.Delete(_paired);
        }
        if (File.Exists(_keysLog)) {
            File.Delete(_keysLog);
        }
    }

    public void Dispose() {
        Restore(_paired, _pairedBackup);
        Restore(_keysLog, _keysLogBackup);
    }

    private static void Restore(string path, byte[]? backup) {
        if (backup != null) {
            File.WriteAllBytes(path, backup);
        } else if (File.Exists(path)) {
            File.Delete(path);
        }
    }

    private static void Feed(string message) => Handle.Invoke(null, [message]);

    /// <summary>实机日志原文：BCKEY 上报必须变成 paired_keys.json 里的一条（仅 aes 字段）。</summary>
    [Fact]
    public void BcKeyReport_LandsInPairedKeysJson() {
        Feed("BCKEY #1 file=Cs_ZD_AQ70201201_SLT.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D rep=1 uni=1");

        Assert.True(File.Exists(_paired), "BCKEY 上报后必须生成 paired_keys.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(_paired));
        var entry = doc.RootElement.GetProperty("Cs_ZD_AQ70201201_SLT");
        Assert.Equal("F5AC17FFE4B4B430553AE073EB8A8A1D", entry.GetProperty("aes").GetString());
        Assert.False(entry.TryGetProperty("audio", out _), "音频 key 未知，不该凭空写出 audio");
    }

    /// <summary>同一把密钥重复上报（rep=1/2/3）在密钥库里只能有一条。</summary>
    [Fact]
    public void RepeatedBcKeyReports_YieldOneEntry() {
        Feed("BCKEY #1 file=Cs_Rep.usm len=16 458725216E2CCBCD12961E57B85109A6 rep=1 uni=1");
        Feed("BCKEY #2 file=Cs_Rep.usm len=16 458725216E2CCBCD12961E57B85109A6 rep=2 uni=1");
        Feed("BCKEY #3 file=Cs_Rep.usm len=16 458725216E2CCBCD12961E57B85109A6 rep=3 uni=1");

        using var doc = JsonDocument.Parse(File.ReadAllText(_paired));
        Assert.Single(doc.RootElement.EnumerateObject());
    }

    /// <summary>没归属的密钥（file=?）绝不能写进密钥库。</summary>
    [Fact]
    public void UnattributedBcKey_DoesNotCreateFile() {
        Feed("BCKEY #1 file=? len=16 F5AC17FFE4B4B430553AE073EB8A8A1D");

        Assert.False(File.Exists(_paired), "拿不到归属时宁可什么都没有，也不能写脏记录");
    }

    /// <summary>README 承诺 mana_keys.log 里有 MANAKEY* / MANAFILE*，现在再加 BCKEY（真正的密钥来源）。</summary>
    [Fact]
    public void RawEvents_AreWrittenToKeysLog() {
        Feed("MANAFILE [0] E:/game/Cs_Raw.usm");
        Feed("BCKEY #1 file=Cs_Raw.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D");

        var text = File.ReadAllText(_keysLog);
        Assert.Contains("MANAFILE [0]", text, StringComparison.Ordinal);
        Assert.Contains("BCKEY #1", text, StringComparison.Ordinal);
    }

}
