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

    /// <summary>
    /// 端到端补一个：DLL 的"跨视频同钥补报"行（reuse=1）也必须落进 paired_keys.json。
    /// 这是 23:17 那轮 RTF_Girl 拿不到密钥的直接回归用例。
    /// </summary>
    [Fact]
    public void BcKeyReuseReport_LandsInPairedKeysJson() {
        Feed("BCKEY reuse#1 file=Cs_ZD_AQ70201101_RTF_Girl.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D reuse=1 uni=1");

        Assert.True(File.Exists(_paired), "补报行也必须生成 paired_keys.json 条目");
        using var doc = JsonDocument.Parse(File.ReadAllText(_paired));
        Assert.Equal("F5AC17FFE4B4B430553AE073EB8A8A1D",
            doc.RootElement.GetProperty("Cs_ZD_AQ70201101_RTF_Girl").GetProperty("aes").GetString());
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

    /// <summary>
    /// 2026-11-03 的新链路：BCKEY 写 aes、MANAKEY4 写 audio，**两条都要留在同一条记录里**。
    /// 这是"只能抓 AES"到"aes+audio 都入库"的端到端回归。
    /// </summary>
    [Fact]
    public void MediaKeysReport_MergesWithBcKey_AndLandsWithAudio() {
        const string aes = "F5AC17FFE4B4B430553AE073EB8A8A1D";
        // 文件名不能和别的用例重复：Program.Lines 是静态去重集合，同一行只会被处理一次
        Feed("BCKEY #1 file=Cs_Merge_Video.usm len=16 " + aes);
        Feed("MANAKEY4 file=Cs_Merge_Video.usm mode=1 aes=" + aes + " audio=0004BA5069B44BD4");

        using var doc = JsonDocument.Parse(File.ReadAllText(_paired));
        var entry = doc.RootElement.GetProperty("Cs_Merge_Video");
        Assert.Equal(aes, entry.GetProperty("aes").GetString());
        Assert.Equal("0004BA5069B44BD4", entry.GetProperty("audio").GetString());
    }

    /// <summary>旧体系只写一个 key，格式与 hk4e_keys.json 的旧条目一致（裸字符串）。</summary>
    [Fact]
    public void MediaKeysLegacyReport_LandsInPairedKeysJson() {
        Feed("MANAKEY4 file=Video_Reunion_67.usm mode=0 videoKey=0004CDB4745CD9EF");

        using var doc = JsonDocument.Parse(File.ReadAllText(_paired));
        var entry = doc.RootElement.GetProperty("Video_Reunion_67");
        Assert.Equal(JsonValueKind.String, entry.ValueKind);
        Assert.Equal("0004CDB4745CD9EF", entry.GetString());
    }

    [Fact]
    public void MediaKeysRawEvent_IsWrittenToKeysLog() {
        Feed("MANAKEY4 file=Cs_Raw.usm mode=1 aes=458725216E2CCBCD12961E57B85109A6 audio=0004BA5069B44BD4");

        Assert.Contains("MANAKEY4", File.ReadAllText(_keysLog), StringComparison.Ordinal);
    }

}
