using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 「文件名 ↔ 密钥」配对状态机测试。
///
/// 这些用例对应的都是实测踩过的坑：密钥函数可能先于 SetFile 到达，而旧实现
/// 只有**一个**待配对槽位，第二把密钥会静默覆盖第一把——表现为密钥库里
/// 某些视频永远配不上 key，且没有任何报错。
/// </summary>
public sealed class KeyPairingTests {

    private const string Aes1 = "458725216E2CCBCD12961E57B85109A6";
    private const string Aes2 = "00112233445566778899AABBCCDDEEFF";

    private static string Method2(int idx, string audio, string aes)
        => $"MANAKEYN3 [{idx}] {audio} AES={aes}";

    private static string Method2NoIndex(string audio, string aes)
        => $"MANAKEY3 {audio} AES={aes}";

    private static string File(int idx, string name)
        => $"MANAFILE [{idx}] E:/Genshin Impact bilibili/games/Genshin Impact Game/YuanShen_Data/StreamingAssets\\VideoAssets\\StandaloneWindows64\\{name}";

    [Fact]
    public void FileThenMethod2_EmitsPairedEntry() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle(File(0, "Cs_ZD_AQ70201201_SLT.usm")));

        var entry = Assert.Single(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));

        Assert.Equal("Cs_ZD_AQ70201201_SLT", entry.File);   // .usm 必须被剥掉
        Assert.Equal(PairingKind.Method2, entry.Kind);
        Assert.Equal(Aes1, entry.Aes);
        Assert.Equal("4A3B2C1D0E0F1021", entry.Audio);
    }

    // ---------------- BCKEY 通路（bcrypt；2026-10-16 实测唯一真正产出密钥的） ----------------

    /// <summary>真实日志原文：BCKEY #1 file=Cs_ZD_AQ70201201_SLT.usm len=16 F5AC… rep=1 uni=1</summary>
    [Fact]
    public void BcKey_WithFile_EmitsVideoAesEntry() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "BCKEY #1 file=Cs_ZD_AQ70201201_SLT.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D rep=1 uni=1"));

        Assert.Equal("Cs_ZD_AQ70201201_SLT", entry.File);   // .usm 必须被剥掉
        Assert.Equal(PairingKind.Aes, entry.Kind);
        Assert.Equal("F5AC17FFE4B4B430553AE073EB8A8A1D", entry.Aes);
        Assert.Equal("", entry.Audio);                       // 音频 key 这一路拿不到，不冒充
    }

    [Fact]
    public void BcKey_RepeatedReports_AreEmittedOnce() {
        var p = new KeyPairing();

        Assert.Single(p.Handle("BCKEY #1 file=Cs_Video.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D rep=1 uni=1"));
        Assert.Empty(p.Handle("BCKEY #2 file=Cs_Video.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D rep=2 uni=1"));
        Assert.Empty(p.Handle("BCKEY #3 file=Cs_Video.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D rep=3 uni=1"));
    }

    [Fact]
    public void BcKey_ForDifferentVideos_EmitsBoth() {
        var p = new KeyPairing();

        var a = Assert.Single(p.Handle("BCKEY #1 file=Cs_First.usm len=16 " + Aes1));
        var b = Assert.Single(p.Handle("BCKEY #2 file=Cs_Second.usm len=16 " + Aes2));

        Assert.Equal("Cs_First", a.File);
        Assert.Equal("Cs_Second", b.File);
        Assert.NotEqual(a.Aes, b.Aes);
    }

    /// <summary>DLL 拿不到归属时报 `file=?`：挂到 `?` 上比丢掉更糟（会污染密钥库）。</summary>
    /// <summary>
    /// "跨视频复用同一把密钥"的补报行（`BCKEY reuse#N … reuse=1`）。
    ///
    /// 依据 2026-10-16 23:17 实测：第二个视频 Cs_ZD_AQ70201101_RTF_Girl 的密钥流用第一个视频
    /// 的密钥能逐字节对上，DLL 因此按新文件名补报了一条 —— 格式必须照样被接受，
    /// 否则那个视频在 paired_keys.json 里永远没有条目。
    /// </summary>
    [Fact]
    public void BcKeyReuseLine_IsPairedLikeANormalBcKey() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "BCKEY reuse#1 file=Cs_ZD_AQ70201101_RTF_Girl.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D reuse=1 uni=1"));

        Assert.Equal("Cs_ZD_AQ70201101_RTF_Girl", entry.File);
        Assert.Equal(PairingKind.Aes, entry.Kind);
        Assert.Equal("F5AC17FFE4B4B430553AE073EB8A8A1D", entry.Aes);
    }

    /// <summary>同一个视频重复播放（DLL 会重复补报）时，密钥库里只能有一条。</summary>
    [Fact]
    public void BcKeyReuseLine_RepeatedForSameFile_IsEmittedOnce() {
        var p = new KeyPairing();

        Assert.Single(p.Handle("BCKEY reuse#1 file=Cs_Rep.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D reuse=1"));
        Assert.Empty(p.Handle("BCKEY reuse#2 file=Cs_Rep.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D reuse=1"));
    }

    [Fact]
    public void BcKey_WithoutFileAttribution_IsRejected() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle("BCKEY #1 file=? len=16 F5AC17FFE4B4B430553AE073EB8A8A1D"));
        Assert.NotNull(p.LastRejectReason);
    }

    [Fact]
    public void BcKey_WithBadKeyOrLength_IsRejected() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle("BCKEY #1 file=Cs_Video.usm len=16 ABC"));
        Assert.Empty(p.Handle("BCKEY #1 file=Cs_Video.usm len=32 F5AC17FFE4B4B430553AE073EB8A8A1D"));
        Assert.Empty(p.Handle("BCKEY #1 file=Cs_Video.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1"));
        Assert.Empty(p.Handle("BCKEY #1 len=16 F5AC17FFE4B4B430553AE073EB8A8A1D"));
    }

    [Fact]
    public void BcKey_LowerCaseHex_IsNormalizedToUpperCase() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "BCKEY #1 file=Cs_Video.usm len=16 f5ac17ffe4b4b430553ae073eb8a8a1d"));

        Assert.Equal("F5AC17FFE4B4B430553AE073EB8A8A1D", entry.Aes);
    }

    /// <summary>多把密钥先于文件名到达时必须排队，不能只留最后一把。</summary>
    [Fact]
    public void KeysArrivingBeforeFile_AreQueuedNotDropped() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));
        Assert.Empty(p.Handle(Method2(0, "AABBCCDDEEFF0011", Aes2)));

        var entries = p.Handle(File(0, "Cs_Foo.usm"));

        Assert.Equal(2, entries.Count);
        Assert.Equal(new[] { Aes1, Aes2 }, entries.Select(e => e.Aes));
        Assert.All(entries, e => Assert.Equal("Cs_Foo", e.File));
    }

    [Fact]
    public void NoIndexKey_ArrivingFirst_IsPairedWithLaterFile() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle(Method2NoIndex("4A3B2C1D0E0F1021", Aes1)));

        var entry = Assert.Single(p.Handle(File(0, "Cs_Bar.usm")));

        Assert.Equal("Cs_Bar", entry.File);
        Assert.Equal(Aes1, entry.Aes);
    }

    [Fact]
    public void RepeatedIdenticalKey_IsEmittedOnlyOnce() {
        var p = new KeyPairing();
        p.Handle(File(0, "Cs_Foo.usm"));

        Assert.Single(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));
        Assert.Empty(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));
    }

    [Fact]
    public void ShortAesKey_IsIgnored() {
        var p = new KeyPairing();
        p.Handle(File(0, "Cs_Foo.usm"));

        Assert.Empty(p.Handle("MANAKEYN3 [0] 4A3B2C1D0E0F1021 AES=ABC"));
        Assert.Empty(p.Handle("MANAKEYN3 [0] 4A3B2C1D0E0F1021 AES="));
    }

    [Fact]
    public void MaskKey_IsEmittedAsMaskEntry() {
        var p = new KeyPairing();
        p.Handle(File(0, "Cs_Foo.usm"));

        var entry = Assert.Single(p.Handle("MANAKEYN2 [0] 1111111111111111 2222222222222222"));

        Assert.Equal(PairingKind.Mask, entry.Kind);
        Assert.Equal("Cs_Foo", entry.File);
        Assert.Equal("1111111111111111", entry.VideoKey);
    }

    [Fact]
    public void PlayerIndexes_AreIsolated() {
        var p = new KeyPairing();
        p.Handle(File(0, "Cs_P0.usm"));
        p.Handle(File(1, "Cs_P1.usm"));

        var e0 = Assert.Single(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));
        var e1 = Assert.Single(p.Handle(Method2(1, "AABBCCDDEEFF0011", Aes2)));

        Assert.Equal("Cs_P0", e0.File);
        Assert.Equal("Cs_P1", e1.File);
    }

    [Fact]
    public void UsmSuffix_IsStrippedCaseInsensitively() {
        var p = new KeyPairing();
        p.Handle(File(0, "CS_Foo.USM"));

        var entry = Assert.Single(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));

        Assert.Equal("CS_Foo", entry.File);
    }

    [Fact]
    public void UnrelatedDiagnosticMessages_ProduceNoEntries() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle("DIAG SetFile self=7002768E3C0 (null)"));
        Assert.Empty(p.Handle("BCKEY #1 file=(null) len=16 458725216E2CCBCD12961E57B85109A6"));
        Assert.Empty(p.Handle("OBJDMP Player obj=7002768E3C0 E0C50907"));
        Assert.Empty(p.Handle(""));
    }

    [Fact]
    public void LastFile_TracksMostRecentSetFile() {
        var p = new KeyPairing();
        p.Handle(File(0, "Cs_First.usm"));
        Assert.Equal("Cs_First", p.LastFile);

        p.Handle(File(0, "Cs_Second.usm"));
        Assert.Equal("Cs_Second", p.LastFile);
    }

    /// <summary>
    /// DLL 解析 il2cpp 字符串失败时会报 "(null)" 这类哨兵串。实测日志里 60 条 BCKEY
    /// 全部 file=(null)，若把它当文件名写进密钥库，就会留下 "(null)":{...} 的污染条目，
    /// 并且后续密钥都会挂到它上面。哨兵必须被拒绝，且不得顶掉上一份有效文件名。
    /// </summary>
    [Fact]
    public void SentinelFileName_IsRejectedWithoutClobberingPreviousFile() {
        var p = new KeyPairing();
        p.Handle(File(0, "Cs_Good.usm"));

        Assert.Empty(p.Handle("MANAFILE [0] (null)"));
        Assert.NotNull(p.LastRejectReason);
        Assert.Equal("Cs_Good", p.LastFile);

        // 拒绝之后，密钥仍应归到上一个有效文件，而不是 "(null)"
        var entry = Assert.Single(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));
        Assert.Equal("Cs_Good", entry.File);
    }

    [Fact]
    public void SentinelFileName_LeavesQueuedKeysWaiting() {
        var p = new KeyPairing();
        Assert.Empty(p.Handle(Method2(0, "4A3B2C1D0E0F1021", Aes1)));

        Assert.Empty(p.Handle("MANAFILE [0] (bad len 16)"));

        var entry = Assert.Single(p.Handle(File(0, "Cs_Real.usm")));
        Assert.Equal("Cs_Real", entry.File);
    }

    // ---------------- MANAKEY4：CriwareMediaPlayer 密钥结构（2026-11-03） ----------------

    /// <summary>7.1+ 的 AES 形态：aes + audio 一起到，且自带文件名。</summary>
    [Fact]
    public void MediaKeys_NewFormat_EmitsAesAndAudio() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "MANAKEY4 file=Cs_ZD_AQ70201201_SLT.usm mode=1 aes=" + Aes1 + " audio=0004BA5069B44BD4"));

        Assert.Equal("Cs_ZD_AQ70201201_SLT", entry.File);   // .usm 必须被剥掉
        Assert.Equal(PairingKind.MediaKeys, entry.Kind);
        Assert.Equal(Aes1, entry.Aes);
        Assert.Equal("0004BA5069B44BD4", entry.Audio);
        Assert.Equal("", entry.VideoKey);
    }

    /// <summary>
    /// 旧 56 位形态：**只报 videoKey**。旧体系里 audioKey 与 videoKey 是同一个值
    /// （HCA 只用低 56 位），库里只存一个就够，格式与 hk4e_keys.json 的旧条目一致。
    /// </summary>
    [Fact]
    public void MediaKeys_LegacyMode_EmitsVideoKeyOnly() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "MANAKEY4 file=Video_Reunion_67.usm mode=0 videoKey=0004CDB4745CD9EF"));

        Assert.Equal(PairingKind.MediaKeys, entry.Kind);
        Assert.Equal("0004CDB4745CD9EF", entry.VideoKey);
        Assert.Equal("", entry.Audio);
        Assert.Equal("", entry.Aes);
    }

    /// <summary>协议兼容：旧报文即使仍带 audio（与 videoKey 同值）也能解析，最终由 JsonStore 归一成裸字符串。</summary>
    [Fact]
    public void MediaKeys_LegacyMode_WithAudio_IsStillAccepted() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "MANAKEY4 file=Video_Reunion_67.usm mode=0 videoKey=0004CDB4745CD9EF audio=0004CDB4745CD9EF"));

        Assert.Equal("0004CDB4745CD9EF", entry.VideoKey);
        Assert.Equal("0004CDB4745CD9EF", entry.Audio);
    }

    /// <summary>只读到 audio（AES 数组还没填好）也要接受：JsonStore 会做字段级合并。</summary>
    [Fact]
    public void MediaKeys_OnlyAudio_IsAccepted() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle("MANAKEY4 file=Cs_Video.usm mode=1 audio=0004BA5069B44BD4"));

        Assert.Equal("0004BA5069B44BD4", entry.Audio);
        Assert.Equal("", entry.Aes);
    }

    [Fact]
    public void MediaKeys_WithoutFileAttribution_IsRejected() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle("MANAKEY4 file=? mode=1 aes=" + Aes1));
        Assert.Empty(p.Handle("MANAKEY4 mode=1 aes=" + Aes1));
        Assert.NotNull(p.LastRejectReason);
    }

    [Fact]
    public void MediaKeys_BadKeyLength_IsRejected() {
        var p = new KeyPairing();

        Assert.Empty(p.Handle("MANAKEY4 file=Cs_Video.usm mode=1 aes=ABC audio=0004BA5069B44BD4"));
        Assert.Empty(p.Handle("MANAKEY4 file=Cs_Video.usm mode=1 audio=123"));
        Assert.Empty(p.Handle("MANAKEY4 file=Cs_Video.usm mode=0 videoKey=0011"));
    }

    /// <summary>同一视频重复播放会重复上报，密钥库里只能有一条。</summary>
    [Fact]
    public void MediaKeys_Repeated_IsEmittedOnce() {
        var p = new KeyPairing();
        var line = "MANAKEY4 file=Cs_Video.usm mode=1 aes=" + Aes1 + " audio=0004BA5069B44BD4";

        Assert.Single(p.Handle(line));
        Assert.Empty(p.Handle(line));
    }

    [Fact]
    public void MediaKeys_LowerCaseHex_IsNormalizedToUpperCase() {
        var p = new KeyPairing();

        var entry = Assert.Single(p.Handle(
            "MANAKEY4 file=Cs_Video.usm mode=1 aes=" + Aes1.ToLowerInvariant() + " audio=0004ba5069b44bd4"));

        Assert.Equal(Aes1, entry.Aes);
        Assert.Equal("0004BA5069B44BD4", entry.Audio);
    }

}
