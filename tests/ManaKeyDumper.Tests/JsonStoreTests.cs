using System.Text.Json;
using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// paired_keys.json 的往返测试。
///
/// 这里覆盖的是曾经的静默数据损坏：写入是「截断 + 全量重写」，一旦解析与写入
/// 不对称，累积数小时的密钥库会在下一次写入时被悄悄改坏或清空。
///
/// 2026-11-03 起文件支持三个字段：aes / audio / videoKey，并且**按字段合并**。
/// 旧形态（裸字符串 = ≤7.0 的 videoKey）从"读取时跳过"改成"原样保留" ——
/// 旧 key 库并入本工具再写回时不能把历史条目丢掉。
/// </summary>
public sealed class JsonStoreTests : IDisposable {

    private const string Aes1 = "458725216E2CCBCD12961E57B85109A6";
    private const string Aes2 = "00112233445566778899AABBCCDDEEFF";
    private const string Audio1 = "0004BA5069B44BD4";
    private const string OldKey = "0004CDB4745CD9EF";

    private readonly string _dir = Directory.CreateTempSubdirectory("gmk-jsonstore-").FullName;

    private string Store => Path.Combine(_dir, "paired_keys.json");

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static JsonDocument Read(string path) => JsonDocument.Parse(File.ReadAllText(path));

    [Fact]
    public void Upsert_WritesIndentedFileWithAesOnly() {
        JsonStore.UpsertAes(Store, "Cs_Video", Aes1);

        // 缩进是需求本身：文件要能直接人工查阅
        Assert.Contains("\n  \"Cs_Video\"", File.ReadAllText(Store));

        using var doc = Read(Store);
        var entry = doc.RootElement.GetProperty("Cs_Video");
        Assert.Equal(Aes1, entry.GetProperty("aes").GetString());
        Assert.False(entry.TryGetProperty("audio", out _), "BCKEY 拿不到音频 key，不该凭空写出 audio 字段");
        Assert.False(entry.TryGetProperty("videoKey", out _), "BCKEY 也拿不到旧 videoKey");
    }

    /// <summary>多条密钥累积，一个都不能丢。</summary>
    [Fact]
    public void Entries_AccumulateWithoutLosingAny() {
        JsonStore.UpsertAes(Store, "Cs_One", Aes1);
        JsonStore.UpsertAes(Store, "Cs_Two", Aes2);

        using var doc = Read(Store);
        Assert.Equal(2, doc.RootElement.EnumerateObject().Count());
        Assert.Equal(Aes1, doc.RootElement.GetProperty("Cs_One").GetProperty("aes").GetString());
        Assert.Equal(Aes2, doc.RootElement.GetProperty("Cs_Two").GetProperty("aes").GetString());
    }

    [Fact]
    public void SameName_IsOverwritten_NotDuplicated() {
        JsonStore.UpsertAes(Store, "Cs_A", Aes1);
        JsonStore.UpsertAes(Store, "Cs_A", Aes2);

        using var doc = Read(Store);
        Assert.Single(doc.RootElement.EnumerateObject());
        Assert.Equal(Aes2, doc.RootElement.GetProperty("Cs_A").GetProperty("aes").GetString());
    }

    /// <summary>
    /// 核心回归：BCKEY 先写 aes，MANAKEY4 后写 audio —— 两者必须同时留在同一条里。
    /// 旧实现每次 Upsert 都整条重写，后到的 audio 会把先到的 aes 顶掉（或反过来）。
    /// </summary>
    [Fact]
    public void BcKeyThenMediaKeys_KeepBothFields() {
        JsonStore.UpsertAes(Store, "Cs_Video", Aes1);
        JsonStore.UpsertKeys(Store, "Cs_Video", "", Audio1, "");

        using var doc = Read(Store);
        var entry = doc.RootElement.GetProperty("Cs_Video");
        Assert.Equal(Aes1, entry.GetProperty("aes").GetString());
        Assert.Equal(Audio1, entry.GetProperty("audio").GetString());
    }

    /// <summary>反过来（MANAKEY4 先到、BCKEY 后到）也不能丢 audio。</summary>
    [Fact]
    public void MediaKeysThenBcKey_KeepBothFields() {
        JsonStore.UpsertKeys(Store, "Cs_Video", "", Audio1, "");
        JsonStore.UpsertAes(Store, "Cs_Video", Aes1);

        var loaded = JsonStore.Load(Store);
        Assert.True(loaded.TryGetValue("Cs_Video", out var entry));
        Assert.Equal(Aes1, entry.Aes);
        Assert.Equal(Audio1, entry.Audio);
    }

    /// <summary>
    /// 旧体系 audio 与 videoKey 同值时，写成裸字符串 —— 旧库只需要一个 key。
    /// 即使协议里带了 audio，也不能把 hk4e_keys.json 的旧格式撑成对象。
    /// </summary>
    [Fact]
    public void LegacyEntry_WithEqualAudio_WritesBareString() {
        JsonStore.UpsertKeys(Store, "Video_Reunion_67", "", OldKey, OldKey);

        var text = File.ReadAllText(Store);
        Assert.Contains("\"Video_Reunion_67\": \"" + OldKey + "\"", text);

        var loaded = JsonStore.Load(Store);
        Assert.Equal(OldKey, loaded["Video_Reunion_67"].VideoKey);
        Assert.Equal("", loaded["Video_Reunion_67"].Audio);   // 裸字符串只还原 videoKey，audio 由它派生
    }

    /// <summary>audio 与 videoKey 不同（异常/手工数据）时才保留成对象，不丢信息。</summary>
    [Fact]
    public void LegacyEntry_WithDifferentAudio_WritesObject() {
        JsonStore.UpsertKeys(Store, "Video_Reunion_67", "", "1111222233334444", OldKey);

        using var doc = Read(Store);
        var entry = doc.RootElement.GetProperty("Video_Reunion_67");
        Assert.Equal("1111222233334444", entry.GetProperty("audio").GetString());
        Assert.Equal(OldKey, entry.GetProperty("videoKey").GetString());
    }

    /// <summary>只有旧 videoKey 时保持 hk4e_keys.json 的裸字符串形态。</summary>
    [Fact]
    public void LegacyOnlyEntry_StaysBareString() {
        JsonStore.UpsertKeys(Store, "Video_Reunion_67", "", "", OldKey);

        var text = File.ReadAllText(Store);
        Assert.Contains("\"Video_Reunion_67\": \"" + OldKey + "\"", text);

        var loaded = JsonStore.Load(Store);
        Assert.Equal(OldKey, loaded["Video_Reunion_67"].VideoKey);
    }

    /// <summary>旧 method2 形态（{"aes":..,"audio":..}）读取时两个字段都保留。</summary>
    [Fact]
    public void OldMethod2Entry_AesAndAudioAreKept() {
        File.WriteAllText(Store,
            $$"""{ "Cs_Old": { "aes": "{{Aes1}}", "audio": "{{Audio1}}" } }""");

        var loaded = JsonStore.Load(Store);

        Assert.True(loaded.TryGetValue("Cs_Old", out var entry));
        Assert.Equal(Aes1, entry.Aes);
        Assert.Equal(Audio1, entry.Audio);
    }

    /// <summary>旧掩码形态（裸字符串）必须保留成 videoKey —— 这是 2026-11-03 改掉的行为。</summary>
    [Fact]
    public void OldMaskEntry_IsPreservedAsVideoKey() {
        File.WriteAllText(Store,
            $$"""{ "Cs_Mask": "{{OldKey}}", "Cs_Good": { "aes": "{{Aes1}}" } }""");

        var loaded = JsonStore.Load(Store);

        Assert.True(loaded.TryGetValue("Cs_Mask", out var mask));
        Assert.Equal(OldKey, mask.VideoKey);
        Assert.Equal(Aes1, loaded["Cs_Good"].Aes);
    }

    /// <summary>不是 16/32 位 hex 的脏值不采信（避免把历史垃圾当成密钥写回去）。</summary>
    [Fact]
    public void InvalidValues_AreIgnored() {
        File.WriteAllText(Store,
            """{ "Cs_Bad": { "aes": "xyz", "audio": "123" }, "Cs_Str": "not-a-key" }""");

        Assert.Empty(JsonStore.Load(Store));
    }

    /// <summary>需要 JSON 转义的字符必须原样往返（旧实现只转义 \ 和 "，读取却完全不反转义）。</summary>
    [Fact]
    public void EscapedCharacters_RoundTripExactly() {
        const string name = "Cs_Back\\slash";
        JsonStore.UpsertAes(Store, name, Aes1);

        using var doc = Read(Store);
        Assert.Equal(Aes1, doc.RootElement.GetProperty(name).GetProperty("aes").GetString());

        var loaded = JsonStore.Load(Store);
        Assert.True(loaded.TryGetValue(name, out var entry), "Load 必须还原出未转义的原始键名");
        Assert.Equal(Aes1, entry.Aes);
    }

    /// <summary>损坏文件不得抛异常、不得丢数据：必须留备份后从空表继续。</summary>
    [Fact]
    public void CorruptFile_IsBackedUp_AndLoadDoesNotThrow() {
        File.WriteAllText(Store, "{ this is not valid json ");

        var loaded = JsonStore.Load(Store);

        Assert.Empty(loaded);
        Assert.NotEmpty(Directory.GetFiles(_dir, "*.corrupt-*"));
    }

    /// <summary>原子写：写入完成后不得残留临时文件。</summary>
    [Fact]
    public void Upsert_LeavesNoTemporaryFile() {
        JsonStore.UpsertAes(Store, "Cs_A", Aes1);
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void MissingFile_LoadsAsEmpty() {
        Assert.Empty(JsonStore.Load(Path.Combine(_dir, "does-not-exist.json")));
    }

}
