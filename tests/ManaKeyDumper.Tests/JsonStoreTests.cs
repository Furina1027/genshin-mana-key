using System.Text.Json;
using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// paired_keys.json 的往返测试。
///
/// 这里覆盖的是曾经的静默数据损坏：写入是「截断 + 全量重写」，一旦解析与写入
/// 不对称，累积数小时的密钥库会在下一次写入时被悄悄改坏或清空。
/// v20 起文件只存「文件名 → { "aes": "hex" }」（缩进美化）；旧掩码 / method2
/// 形态在读取时按规则迁移或跳过，由 OldFormat_* 系列用例覆盖。
/// </summary>
public sealed class JsonStoreTests : IDisposable {

    private const string Aes1 = "458725216E2CCBCD12961E57B85109A6";
    private const string Aes2 = "00112233445566778899AABBCCDDEEFF";

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

    /// <summary>旧 method2 形态（{"aes":..,"audio":..}）读取时保留其 aes —— 那仍是有效的视频密钥。</summary>
    [Fact]
    public void OldMethod2Entry_AesIsKept() {
        File.WriteAllText(Store,
            $$"""{ "Cs_Old": { "aes": "{{Aes1}}", "audio": "4A3B2C1D0E0F1021" } }""");

        var loaded = JsonStore.Load(Store);

        Assert.True(loaded.TryGetValue("Cs_Old", out var aes));
        Assert.Equal(Aes1, aes);
    }

    /// <summary>旧掩码形态（裸字符串）不是视频 AES，读取时跳过 —— 收了也是错的密钥类型。</summary>
    [Fact]
    public void OldMaskEntry_IsSkipped() {
        File.WriteAllText(Store,
            $$"""{ "Cs_Mask": "1111222233334444", "Cs_Good": { "aes": "{{Aes1}}" } }""");

        var loaded = JsonStore.Load(Store);

        Assert.False(loaded.ContainsKey("Cs_Mask"));
        Assert.Equal(Aes1, loaded["Cs_Good"]);
    }

    /// <summary>需要 JSON 转义的字符必须原样往返（旧实现只转义 \ 和 "，读取却完全不反转义）。</summary>
    [Fact]
    public void EscapedCharacters_RoundTripExactly() {
        const string name = "Cs_Back\\slash";
        JsonStore.UpsertAes(Store, name, Aes1);

        using var doc = Read(Store);
        Assert.Equal(Aes1, doc.RootElement.GetProperty(name).GetProperty("aes").GetString());

        var loaded = JsonStore.Load(Store);
        Assert.True(loaded.TryGetValue(name, out var aes), "Load 必须还原出未转义的原始键名");
        Assert.Equal(Aes1, aes);
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
