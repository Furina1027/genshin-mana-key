using System.Text.Json;
using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// paired_keys.json 的往返测试。
///
/// 这里覆盖的是曾经的静默数据损坏：键值存储同时容纳两种值形态
/// （掩码 = 裸字符串，method2 = {"aes":..,"audio":..} 对象），而旧实现用
/// Split(',')/Split(':') 解析并且写入是「截断 + 全量重写」，一旦解析与写入
/// 不对称，累积数小时的密钥库会在下一次写入时被悄悄改坏或清空。
/// </summary>
public sealed class JsonStoreTests : IDisposable {

    private const string Aes1 = "458725216E2CCBCD12961E57B85109A6";
    private const string Aes2 = "00112233445566778899AABBCCDDEEFF";

    private readonly string _dir = Directory.CreateTempSubdirectory("gmk-jsonstore-").FullName;

    private string Store => Path.Combine(_dir, "paired_keys.json");

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static JsonDocument Read(string path) => JsonDocument.Parse(File.ReadAllText(path));

    [Fact]
    public void Method2_Upsert_WritesNestedObject() {
        JsonStore.UpsertMethod2(Store, "Cs_A", Aes1, "4A3B2C1D0E0F1021");

        using var doc = Read(Store);
        var entry = doc.RootElement.GetProperty("Cs_A");
        Assert.Equal(Aes1, entry.GetProperty("aes").GetString());
        Assert.Equal("4A3B2C1D0E0F1021", entry.GetProperty("audio").GetString());
    }

    [Fact]
    public void Mask_Upsert_WritesBareString() {
        JsonStore.UpsertMask(Store, "Cs_A", "1111222233334444");

        using var doc = Read(Store);
        Assert.Equal("1111222233334444", doc.RootElement.GetProperty("Cs_A").GetString());
    }

    /// <summary>BCKEY 通路：只写 aes 字段，不写空 audio（否则等于宣称"音频 key 是空"）。</summary>
    [Fact]
    public void AesOnly_Upsert_WritesObjectWithoutAudio() {
        JsonStore.UpsertAes(Store, "Cs_Video", Aes1);

        using var doc = Read(Store);
        var entry = doc.RootElement.GetProperty("Cs_Video");
        Assert.Equal(Aes1, entry.GetProperty("aes").GetString());
        Assert.False(entry.TryGetProperty("audio", out _), "不该凭空写出 audio 字段");
    }

    /// <summary>三种值形态（掩码 / method2 / 仅 aes）混存后都要保留。</summary>
    [Fact]
    public void AesShape_CoexistsWithOtherShapes() {
        JsonStore.UpsertMask(Store, "Cs_Mask", "1111222233334444");
        JsonStore.UpsertMethod2(Store, "Cs_M2", Aes1, "4A3B2C1D0E0F1021");
        JsonStore.UpsertAes(Store, "Cs_Video", Aes2);

        using var doc = Read(Store);
        Assert.Equal(3, doc.RootElement.EnumerateObject().Count());
        Assert.Equal(Aes2, doc.RootElement.GetProperty("Cs_Video").GetProperty("aes").GetString());
        Assert.False(doc.RootElement.GetProperty("Cs_Video").TryGetProperty("audio", out _));
        Assert.Equal(Aes1, doc.RootElement.GetProperty("Cs_M2").GetProperty("aes").GetString());
    }

    /// <summary>两种值形态混存后再写入，已有条目一个都不能丢（旧解析器的重灾区）。</summary>
    [Fact]
    public void MixedShapes_AccumulateWithoutLosingEntries() {
        JsonStore.UpsertMask(Store, "Cs_Mask", "1111222233334444");
        JsonStore.UpsertMethod2(Store, "Cs_One", Aes1, "4A3B2C1D0E0F1021");
        JsonStore.UpsertMethod2(Store, "Cs_Two", Aes2, "AABBCCDDEEFF0011");

        using var doc = Read(Store);
        Assert.Equal(3, doc.RootElement.EnumerateObject().Count());
        Assert.Equal("1111222233334444", doc.RootElement.GetProperty("Cs_Mask").GetString());
        Assert.Equal(Aes1, doc.RootElement.GetProperty("Cs_One").GetProperty("aes").GetString());
        Assert.Equal(Aes2, doc.RootElement.GetProperty("Cs_Two").GetProperty("aes").GetString());
    }

    [Fact]
    public void SameName_IsOverwritten_NotDuplicated() {
        JsonStore.UpsertMethod2(Store, "Cs_A", Aes1, "4A3B2C1D0E0F1021");
        JsonStore.UpsertMethod2(Store, "Cs_A", Aes2, "AABBCCDDEEFF0011");

        using var doc = Read(Store);
        Assert.Single(doc.RootElement.EnumerateObject());
        Assert.Equal(Aes2, doc.RootElement.GetProperty("Cs_A").GetProperty("aes").GetString());
    }

    /// <summary>需要 JSON 转义的字符必须原样往返（旧实现只转义 \ 和 "，读取却完全不反转义）。</summary>
    [Fact]
    public void EscapedCharacters_RoundTripExactly() {
        const string name = "Cs_Back\\slash";
        JsonStore.UpsertMask(Store, name, "AABBCCDDEEFF0011");

        using var doc = Read(Store);
        Assert.Equal("AABBCCDDEEFF0011", doc.RootElement.GetProperty(name).GetString());

        var loaded = JsonStore.Load(Store);
        Assert.True(loaded.TryGetValue(name, out var raw), "Load 必须还原出未转义的原始键名");
        Assert.False(string.IsNullOrWhiteSpace(raw));
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
        JsonStore.UpsertMethod2(Store, "Cs_A", Aes1, "4A3B2C1D0E0F1021");
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
    }

    [Fact]
    public void MissingFile_LoadsAsEmpty() {
        Assert.Empty(JsonStore.Load(Path.Combine(_dir, "does-not-exist.json")));
    }

}
