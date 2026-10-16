using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 遮罩外观配置测试（颜色解析 + 环境变量解析）。
///
/// 颜色/字体是用户直接手写进环境变量的字符串（`#D3D3D3`、`LightGray`、`#80D3D3D3`、
/// `Consolas,Courier New`），写错时的表现是"遮罩颜色莫名其妙"甚至"启动即崩"，
/// 所以解析必须容错，而且这些容错规则要钉在单测里。
/// </summary>
public sealed class OverlayStyleTests {

    /// <summary>用字典冒充环境变量：不去动真实进程环境，测试之间也不会互相污染。</summary>
    private static OverlayStyle FromDict(Dictionary<string, string?> env) =>
        OverlayStyle.FromEnvironment(name => env.TryGetValue(name, out var value) ? value : null);

    [Theory]
    [InlineData("#D3D3D3", 0xD3D3D3)]
    [InlineData("#d3d3d3", 0xD3D3D3)]
    [InlineData("LightGray", 0xD3D3D3)]
    [InlineData("lightgray", 0xD3D3D3)]
    [InlineData("LightGrey", 0xD3D3D3)]
    [InlineData("White", 0xFFFFFF)]
    [InlineData("Black", 0x000000)]
    [InlineData("#FF0000", 0x0000FF)]   // COLORREF = 0x00BBGGRR：红落在最低字节
    [InlineData("#0000FF", 0xFF0000)]   // 蓝落在最高字节
    public void TryParseColor_AcceptsHexAndNames(string text, int expected) {
        Assert.True(OverlayStyle.TryParseColor(text, out var colorRef));

        Assert.Equal((uint) expected, colorRef);
    }

    /// <summary>`#AARRGGBB` 的 AA 折进 RGB 当调暗用（本遮罩的 alpha 是亮度算出来的，没有独立透明度）。</summary>
    [Fact]
    public void TryParseColor_FoldsAlphaIntoRgb() {
        Assert.True(OverlayStyle.TryParseColor("#80D3D3D3", out var half));
        Assert.Equal(0x696969u, half);            // 211 × 128 / 255 = 105 = 0x69

        Assert.True(OverlayStyle.TryParseColor("#FFD3D3D3", out var opaque));
        Assert.Equal(0xD3D3D3u, opaque);          // AA = FF 等于没有透明
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("#12345")]
    [InlineData("#GGGGGG")]
    [InlineData("NotAColor")]
    public void TryParseColor_RejectsGarbage(string? text) {
        Assert.False(OverlayStyle.TryParseColor(text, out _));
    }

    /// <summary>什么都不设时必须是 BGI 的那套默认值。</summary>
    [Fact]
    public void FromEnvironment_WithoutVariables_UsesBgiDefaults() {
        var style = FromDict(new Dictionary<string, string?>());

        Assert.Equal(0xD3D3D3u, style.TextColor);
        Assert.Equal(0x585858u, style.ShadowColor);
        Assert.Equal("Cascadia Mono|Consolas|Courier New", string.Join('|', style.MonoChain));
        Assert.Equal("MiSans", style.CjkChain[0]);
        Assert.Null(style.PrivateFontFile);
    }

    [Fact]
    public void FromEnvironment_ReadsEveryKnob() {
        var style = FromDict(new Dictionary<string, string?> {
            ["GMK_OVERLAY_TEXT_COLOR"] = "#E8E8E8",
            ["GMK_OVERLAY_SHADOW_COLOR"] = "#404040",
            ["GMK_OVERLAY_MONO_FONT"] = " Consolas , Courier New ",
            ["GMK_OVERLAY_CJK_FONT"] = "MiSans",
            ["GMK_OVERLAY_FONT_FILE"] = @"C:\fonts\MiSans-Regular.ttf",
        });

        Assert.Equal(0xE8E8E8u, style.TextColor);
        Assert.Equal(0x404040u, style.ShadowColor);
        Assert.Equal("Consolas|Courier New", string.Join('|', style.MonoChain));
        Assert.Equal("MiSans", string.Join('|', style.CjkChain));
        Assert.Equal(@"C:\fonts\MiSans-Regular.ttf", style.PrivateFontFile);
    }

    /// <summary>设了变量但留空（`set GMK_OVERLAY_TEXT_COLOR=`）不能把配置搞坏 —— 一律回落默认。</summary>
    [Fact]
    public void FromEnvironment_BlankValuesFallBackToDefaults() {
        var style = FromDict(new Dictionary<string, string?> {
            ["GMK_OVERLAY_TEXT_COLOR"] = "   ",
            ["GMK_OVERLAY_MONO_FONT"] = "",
            ["GMK_OVERLAY_CJK_FONT"] = " , ",
            ["GMK_OVERLAY_FONT_FILE"] = "",
        });

        Assert.Equal(0xD3D3D3u, style.TextColor);
        Assert.Equal("Cascadia Mono|Consolas|Courier New", string.Join('|', style.MonoChain));
        Assert.Equal("MiSans|Microsoft YaHei UI|Microsoft YaHei|SimSun", string.Join('|', style.CjkChain));
        Assert.Null(style.PrivateFontFile);
    }

    [Fact]
    public void FromEnvironment_InvalidColorFallsBackToDefault() {
        var style = FromDict(new Dictionary<string, string?> { ["GMK_OVERLAY_TEXT_COLOR"] = "#ZZZ" });

        Assert.Equal(0xD3D3D3u, style.TextColor);
    }

    /// <summary>日志里那句话要能一眼看出这次生效的是什么（排障靠它）。</summary>
    [Fact]
    public void Describe_ShowsResolvedHexAndFontChains() {
        var text = FromDict(new Dictionary<string, string?> { ["GMK_OVERLAY_FONT_FILE"] = @"C:\f\MiSans-Regular.ttf" })
            .Describe();

        Assert.Contains("#D3D3D3", text);
        Assert.Contains("#585858", text);
        Assert.Contains("Cascadia Mono", text);
        Assert.Contains("MiSans", text);
        Assert.Contains("MiSans-Regular.ttf", text);
    }
}
