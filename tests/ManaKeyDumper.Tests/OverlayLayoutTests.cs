using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 遮罩几何/字号换算测试。
///
/// 数值是照着 BetterGI 的「日志遮罩」默认值取的（用户要求样式对齐 BGI），
/// 所以这里也照 BGI 的期望值钉住 —— 尤其 `(20, 822)` 这个位置和
/// 「BGI 的 FontSize 是 em、GDI 的 lfHeight 是字符高度，差 0.8 倍」这条换算。
/// </summary>
public sealed class OverlayLayoutTests {

    [Theory]
    [InlineData(1920, 1080, 1.0)]
    [InlineData(1536, 864, 0.8)]
    [InlineData(3840, 2160, 2.0)]
    [InlineData(1280, 720, 0.667)]
    [InlineData(0, 0, 1.0)]
    public void Scale_MatchesBgiRatio(int width, int height, double expected) {
        Assert.Equal(expected, OverlayLayout.ScaleFor(width, height), 3);
    }

    [Fact]
    public void Scale_IsClampedToHalfAndThree() {
        Assert.Equal(0.5, OverlayLayout.ScaleFor(640, 360), 3);
        Assert.Equal(3.0, OverlayLayout.ScaleFor(8000, 8000), 3);
    }

    /// <summary>
    /// 设计字号 24 DIP（= BGI 默认 12 的两倍）是 em 大小；GDI 的字符高度要乘 0.8 才对得上。
    /// 1080p 下算出来 19px —— 正好是原来 10px 的约两倍。
    /// </summary>
    [Fact]
    public void FontHeight_UsesGdiCharacterHeightFactor() {
        Assert.Equal(19, OverlayLayout.FontHeight(1.0));    // round(24 × 0.8)
        Assert.Equal(15, OverlayLayout.FontHeight(0.8));    // round(15.36)
        Assert.True(OverlayLayout.FontHeight(0.05) >= OverlayLayout.MinFontHeight);
    }

    /// <summary>BGI 默认位置：1920×1080 下左上角是 (20, 822)。</summary>
    [Fact]
    public void Position_MatchesBgiDefaults() {
        var box = OverlayLayout.Compute(1920, 1080, 400, 2);

        Assert.Equal(20, box.Left);
        Assert.Equal(822, box.Top);
    }

    [Fact]
    public void Width_FitsContentThenClamps() {
        Assert.Equal(OverlayLayout.MinWidth, OverlayLayout.Compute(1920, 1080, 10, 1).Width);
        Assert.Equal(402, OverlayLayout.Compute(1920, 1080, 400, 1).Width);   // 400 + 1×2（BGI 的 Padding 左 0）
        Assert.Equal(OverlayLayout.MaxWidth, OverlayLayout.Compute(1920, 1080, 5000, 1).Width);
    }

    /// <summary>
    /// 窗口窄的时候宽度上限要退到"窗口右沿 − 左边距 − 8" —— 否则字号翻倍后一条长配对行
    /// 会直接画到屏幕外面去（宽度方向原本完全没有这层约束）。
    /// </summary>
    [Fact]
    public void Width_NeverRunsPastTheWindowEdge() {
        var box = OverlayLayout.Compute(1280, 720, 5000, 1);

        Assert.Equal(13, box.Left);                        // round(1280 × 20/1920)
        Assert.Equal(1280 - 13 - 8, box.Width);            // 1259，而不是 MaxWidth
        Assert.True(box.Left + box.Width <= 1280);
    }

    /// <summary>左上角锚定：行数增加只让高度变大，Top 不动（向下生长，和 BGI 一致）。</summary>
    [Fact]
    public void Height_GrowsDownwardOnly() {
        var none = OverlayLayout.Compute(1920, 1080, 400, 0);
        var one = OverlayLayout.Compute(1920, 1080, 400, 1);
        var three = OverlayLayout.Compute(1920, 1080, 400, 3);

        Assert.Equal(0, none.Height);
        Assert.Equal(one.Top, three.Top);
        Assert.Equal(one.Height + 2 * OverlayLayout.LineHeightFor(1.0), three.Height);
    }

    [Fact]
    public void Geometry_ScalesWithWindowSize() {
        var box = OverlayLayout.Compute(1536, 864, 400, 1);

        Assert.Equal(16, box.Left);      // round(1536 × 20/1920)
        Assert.Equal(658, box.Top);      // round(864 × 822/1080) = round(657.6)
    }
}
