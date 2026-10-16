using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 分层窗口的像素变换测试（BGRA：alpha 取亮度，RGB 再乘上这个 alpha）。
///
/// 这步错了的表现是"遮罩全透明什么都没有"或"文字亮得像纯白"，
/// 而且只在真机上才看得见，所以把判据钉在单测里。
/// </summary>
public sealed class OverlayAlphaTests {

    private static byte[] OnePixel(byte b, byte g, byte r) => [b, g, r, 0];

    [Fact]
    public void WhiteText_BecomesOpaque() {
        var pixel = OnePixel(0xFF, 0xFF, 0xFF);

        OverlayAlpha.ApplyLuminanceAlpha(pixel, 1, 1);

        Assert.Equal([0xFF, 0xFF, 0xFF, 0xFF], pixel);
    }

    [Fact]
    public void BlackBackground_BecomesFullyTransparent() {
        var pixel = OnePixel(0, 0, 0);

        OverlayAlpha.ApplyLuminanceAlpha(pixel, 1, 1);

        Assert.Equal([0, 0, 0, 0], pixel);
    }

    /// <summary>抗锯齿边缘：alpha 取亮度，RGB 同时被预乘调暗（128×128/255 ≈ 64）。</summary>
    [Fact]
    public void AntialiasedEdge_BecomesSemiTransparentAndPremultiplied() {
        var pixel = OnePixel(0x80, 0x80, 0x80);

        OverlayAlpha.ApplyLuminanceAlpha(pixel, 1, 1);

        Assert.Equal([0x40, 0x40, 0x40, 0x80], pixel);
    }

    /// <summary>投影是深灰：alpha 跟着变低，RGB 预乘后变成真正的暗色（原来会亮成灰雾）。</summary>
    [Fact]
    public void ShadowGray_BecomesDarkerAndSemiTransparent() {
        var pixel = OnePixel(0x20, 0x20, 0x20);

        OverlayAlpha.ApplyLuminanceAlpha(pixel, 1, 1);

        Assert.Equal([0x04, 0x04, 0x04, 0x20], pixel);
    }

    /// <summary>alpha 取 RGB 的最大值：只在一个通道亮的像素也不能被当成透明。</summary>
    [Fact]
    public void AlphaUsesLargestChannel() {
        var pixel = OnePixel(0x00, 0x00, 0xC8);

        OverlayAlpha.ApplyLuminanceAlpha(pixel, 1, 1);

        Assert.Equal(0xC8, pixel[3]);
        Assert.Equal([0x00, 0x00, 0x9D, 0xC8], pixel);   // 200×200/255 ≈ 157
    }

    /// <summary>
    /// 回归：源位图必须是**预乘** alpha，否则文字会比配置的颜色亮一大截。
    ///
    /// 漏掉预乘时 <c>AC_SRC_ALPHA</c> 的公式退化成 `src + dst×(1−a)`：
    /// LightGray(211) 在亮背景(dst≈200)上会算成 211 + 34 = 245 —— 就是当初那个"刺眼的纯白"。
    /// 预乘之后是 175 + 34 = 209，才是配置里写着的那个 LightGray。
    /// </summary>
    [Fact]
    public void LightGray_IsPremultipliedSoItDoesNotWashOutToWhite() {
        var pixel = OnePixel(0xD3, 0xD3, 0xD3);

        OverlayAlpha.ApplyLuminanceAlpha(pixel, 1, 1);

        Assert.Equal(0xD3, pixel[3]);
        Assert.Equal(0xAF, pixel[0]);                    // 211×211/255 ≈ 175

        var overBrightBackground = pixel[0] + 200 * (255 - pixel[3]) / 255;
        Assert.InRange(overBrightBackground, 200, 215);
    }

    [Fact]
    public void ProcessesEveryPixelOfTheSurface() {
        var surface = new byte[2 * 2 * 4];
        // 第 0 个像素留黑；第 1 个白；第 2 个灰；第 3 个不完整也不该崩
        surface[4] = 0xFF; surface[5] = 0xFF; surface[6] = 0xFF;
        surface[8] = 0x40; surface[9] = 0x40; surface[10] = 0x40;

        OverlayAlpha.ApplyLuminanceAlpha(surface, 2, 2);

        Assert.Equal(0, surface[3]);
        Assert.Equal(0xFF, surface[7]);
        Assert.Equal(0x40, surface[11]);
        Assert.Equal(0x10, surface[8]);                  // 64×64/255 ≈ 16
    }

    [Fact]
    public void TruncatedOrEmptyBuffer_IsIgnoredWithoutCrash() {
        var tooSmall = new byte[3];
        OverlayAlpha.ApplyLuminanceAlpha(tooSmall, 1, 1);
        Assert.Equal([0, 0, 0], tooSmall);

        OverlayAlpha.ApplyLuminanceAlpha([], 0, 0);
        OverlayAlpha.ApplyLuminanceAlpha([1, 2, 3, 4], -1, 5);
    }
}
