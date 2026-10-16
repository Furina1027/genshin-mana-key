namespace GenshinSniffer;

/// <summary>
/// 分层窗口合成用的像素变换：把 GDI 画出来的 32 位位图变成**预乘 alpha** 的文字。
///
/// 做两件事：
///   1. `alpha = max(r, g, b)` —— GDI 往 32bpp DIB 里画文字时**只写 RGB、不写 alpha**
///      （alpha 字节保持 0），直接拿去 UpdateLayeredWindow(ULW_ALPHA) 会得到全透明的窗口，
///      什么都看不见；
///   2. **RGB 再乘上这个 alpha（预乘）** —— AC_SRC_ALPHA 明确要求源位图是预乘的，
///      合成公式是 `out = src + dst × (1 − a)`。
///
/// 第 2 步以前漏了，后果不是"稍微亮一点"，而是文字和投影一起被抬亮：
///   · 正文 LightGray `#D3D3D3` → 未预乘时合成出 `211 + dst×0.17`，亮背景上直接 240+，
///     就是当初那个"刺眼的纯白"；
///   · 投影 `#585858` → 未预乘时是 `88 + dst×0.66`，跟正文差不多亮，
///     于是**暗边消失、整块糊成一片白**（投影本来是拿来把文字从亮背景里抠出来的）。
/// 预乘之后：正文落在真正的 211，投影落成 `30 + dst×0.655` 的半透明黑影，暗边才回来。
///
/// 顺带解释两个看起来奇怪的选择：
///   · 只有"亮度→alpha"这一条通路，所以**不可能有纯黑投影**（黑色亮度为 0 → alpha 0 → 全透明）。
///     投影色 `#585858` 的 88 亮度既是它的 alpha 也是它变暗的来源 —— 想加深投影就得调
///     <see cref="OverlayStyle.ShadowColor"/>（见那个类的说明），而不是往黑里调。
///   · 字体用 ANTIALIASED_QUALITY（灰度抗锯齿）而不是 ClearType：ClearType 会写出带颜色的
///     子像素条纹，做"亮度→alpha"时会在文字边缘留下彩色毛边。
/// 只跑一次线性扫描（1080p 下的遮罩也就十几万像素），且只在重绘时跑。
/// </summary>
internal static class OverlayAlpha {

    /// <summary>就地变换 BGRA 缓冲（每像素 4 字节，第 4 字节是 alpha）。</summary>
    public static void ApplyLuminanceAlpha(Span<byte> bgra, int width, int height) {
        if (width <= 0 || height <= 0) {
            return;
        }
        var pixels = (long) width * height;
        if (bgra.Length < pixels * 4) {
            return;   // 缓冲比声明的尺寸小：宁可不画，也不越界写
        }
        for (long i = 0; i < pixels; i++) {
            var o = (int) (i * 4);
            var b = bgra[o];
            var g = bgra[o + 1];
            var r = bgra[o + 2];
            var max = b > g ? b : g;
            if (r > max) {
                max = r;
            }
            bgra[o + 3] = max;
            if (max is 0 or 255) {
                continue;   // 0：本来就是透明黑；255：已经是白，预乘不动
            }
            // 预乘：四舍五入（截断会让半透明像素整体偏暗一档）
            bgra[o] = (byte) ((b * max + 127) / 255);
            bgra[o + 1] = (byte) ((g * max + 127) / 255);
            bgra[o + 2] = (byte) ((r * max + 127) / 255);
        }
    }
}
