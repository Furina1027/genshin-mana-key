namespace GenshinSniffer;

/// <summary>遮罩窗口的矩形（屏幕像素）。</summary>
internal readonly record struct OverlayRect(int Left, int Top, int Width, int Height);

/// <summary>
/// 遮罩的几何与字号换算（纯函数，可单测）。
///
/// 数值刻意照 BetterGI 的「日志遮罩」默认值取（用户要求样式与 BGI 对齐）：
///   · 位置比例：`LeftRatio = 20/1920`、`TopRatio = 822/1080`
///     （对应 BGI 的 `LogTextBoxLeftRatio` / `LogTextBoxTopRatio`）
///   · 字号：`24 DIP × min(W/1920, H/1080)`，再夹到 0.5–3.0
///     （对应 BGI 的 `LogFontSize × ScaleTo1080PRatio`，比例取宽高比里较小的那个。
///      BGI 默认是 12 DIP，这里用了**两倍**—— 用户明确要求字号翻倍，见 `BaseEmPx`）
///   · **左上角锚定、行数增加时向下生长**（BGI 的 RichTextBox 就是从框顶往下排）
///
/// 关于 `GdiCharacterHeightFactor`：GDI 的 `lfHeight` 是"字符高度"（em 减去内部行距），
/// 而 WPF 的 `FontSize` 是 em 大小，两者差约 0.8 倍。
/// 实测依据：`-12` 的 Consolas 步进量是 8.2px（em≈15px），若直接拿 BGI 的 12 去创建就会偏大一圈。
/// </summary>
internal static class OverlayLayout {

    public const double LeftRatio = 20.0 / 1920;
    public const double TopRatio = 822.0 / 1080;

    /// <summary>
    /// 设计字号（DIP）。BGI 的 `LogFontSize` 默认是 12，这里取**两倍** —— 用户要求字号翻倍。
    ///
    /// 注意它只是"设计值"：真正画出来的是 <see cref="FontHeight"/> 折算后的 GDI 字符高度，
    /// 1080p 下从 10px 变成 19px（约两倍，见 <see cref="GdiCharacterHeightFactor"/>）。
    /// </summary>
    public const double BaseEmPx = 24.0;

    public const double GdiCharacterHeightFactor = 0.8;

    public const int MinWidth = 240;

    /// <summary>
    /// 内容再长也不超过这个宽度。原来是 900（配 10px 字号），**字号翻倍后必须跟着放大**：
    /// 那条配对行在 19px 字号下要 ~1200px，还按 900 卡就会把密钥截掉 ——
    /// 密钥被截等于这条提示白给。真正能用到多宽还受窗口右沿限制，见 <see cref="Compute"/>。
    /// </summary>
    public const int MaxWidth = 1500;

    /// <summary>BGI 的 RichTextBox 是 Padding="0,5,0,0"（左 0、上 5）。左边留 1px 让投影不被裁掉。</summary>
    public const int PadX = 1;
    public const int PadY = 5;

    /// <summary>行距里的额外间隙：原字号下字符高度 10 + 6 = 16px 一行，与 BGI 观感一致。</summary>
    public const int LineGap = 6;

    public const int MinFontHeight = 8;

    /// <summary>BGI 的 ScaleTo1080PRatio：宽高比里取较小的那个，并夹到 0.5–3.0。</summary>
    public static double ScaleFor(int windowWidth, int windowHeight) {
        if (windowWidth <= 0 || windowHeight <= 0) {
            return 1.0;
        }
        return Math.Clamp(Math.Min(windowWidth / 1920.0, windowHeight / 1080.0), 0.5, 3.0);
    }

    /// <summary>传给 GDI `CreateFontW` 的字符高度（取负值表示按高度而非 cell 高度）。</summary>
    public static int FontHeight(double scale) =>
        Math.Max(MinFontHeight, (int) Math.Round(BaseEmPx * GdiCharacterHeightFactor * scale));

    public static int PadXFor(double scale) => Math.Max(1, (int) Math.Round(PadX * scale));

    public static int PadYFor(double scale) => Math.Max(3, (int) Math.Round(PadY * scale));

    public static int LineHeightFor(double scale) =>
        FontHeight(scale) + Math.Max(2, (int) Math.Round(LineGap * scale));

    /// <summary>
    /// 算遮罩矩形。<paramref name="contentWidth"/> 是最长一行的实测宽度（0 = 还没量到）。
    /// 行数为 0 时高度为 0（调用方据此隐藏窗口）。
    /// </summary>
    public static OverlayRect Compute(int windowWidth, int windowHeight, int contentWidth, int lineCount) {
        var scale = ScaleFor(windowWidth, windowHeight);
        var padX = PadXFor(scale);
        var padY = PadYFor(scale);
        var gap = Math.Max(2, (int) Math.Round(LineGap * scale));
        var lineHeight = LineHeightFor(scale);
        var left = (int) Math.Round(windowWidth * LeftRatio);
        // 再宽也不许越过窗口右沿（右侧多留 8px，免得贴着边）。字号翻倍后内容很容易变长，
        // 而宽度方向原本没有任何"屏幕"约束 —— 高度方向至少还有 MaxLines 兜着。
        var maxWidth = Math.Max(MinWidth, Math.Min(MaxWidth, windowWidth - left - 8));
        var width = Math.Clamp(contentWidth + padX * 2, MinWidth, maxWidth);
        var height = lineCount <= 0 ? 0 : padY * 2 + lineCount * lineHeight - gap;
        return new OverlayRect(left, (int) Math.Round(windowHeight * TopRatio), width, height);
    }
}
