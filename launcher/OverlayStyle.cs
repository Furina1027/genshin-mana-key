using System.Globalization;

namespace GenshinSniffer;

/// <summary>
/// 遮罩的外观配置：颜色、字体链、可选的私有字体文件。
///
/// 为什么要做成可配：遮罩是贴在游戏画面上的，好不好看完全取决于当时的背景
/// （亮场景 vs 洞窟完全是两种观感），内置一个"绝对正确"的颜色是不存在的。
/// 启动器没有配置文件体系，所以沿用项目里既有的 `GMK_*` 环境变量约定，改完重启即可生效：
///
/// | 环境变量 | 默认值 | 说明 |
/// |---|---|---|
/// | `GMK_OVERLAY_TEXT_COLOR`   | `LightGray` | 正文颜色。`#RRGGBB` / `#AARRGGBB` / 颜色名 |
/// | `GMK_OVERLAY_SHADOW_COLOR` | `#585858`   | 投影颜色（见下方"为什么投影不能是纯黑"） |
/// | `GMK_OVERLAY_MONO_FONT`    | `Cascadia Mono,Consolas,Courier New` | 前缀用的等宽候选链 |
/// | `GMK_OVERLAY_CJK_FONT`     | `MiSans,Microsoft YaHei UI,...` | 正文用的中文候选链 |
/// | `GMK_OVERLAY_FONT_FILE`    | （自动找 exe 旁边的 `MiSans-Regular.ttf`） | 私有加载的字体文件，**不装进系统** |
///
/// 关于 `#AARRGGBB` 的 AA：本遮罩的 alpha 是"亮度"算出来的
/// （见 <see cref="OverlayAlpha"/>），没法单独给一个透明度，所以 AA 被折进 RGB 当调暗用 ——
/// 观感上等价于半透明，`#80D3D3D3` 就是"淡一档的 LightGray"。
///
/// 关于**为什么投影不能是纯黑**：黑色亮度 0 → alpha 0 → 全透明，等于没投影。
/// 同一条规则也限定了投影的深度：投影色越暗，alpha 越小、越透明，两个方向互相牵制 ——
/// `#585858` 是这条曲线上的一个平衡点；想更重就调 `GMK_OVERLAY_SHADOW_COLOR`
/// （例如 `#6E6E6E` 更实、`#484848` 更轻），而不是往黑里调。
/// </summary>
internal sealed class OverlayStyle {

    /// <summary>正文默认色：与 BetterGI 的 `DefaultLogTextColor` 一致。</summary>
    public const string DefaultTextColor = "LightGray";

    /// <summary>投影默认色，与 <see cref="OverlayWindow"/> 里原来的常量一致。</summary>
    public const string DefaultShadowColor = "#585858";

    /// <summary>前缀（时间戳 + 级别）的等宽候选链，与 BGI 的 `DefaultOverlayMonoFontFamily` 对齐。</summary>
    public static readonly string[] DefaultMonoChain = ["Cascadia Mono", "Consolas", "Courier New"];

    /// <summary>
    /// 中文正文的候选链。BGI 用的是它**随包分发的 MiSans**，所以 MiSans 排第一：
    /// 把字体文件喂进来（放 exe 旁边或指定 `GMK_OVERLAY_FONT_FILE`）字形就与 BGI 完全一致；
    /// 没有这个文件时会自动退到系统雅黑（`CreateFontChecked` 会校验 GDI 真的选中了才用）。
    /// </summary>
    public static readonly string[] DefaultCjkChain = ["MiSans", "Microsoft YaHei UI", "Microsoft YaHei", "SimSun"];

    /// <summary>正文颜色（COLORREF，即 GDI 的 `0x00BBGGRR`）。</summary>
    public uint TextColor { get; private init; }

    /// <summary>投影颜色（COLORREF）。</summary>
    public uint ShadowColor { get; private init; }

    /// <summary>前缀的等宽字体候选链（按顺序试，第一个 GDI 真正选中的生效）。</summary>
    public string[] MonoChain { get; private init; } = DefaultMonoChain;

    /// <summary>正文的中文候选链。</summary>
    public string[] CjkChain { get; private init; } = DefaultCjkChain;

    /// <summary>要私有加载的字体文件（null = 不加载）。加载失败不致命，只是字体退回候选链的下一档。</summary>
    public string? PrivateFontFile { get; private init; }

    /// <summary>用进程环境变量解析一份样式。<see cref="OverlayWindow"/> 启动时读一次。</summary>
    public static OverlayStyle FromEnvironment() => FromEnvironment(Environment.GetEnvironmentVariable);

    /// <summary>可注入读取器的版本 —— 单测用它把环境变量换成字典，不去动真实进程环境。</summary>
    public static OverlayStyle FromEnvironment(Func<string, string?> read) {
        return new OverlayStyle {
            TextColor = ParseColorOrDefault(read("GMK_OVERLAY_TEXT_COLOR"), DefaultTextColor),
            ShadowColor = ParseColorOrDefault(read("GMK_OVERLAY_SHADOW_COLOR"), DefaultShadowColor),
            MonoChain = ParseFontChain(read("GMK_OVERLAY_MONO_FONT"), DefaultMonoChain),
            CjkChain = ParseFontChain(read("GMK_OVERLAY_CJK_FONT"), DefaultCjkChain),
            PrivateFontFile = Blank(read("GMK_OVERLAY_FONT_FILE")),
        };
    }

    /// <summary>给日志用的一句话描述（排障时一眼看出这次生效的是什么）。</summary>
    public string Describe() =>
        $"文字={ToHex(TextColor)} 投影={ToHex(ShadowColor)} "
        + $"等宽={string.Join('/', MonoChain)} 中文={string.Join('/', CjkChain)}"
        + (PrivateFontFile == null ? "" : $" 字体文件={Path.GetFileName(PrivateFontFile)}");

    /// <summary>COLORREF → `#RRGGBB`（只用于日志，别拿去当解析输入）。</summary>
    public static string ToHex(uint colorRef) =>
        $"#{colorRef & 0xFF:X2}{(colorRef >> 8) & 0xFF:X2}{(colorRef >> 16) & 0xFF:X2}";

    /// <summary>解析颜色文本；解析不出来返回 false（调用方用自己的兜底）。</summary>
    public static bool TryParseColor(string? text, out uint colorRef) {
        colorRef = 0;
        if (Blank(text) is not { } value) {
            return false;
        }
        if (value[0] == '#') {
            if (!TryParseHex(value.AsSpan(1), out var r, out var g, out var b)) {
                return false;
            }
            colorRef = ColorRef(r, g, b);
            return true;
        }
        if (!TryParseNamed(value, out var nr, out var ng, out var nb)) {
            return false;
        }
        colorRef = ColorRef(nr, ng, nb);
        return true;
    }

    private static uint ParseColorOrDefault(string? text, string fallback) =>
        TryParseColor(text, out var parsed) ? parsed
        : TryParseColor(fallback, out var fb) ? fb
        : ColorRef(0xD3, 0xD3, 0xD3);

    private static uint ColorRef(byte r, byte g, byte b) => (uint) ((b << 16) | (g << 8) | r);

    /// <summary>`#RRGGBB` 或 `#AARRGGBB`（AA 折进 RGB）。</summary>
    private static bool TryParseHex(ReadOnlySpan<char> hex, out byte r, out byte g, out byte b) {
        r = g = b = 0;
        if (hex.Length is not (6 or 8)) {
            return false;
        }
        var start = hex.Length == 8 ? 2 : 0;
        if (!TryParseByte(hex.Slice(start, 2), out r)
            || !TryParseByte(hex.Slice(start + 2, 2), out g)
            || !TryParseByte(hex.Slice(start + 4, 2), out b)) {
            return false;
        }
        if (hex.Length == 8 && TryParseByte(hex[..2], out var a) && a != 255) {
            r = (byte) (r * a / 255);
            g = (byte) (g * a / 255);
            b = (byte) (b * a / 255);
        }
        return true;
    }

    private static bool TryParseByte(ReadOnlySpan<char> text, out byte value) =>
        byte.TryParse(text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);

    /// <summary>
    /// 常见颜色名。只收 BGI 默认值里出现过的那些 + 几个随手会想用的，
    /// 名字按 WPF/HTML 的常见拼法（`LightGray` 与 `LightGrey` 都认）。
    /// </summary>
    private static bool TryParseNamed(string name, out byte r, out byte g, out byte b) {
        switch (name.Trim().ToUpperInvariant()) {
            case "WHITE": r = g = b = 255; return true;
            case "BLACK": r = g = b = 0; return true;
            case "SILVER": r = g = b = 192; return true;
            case "LIGHTGRAY" or "LIGHTGREY": r = g = b = 211; return true;
            case "GRAY" or "GREY": r = g = b = 128; return true;
            case "DARKGRAY" or "DARKGREY": r = g = b = 64; return true;
            case "DIMGRAY" or "DIMGREY": r = g = b = 105; return true;
            case "GAINSBORO" or "WHITESMOKE": r = g = b = 240; return true;
            case "SNOW" or "IVORY": r = g = b = 250; return true;
            case "LIGHTGREEN": r = 144; g = 238; b = 144; return true;
            case "PALEGREEN": r = 152; g = 251; b = 152; return true;
            case "GREEN": r = 0; g = 128; b = 0; return true;
            case "YELLOW": r = 255; g = 255; b = 0; return true;
            case "GOLD": r = 255; g = 215; b = 0; return true;
            case "ORANGE": r = 255; g = 165; b = 0; return true;
            case "RED": r = 255; g = 0; b = 0; return true;
            case "CYAN" or "AQUA": r = 0; g = 255; b = 255; return true;
            case "MAGENTA" or "FUCHSIA": r = 255; g = 0; b = 255; return true;
            case "SKYBLUE": r = 135; g = 206; b = 235; return true;
            default: r = g = b = 0; return false;
        }
    }

    private static string[] ParseFontChain(string? text, string[] fallback) {
        if (Blank(text) is not { } value) {
            return fallback;
        }
        var parts = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 0 ? fallback : parts;
    }

    /// <summary>空串/纯空白的输入一律当作"没配"（免得用户写了 `GMK_OVERLAY_TEXT_COLOR=` 就崩）。</summary>
    private static string? Blank(string? text) => string.IsNullOrWhiteSpace(text) ? null : text.Trim();
}
