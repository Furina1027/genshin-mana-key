namespace GenshinSniffer;

/// <summary>
/// 遮罩上的一行。
///
/// **前缀与正文分开存**，因为它们要用不同字体画：前缀是 BGI 那种等宽时间戳/级别
/// （`[20:46:54 INF] `），正文常常是中文，而等宽字体链（Cascadia Mono / Consolas /
/// Courier New）没有 CJK 字形。这正是 BGI 的实际观感 —— WPF 逐字形回退：
/// 拉丁走 Cascadia Mono、中文走 MiSans。这里用 GDI 手工复刻同一条规则
/// （见 <see cref="OverlayLines.NeedsCjkFont"/>）。
/// </summary>
internal readonly record struct OverlayLine(string Prefix, string Message) {

    /// <summary>整行文本（前缀 + 正文）。单测断言与排障时看这个。</summary>
    public string Text => Prefix + Message;
}

/// <summary>
/// 遮罩上要显示的内容 —— 只保留最近 <see cref="MaxLines"/> 行的环形缓冲，
/// 以及把一条日志拼成 BetterGI 那行格式的纯函数。
///
/// **谁会进到这里**：只有配对成功那几行（走 <see cref="Log.Pair"/>）。其余日志一律只写文件，
/// 碰不到本类 —— "前台只显示已配对的那行"这条规则是在 <see cref="Log"/> 那侧分流掉的，
/// 不是在这里过滤字符串（那样又脆又容易漏）。
///
/// 为什么单独抽成一个纯类：遮罩窗口本身是 Win32/GDI 代码，没法在单测里跑；
/// 而"显示哪几行、怎么拼、满了淘汰谁、什么时候算空闲"这些规则恰恰是最容易写错
/// 又最难人工发现的部分（上限算错会一直涨、前缀拼错会让人以为是别的级别、
/// 换行没拆开会被 GDI 吃掉后半截）。所以规则全放这里，窗口只负责把 <see cref="Snapshot"/> 画出来。
///
/// 前台格式照 BGI 的日志遮罩（也就是它的 Serilog 输出模板）：
/// <code>[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}</code>
/// 即 `[20:46:54 INF] ★★ 已配对(掩码) Cs_ZD_… → paired_keys.json (F5AC…)`。
///
/// **后台 dumper.log 刻意不同**：那边仍然是 `[MM-dd HH:mm:ss] 消息`，一个字节都不改。
/// 前台要的是 BGI 的观感（只有时分秒、带级别），后台要的是可追溯的完整日期。
/// </summary>
internal sealed class OverlayLines {

    /// <summary>
    /// 最多保留多少行。**跟着字号走**：BGI 的默认日志框高 188/1080（1080p 下 188px），
    /// 12px 字号时行距约 16px → 约 11 行；字号翻倍后行距变成约 25px → 188/25 ≈ 7 行。
    ///
    /// 为什么必须跟着缩：遮罩是从 y=822 往下长的，1080p 下只剩 258px 可用，
    /// 11 行 × 25px = 279px 会直接越过屏幕下沿被切掉。
    /// </summary>
    public const int MaxLines = 7;

    /// <summary>
    /// 距最后一条**前台内容**超过这么久（毫秒）就认为"没有新日志了"，遮罩可以收起来。
    ///
    /// 只算前台内容（配对行），**不算普通日志**：普通日志本来就只进 dumper.log，
    /// 而注入之后管道消息是持续不断的，真拿它们当"有新日志"的话遮罩就永远收不回去了。
    /// </summary>
    public const int IdleHideMs = 10_000;

    private readonly Queue<OverlayLine> _lines = new();

    /// <summary>已经喂进来了多少**显示行**（多行消息会拆成多行，故可能大于调用次数）。不受 <see cref="MaxLines"/> 截断影响。</summary>
    public int PushedCount { get; private set; }

    /// <summary>
    /// 清空当前内容。空闲隐藏时用它 —— 否则下次配对时会把几分钟前的旧密钥一起摆回屏幕上，
    /// 而用户要的就是"只看刚配对的那条"。（<see cref="PushedCount"/> 是本会话累计计数，不重置。）
    /// </summary>
    public void Clear() => _lines.Clear();

    /// <summary>
    /// 空闲判定（纯函数，方便单测）：距离最后一次前台推送是否已经超过 <see cref="IdleHideMs"/>。
    /// </summary>
    public static bool ShouldHide(long nowTicks, long lastPushTicks) =>
        nowTicks - lastPushTicks >= IdleHideMs;

    /// <summary>
    /// 追加一条日志：自己拼 BGI 式前缀，并把消息里的换行拆成多条显示行。
    ///
    /// 为什么要拆换行：异常消息常常是多行的，而 GDI 的 `DT_SINGLELINE` 只会画出第一行，
    /// 后面的内容会静默消失 —— 恰恰是排障时最需要的那几行。
    /// 拆出来的后续行用与前缀等长的空格缩进，让它们看起来仍然属于同一条日志。
    /// </summary>
    public void Push(DateTime timestamp, LogLevel level, string message) {
        var prefix = Prefix(timestamp, level);
        var indent = new string(' ', prefix.Length);
        var first = true;
        foreach (var raw in message.Split('\n')) {
            Enqueue(new OverlayLine(first ? prefix : indent, raw.TrimEnd('\r')));
            first = false;
        }
    }

    private void Enqueue(OverlayLine line) {
        PushedCount++;
        _lines.Enqueue(line);
        while (_lines.Count > MaxLines) {
            _lines.Dequeue();
        }
    }

    /// <summary>当前应该画出来的行（顺序 = 从上到下）。空列表表示什么都不画（调用方据此隐藏窗口）。</summary>
    public IReadOnlyList<OverlayLine> Snapshot() => [.. _lines];

    /// <summary>BGI 的 `[{Timestamp:HH:mm:ss} {Level:u3}] ` 前缀（含尾随空格）。</summary>
    public static string Prefix(DateTime timestamp, LogLevel level) =>
        $"[{timestamp:HH:mm:ss} {Abbreviation(level)}] ";

    /// <summary>级别的三字母缩写 —— 与 Serilog 的 `{Level:u3}` 一致（BGI 的日志遮罩用的就是这个格式串）。</summary>
    public static string Abbreviation(LogLevel level) => level switch {
        LogLevel.Warn => "WRN",
        LogLevel.Error => "ERR",
        _ => "INF",
    };

    /// <summary>
    /// 这段文字能不能用等宽字体画。判据是"纯 ASCII"：只要出现非 ASCII 字符
    /// （中文、★、→、…）就换成中文 UI 字体，否则 GDI 会画出方块或干脆空白。
    ///
    /// 为什么不用"检测字体里有没有这个字形"：GDI 的字体链接（FontLink）取决于注册表，
    /// 本例机器上 Consolas 就没注册 SystemLink —— 靠它等于把可读性交给运气。
    /// 直接按"含非 ASCII 就用 CJK 字体"是确定性的。
    /// </summary>
    public static bool NeedsCjkFont(string text) {
        foreach (var c in text) {
            if (!IsMonoSafe(c)) {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// 把正文切成"等宽段 / 中文段"交替的若干段 —— 这是 BGI 逐字形回退的等价物。
    ///
    /// BGI 的 FontFamily 链是 `Cascadia Mono, Consolas, …, MiSans`，WPF 对**每个字形**依次尝试：
    /// 拉丁字符命中 Cascadia Mono，中日韩字符才落到 MiSans。GDI 没有这个机制，所以手工切段。
    ///
    /// 效果：`★★ 已配对 Cs_ZD_AQ70201201_SLT → paired_keys.json (F5AC…)` 里
    /// 密钥与文件名仍然是等宽的（能对得齐、方便肉眼核对），只有中文那几段换字体。
    /// </summary>
    public static OverlayRun[] SplitRuns(string text) {
        if (text.Length == 0) {
            return [];
        }
        var runs = new List<OverlayRun>(4);
        var start = 0;
        var cjk = !IsMonoSafe(text[0]);
        for (var i = 1; i < text.Length; i++) {
            var next = !IsMonoSafe(text[i]);
            if (next != cjk) {
                runs.Add(new OverlayRun(text[start..i], cjk));
                start = i;
                cjk = next;
            }
        }
        runs.Add(new OverlayRun(text[start..], cjk));
        return [.. runs];
    }

    /// <summary>ASCII 里等宽链（Cascadia Mono/Consolas/Courier New）一定有字形。</summary>
    private static bool IsMonoSafe(char c) => c <= '\x7e';
}

/// <summary>正文里的一段连续文字 + 它该用哪条字体链（<see cref="Cjk"/> = 中文 UI 链）。</summary>
internal readonly record struct OverlayRun(string Text, bool Cjk);
