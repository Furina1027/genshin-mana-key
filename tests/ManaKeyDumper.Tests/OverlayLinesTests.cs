using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 遮罩显示规则测试。
///
/// 这些规则出错的后果很隐蔽：行数上限算错会让角落一直涨、前缀拼错会让人以为是别的级别、
/// 换行没拆开会被 GDI 的单行绘制静默吃掉后半截 —— 而它们全靠人工盯着游戏画面才能发现，所以放单测。
///
/// 本文件钉的是**前台格式**（BGI 的 `[HH:mm:ss INF] 消息`）。
/// 后台 dumper.log 的 `[MM-dd HH:mm:ss] 消息` 不在覆盖范围内：那一路本次一个字节都没有改动。
/// </summary>
public sealed class OverlayLinesTests {

    /// <summary>固定时间戳，免得断言跟着"现在几点"漂。</summary>
    private static readonly DateTime T = new(2026, 10, 16, 20, 46, 54);

    /// <summary>"[20:46:54 WRN] " 的长度 —— 续行缩进要跟它一样宽。</summary>
    private const int PrefixLength = 15;

    [Fact]
    public void Prefix_MatchesBgiLogOverlayFormat() {
        Assert.Equal("[20:46:54 INF] ", OverlayLines.Prefix(T, LogLevel.Info));
        Assert.Equal("[20:46:54 WRN] ", OverlayLines.Prefix(T, LogLevel.Warn));
        Assert.Equal("[20:46:54 ERR] ", OverlayLines.Prefix(T, LogLevel.Error));
    }

    /// <summary>三字母缩写与 Serilog 的 `{Level:u3}` 一致（BGI 的输出模板用的正是这个占位符）。</summary>
    /// <remarks>
    /// 写成一条 [Fact] 而不是 [Theory]：<see cref="LogLevel"/> 是 internal，
    /// 而 public 的测试方法签名里不能出现可访问性更低的类型（CS0051）。
    /// </remarks>
    [Fact]
    public void Abbreviation_MatchesSerilogU3() {
        Assert.Equal("INF", OverlayLines.Abbreviation(LogLevel.Info));
        Assert.Equal("WRN", OverlayLines.Abbreviation(LogLevel.Warn));
        Assert.Equal("ERR", OverlayLines.Abbreviation(LogLevel.Error));
    }

    /// <summary>
    /// 前缀必须永远是纯 ASCII —— 它固定用等宽字体画，而那条链（Cascadia Mono/Consolas）
    /// 没有 CJK 字形。哪天有人往前缀里塞中文，这条会先炸。
    /// </summary>
    [Fact]
    public void Prefix_IsAlwaysAscii() {
        foreach (var level in new[] { LogLevel.Info, LogLevel.Warn, LogLevel.Error }) {
            Assert.False(OverlayLines.NeedsCjkFont(OverlayLines.Prefix(T, level)));
        }
    }

    /// <summary>一条日志都还没有时什么都不画（调用方据此隐藏窗口，而不是留个空框）。</summary>
    [Fact]
    public void BeforeAnyLog_NothingIsShown() {
        var lines = new OverlayLines();

        Assert.Empty(lines.Snapshot());
        Assert.Equal(0, lines.PushedCount);
    }

    /// <summary>最新的在最下面 —— 和 BGI 的 RichTextBox 一样是往下追加。</summary>
    [Fact]
    public void Push_KeepsNewestAtTheBottom() {
        var lines = new OverlayLines();
        lines.Push(T, LogLevel.Info, "第一条");
        lines.Push(T, LogLevel.Info, "第二条");

        var snapshot = lines.Snapshot();

        Assert.Equal(2, snapshot.Count);
        Assert.Equal("[20:46:54 INF] 第一条", snapshot[0].Text);
        Assert.Equal("[20:46:54 INF] 第二条", snapshot[^1].Text);
    }

    /// <summary>
    /// 多行消息必须拆成多条显示行：GDI 的 DT_SINGLELINE 只画第一行，后面的会静默消失，
    /// 而那恰恰是排障时最需要的部分（异常消息常常是多行的）。
    /// </summary>
    [Fact]
    public void Push_SplitsEmbeddedNewlinesAndIndentsContinuations() {
        var lines = new OverlayLines();
        lines.Push(T, LogLevel.Warn, "第一行\r\n第二行\n第三行");

        var snapshot = lines.Snapshot();

        Assert.Equal(3, snapshot.Count);
        Assert.Equal("[20:46:54 WRN] 第一行", snapshot[0].Text);
        Assert.Equal("第二行", snapshot[1].Message);
        Assert.Equal("第三行", snapshot[2].Message);
        // 续行的前缀是等长空格：既缩进对齐，又不至于被当成一条新日志
        Assert.Equal(new string(' ', PrefixLength), snapshot[1].Prefix);
        Assert.Equal(new string(' ', PrefixLength), snapshot[2].Prefix);
    }

    /// <summary>空消息也要占一行（否则`Push` 的计数与显示对不上）。</summary>
    [Fact]
    public void Push_WithEmptyMessage_StillProducesOneLine() {
        var lines = new OverlayLines();
        lines.Push(T, LogLevel.Info, "");

        var snapshot = lines.Snapshot();

        Assert.Single(snapshot);
        Assert.Equal("[20:46:54 INF] ", snapshot[0].Text);
    }

    /// <summary>超过上限时淘汰最早的，保留最近 MaxLines 条。</summary>
    [Fact]
    public void KeepsOnlyTheNewestLines() {
        var lines = new OverlayLines();
        for (var i = 1; i <= OverlayLines.MaxLines + 3; i++) {
            lines.Push(T, LogLevel.Info, $"第 {i} 条");
        }

        var snapshot = lines.Snapshot();

        Assert.Equal(OverlayLines.MaxLines, snapshot.Count);
        Assert.Equal("[20:46:54 INF] 第 4 条", snapshot[0].Text);          // 1..3 已被淘汰
        Assert.Equal($"[20:46:54 INF] 第 {OverlayLines.MaxLines + 3} 条", snapshot[^1].Text);
    }

    /// <summary>换行拆出来的续行也受同一个上限约束（不能因为一条长消息就把上限撑破）。</summary>
    [Fact]
    public void MultiLineMessage_AlsoObeysTheLimit() {
        var parts = Enumerable.Range(1, OverlayLines.MaxLines + 5).Select(i => $"第 {i} 行").ToArray();

        var lines = new OverlayLines();
        lines.Push(T, LogLevel.Info, string.Join('\n', parts));

        Assert.Equal(OverlayLines.MaxLines, lines.Snapshot().Count);
    }

    /// <summary>PushedCount 是"本会话一共显示过多少行"，不该被显示上限截断。</summary>
    [Fact]
    public void PushedCount_IsNotCappedByDisplayLimit() {
        var lines = new OverlayLines();
        for (var i = 0; i < OverlayLines.MaxLines * 2; i++) {
            lines.Push(T, LogLevel.Info, "x");
        }

        Assert.Equal(OverlayLines.MaxLines * 2, lines.PushedCount);
        Assert.Equal(OverlayLines.MaxLines, lines.Snapshot().Count);
    }

    /// <summary>
    /// 7 行是照 BGI 的默认日志框折出来的（框高 188/1080，字号翻倍后行距约 25px → 188/25 ≈ 7）。
    /// 这条断言是防"随手把上限调大"：从 y=822 往下只有 258px 可用，行数再多就顶出屏幕下沿了。
    /// </summary>
    [Fact]
    public void MaxLines_FitsBgiDefaultBoxAndTheScreen() {
        Assert.Equal(7, OverlayLines.MaxLines);
    }

    /// <summary>含非 ASCII 的正文要换中文 UI 字体（等宽链没有 CJK 字形，硬画会出方块）。</summary>
    [Theory]
    [InlineData("", false)]
    [InlineData("[20:46:54 INF] ", false)]
    [InlineData("[DLL] MANAKEY 1234567890ABCDEF", false)]
    [InlineData("游戏: E:\\Genshin\\YuanShen.exe", true)]
    [InlineData("★★ 已配对(掩码)", true)]
    [InlineData("→", true)]
    [InlineData("…", true)]
    public void NeedsCjkFont_IsAsciiOnlyCriterion(string text, bool expected) {
        Assert.Equal(expected, OverlayLines.NeedsCjkFont(text));
    }

    /// <summary>
    /// 逐字形回退的切段：ASCII 连成一段、非 ASCII 连成一段，交替出现。
    /// 这是 BGI 那条 FontFamily 链（Cascadia Mono → … → MiSans）在 GDI 下的等价物 ——
    /// 密钥与文件名必须留在等宽段里，才能对齐、方便肉眼核对。
    /// </summary>
    [Fact]
    public void SplitRuns_SplitsAtEveryScriptBoundary() {
        var runs = OverlayLines.SplitRuns("AB中文CD");

        Assert.Equal(3, runs.Length);
        Assert.Equal("AB", runs[0].Text);
        Assert.False(runs[0].Cjk);
        Assert.Equal("中文", runs[1].Text);
        Assert.True(runs[1].Cjk);
        Assert.Equal("CD", runs[2].Text);
        Assert.False(runs[2].Cjk);
    }

    [Fact]
    public void SplitRuns_EmptyOrSingleScript_StaysOneRun() {
        Assert.Empty(OverlayLines.SplitRuns(""));

        var ascii = OverlayLines.SplitRuns("[DLL] MANAKEY 1234567890ABCDEF");
        Assert.Single(ascii);
        Assert.False(ascii[0].Cjk);

        var cjk = OverlayLines.SplitRuns("中文日志");
        Assert.Single(cjk);
        Assert.True(cjk[0].Cjk);
    }

    /// <summary>
    /// 切段的不变式：拼回去必须与原串逐字相同；每段的标记必须与判据一致；
    /// 且相邻两段绝不会用同一条字体链（否则就是白切一段）。
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("★★ 已配对(掩码) Cs_ZD_AQ70201201_SLT → paired_keys.json")]
    [InlineData("a中b文c")]
    [InlineData("全中文")]
    [InlineData("all ascii")]
    public void SplitRuns_PreservesTextAndFlags(string text) {
        var runs = OverlayLines.SplitRuns(text);

        Assert.Equal(text, string.Concat(runs.Select(run => run.Text)));

        bool? previous = null;
        foreach (var run in runs) {
            Assert.Equal(OverlayLines.NeedsCjkFont(run.Text), run.Cjk);
            Assert.True(previous != run.Cjk, "相邻两段选了同一条字体链");
            previous = run.Cjk;
        }
    }

    /// <summary>空闲隐藏时用的清空：清完什么都不画（调用方据此把窗口藏起来）。</summary>
    [Fact]
    public void Clear_RemovesEverything() {
        var lines = new OverlayLines();
        lines.Push(T, LogLevel.Info, "第一条");
        lines.Push(T, LogLevel.Info, "第二条");

        lines.Clear();

        Assert.Empty(lines.Snapshot());
        Assert.Equal(2, lines.PushedCount);       // 累计计数不重置：它统计的是"本会话显示过多少行"
    }

    /// <summary>清空之后再来一条，屏幕上只该有这一条 —— 这正是"10 秒后隐藏并清空"的意义。</summary>
    [Fact]
    public void AfterClear_OnlyTheNewLineShows() {
        var lines = new OverlayLines();
        lines.Push(T, LogLevel.Info, "几分钟前的旧密钥");
        lines.Clear();
        lines.Push(T, LogLevel.Info, "刚配上的新密钥");

        var snapshot = lines.Snapshot();

        Assert.Single(snapshot);
        Assert.Equal("[20:46:54 INF] 刚配上的新密钥", snapshot[0].Text);
    }

    /// <summary>
    /// 空闲判定的边界：差 1 毫秒不算空闲、正好到点算空闲。
    /// 这个常数决定"配对提示在屏幕上待多久"，调错的表现是提示一闪而过或者赖着不走。
    /// </summary>
    [Fact]
    public void ShouldHide_TriggersExactlyAtTheTimeout() {
        const long last = 100_000;

        Assert.False(OverlayLines.ShouldHide(last + OverlayLines.IdleHideMs - 1, last));
        Assert.True(OverlayLines.ShouldHide(last + OverlayLines.IdleHideMs, last));
        Assert.True(OverlayLines.ShouldHide(last + (OverlayLines.IdleHideMs * 3), last));
    }

    /// <summary>10 秒是需求里写死的值（"10s 没有新日志就隐藏"），别顺手改。</summary>
    [Fact]
    public void IdleHide_IsTenSeconds() {
        Assert.Equal(10_000, OverlayLines.IdleHideMs);
    }
}
