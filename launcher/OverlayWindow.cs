using System.Runtime.InteropServices;

namespace GenshinSniffer;

/// <summary>
/// 游戏窗口左下角的实时日志遮罩（纯 Win32 分层窗口，无 WPF/WinForms，NativeAOT 兼容）。
///
/// 设计要点（与 BetterGI 的遮罩同源，但实现不同 —— WPF 不支持 NativeAOT）：
///   · 样式 `WS_POPUP + LAYERED|TRANSPARENT|NOACTIVATE|TOOLWINDOW`：逐像素透明、鼠标穿透、
///     不抢焦点、不进 Alt+Tab；**刻意不用 TOPMOST** —— 那会让它飘在所有窗口之上（实测反馈），
///     改成把游戏窗口设成它的 owner，并且只在前台窗口是游戏时才显示；
///   · 渲染：GDI 把文字画进 32bpp DIB（白字 + 深灰偏移投影），再把"亮度"写进 alpha，
///     最后 `UpdateLayeredWindow(ULW_ALPHA)` 提交 —— 见 <see cref="OverlayAlpha"/>；
///   · 位置：以 1080p 为基准的比例制，锚定游戏窗口**左下角**，随窗口尺寸/移动每 250ms 校正；
///   · 线程：Win32 窗口是单线程的，所以窗口与消息循环跑在**主线程**；
///     管道读取线程只把日志塞进 <see cref="OverlayLines"/> 并 `PostMessage`，绝不直接碰窗口；
///   · 内容：**只有配对成功那一行**（<see cref="Log.Pair"/>，BGI 式 `[HH:mm:ss INF] 消息`）。
///     其余日志一律只进 dumper.log —— 遮罩贴在游戏画面上，管道诊断那几十行没人会看；
///   · 收放：有内容才显示；<see cref="OverlayLines.IdleHideMs"/> 内没有新的前台内容就清空并隐藏，
///     像一条会自己消失的提示，不长期占着游戏画面；
///   · 字体：前缀固定用等宽链（BGI 的 Cascadia Mono → Consolas → Courier New），
///     正文含中文时换中文 UI 链 —— GDI 不像 WPF 那样自动逐字形回退，
///     而这条等宽链没有 CJK 字形（判据见 <see cref="OverlayLines.NeedsCjkFont"/>）。
///
/// 本类只做"画"和"摆"，不做任何日志/配对逻辑，**也不影响 dumper.log 的写入**。
/// </summary>
internal static unsafe class OverlayWindow {

    private const string ClassName = "GenshinManaKeyOverlay";

    /// <summary>跟随游戏窗口位置/尺寸的刷新间隔（也决定 Alt+Tab 后遮罩消失/回来的延迟）。</summary>
    private const uint FollowIntervalMs = 250;

    /// <summary>
    /// 外观（颜色 / 字体链 / 私有字体文件）。**进程内只解析一次环境变量** ——
    /// 遮罩跑在渲染热路径上，不该每条日志都去读一次环境。
    /// 调法见 <see cref="OverlayStyle"/> 的类注释。
    /// </summary>
    private static readonly OverlayStyle Style = OverlayStyle.FromEnvironment();

    /// <summary>投影偏移：上下左右各 1px（静态数组，避免每行都新建一个数组）。</summary>
    private static readonly (int Dx, int Dy)[] ShadowOffsets = [(1, 0), (-1, 0), (0, 1), (0, -1)];

    /// <summary>
    /// 自动查找的字体文件名（`GMK_OVERLAY_FONT_FILE` 没设时按这个顺序找）。
    /// 两个位置覆盖了"直接丢在 exe 旁边"和"照抄 BGI 的目录结构"两种放法。
    /// </summary>
    private static readonly string[] DefaultFontFileNames = [
        Path.Combine(Paths.BaseDirectory, "MiSans-Regular.ttf"),
        Path.Combine(Paths.BaseDirectory, "Resources", "Fonts", "MiSans-Regular.ttf"),
    ];

    private static readonly object Lock = new();
    private static readonly OverlayLines Content = new();

    private static nint _hwnd;
    private static nint _memDc;
    private static nint _dib;
    private static nint _dibBits;
    private static int _dibWidth, _dibHeight;
    private static nint _fontMono;
    private static nint _fontUi;
    private static int _fontPx = -1;
    private static uint _gamePid;
    private static nint _gameHwnd;
    private static bool _shown;
    private static bool _destroyed;

    private static int _findPid;
    private static nint _foundHwnd;
    private static bool _selfTest;
    private static bool _renderErrorLogged;
    /// <summary>内容版本号（每次 PushPairing 递增）：与"已画版本 + 锚点矩形"一起做重绘去抖。</summary>
    private static int _contentVersion;
    /// <summary>最后一条前台内容的时刻（Environment.TickCount64）：空闲超过 <see cref="OverlayLines.IdleHideMs"/> 就收起遮罩。</summary>
    private static long _lastPushTicks = Environment.TickCount64;
    private static int _drawnVersion = -1;
    private static OverlayNative.RECT _drawnAnchor;

    /// <summary>窗口是否已建好（没建好时调用方应回退到控制台模式）。</summary>
    public static bool Available => _hwnd != 0;

    // ==================== 建/销 ====================

    /// <summary>注册窗口类并创建窗口（先隐藏，等找到游戏窗口再显示）。失败返回 false。</summary>
    public static bool Create() {
        if (_hwnd != 0) {
            return true;
        }
        var hInstance = OverlayNative.GetModuleHandleW(0);
        var classNamePtr = Marshal.StringToHGlobalUni(ClassName);
        try {
            var wc = new OverlayNative.WNDCLASSW {
                lpfnWndProc = (nint) (delegate* unmanaged<nint, uint, nint, nint, nint>) &WndProc,
                hInstance = hInstance,
                lpszClassName = classNamePtr,
            };
            if (OverlayNative.RegisterClassW(in wc) == 0) {
                Log.Warn($"遮罩窗口类注册失败（Win32 错误 {Marshal.GetLastWin32Error()}），改用控制台日志");
                return false;
            }
            // 注意：**不加 WS_EX_TOPMOST**。加了它会飘在所有窗口之上（实测反馈）；
            // 现在改成"挂在游戏窗口的 owner 链上 + 只在前台是游戏时显示"，双保险。
            const uint exStyle = OverlayNative.WS_EX_LAYERED | OverlayNative.WS_EX_TRANSPARENT
                | OverlayNative.WS_EX_NOACTIVATE | OverlayNative.WS_EX_TOOLWINDOW;
            _hwnd = OverlayNative.CreateWindowExW(exStyle, ClassName, "GenshinManaKey",
                OverlayNative.WS_POPUP, 0, 0, OverlayLayout.MinWidth, 120, 0, 0, hInstance, 0);
            if (_hwnd == 0) {
                Log.Warn($"遮罩窗口创建失败（Win32 错误 {Marshal.GetLastWin32Error()}），改用控制台日志");
                return false;
            }
            _memDc = OverlayNative.CreateCompatibleDC(0);
            if (_memDc == 0) {
                Log.Warn("遮罩用的内存 DC 创建失败，改用控制台日志");
                Destroy();
                return false;
            }
            // 字体文件必须在建字体之前私有加载：这样 EnsureFonts 的候选链里 "MiSans" 才能命中
            LoadPrivateFont();
            OverlayNative.SetTimer(_hwnd, 1, FollowIntervalMs, 0);
            Log.Write($"遮罩窗口已创建（左下角实时日志，滚动显示最近 {OverlayLines.MaxLines} 条）");
            Log.Write($"遮罩样式: {Style.Describe()}");
            return true;
        } finally {
            Marshal.FreeHGlobal(classNamePtr);
        }
    }

    /// <summary>任意线程可调：结束消息循环。</summary>
    public static void RequestExit() {
        var hwnd = _hwnd;
        if (hwnd != 0) {
            OverlayNative.PostMessageW(hwnd, OverlayNative.WM_OVERLAY_GAME_EXIT, 0, 0);
        }
    }

    public static void Destroy() {
        if (_hwnd != 0 && !_destroyed) {
            OverlayNative.DestroyWindow(_hwnd);
        }
        _hwnd = 0;
    }

    // ==================== 对外内容接口（线程安全）====================

    /// <summary>
    /// 自检模式：不跟随游戏窗口，直接拿整个屏幕当锚点。
    /// 用途是"只看遮罩本身对不对"（位置/穿透/Alt+Tab/字体）—— 不需要启动游戏、不碰反作弊。
    /// </summary>
    public static void SetSelfTestTarget() {
        _selfTest = true;
        PostUpdate();
    }

    /// <summary>告诉遮罩跟随哪个进程的游戏窗口。</summary>
    public static void SetTargetProcess(uint pid) {
        lock (Lock) {
            _gamePid = pid;
        }
        PostUpdate();
    }

    /// <summary>
    /// 推送一条**前台内容**（配对成功那行）：BGI 式前缀 + 消息。**任意线程可调** ——
    /// 只往 <see cref="Content"/> 塞一行、记一下时间戳、再 PostMessage，绝不直接碰窗口
    /// （窗口只能在主线程上动）。
    ///
    /// 只有 <see cref="Log.Pair"/> 会调到这里；普通日志在 <see cref="Log"/> 那侧就分流掉了。
    /// 同时这里会刷新空闲计时：<see cref="OverlayLines.IdleHideMs"/> 内没有新的前台内容就收起遮罩。
    /// </summary>
    public static void PushPairing(DateTime timestamp, LogLevel level, string message) {
        lock (Lock) {
            Content.Push(timestamp, level, message);
        }
        Volatile.Write(ref _lastPushTicks, Environment.TickCount64);
        Interlocked.Increment(ref _contentVersion);
        PostUpdate();
    }

    /// <summary>控制台被隐藏时的兜底提示（启动期致命错误用）。阻塞直到用户点确定，符合双击场景。</summary>
    public static void ShowFatal(string title, string text) {
        const uint mbOk = 0x00000000;
        const uint mbIconError = 0x00000010;
        const uint mbSetForeground = 0x00010000;
        const uint mbTopMost = 0x00040000;
        OverlayNative.MessageBoxW(0, text, title, mbOk | mbIconError | mbSetForeground | mbTopMost);
    }

    private static void PostUpdate() {
        var hwnd = _hwnd;
        if (hwnd != 0) {
            OverlayNative.PostMessageW(hwnd, OverlayNative.WM_OVERLAY_UPDATE, 0, 0);
        }
    }

    // ==================== 消息循环 ====================

    /// <summary>在当前线程跑消息循环，阻塞直到 <see cref="RequestExit"/> 或窗口销毁。</summary>
    public static void RunMessageLoop() {
        if (_hwnd == 0) {
            return;
        }
        while (OverlayNative.GetMessageW(out var msg, 0, 0, 0) > 0) {
            OverlayNative.TranslateMessage(in msg);
            OverlayNative.DispatchMessageW(in msg);
        }
    }

    // ==================== 窗口过程 ====================

    [UnmanagedCallersOnly]
    private static nint WndProc(nint hwnd, uint msg, nint wParam, nint lParam) {
        switch (msg) {
            case OverlayNative.WM_NCHITTEST:
                return OverlayNative.HTTRANSPARENT;      // 双保险：点击穿透到游戏
            case OverlayNative.WM_TIMER:
            case OverlayNative.WM_OVERLAY_UPDATE:
                // 画不出来绝不能带走启动器（此刻游戏正在运行）：吞掉异常，只报一次
                try {
                    OnTick();
                } catch (Exception e) {
                    if (!_renderErrorLogged) {
                        _renderErrorLogged = true;
                        Log.Warn($"遮罩渲染异常（已忽略，后续不再重复报）：{e.Message}");
                    }
                }
                return 0;
            case OverlayNative.WM_OVERLAY_GAME_EXIT:
            case OverlayNative.WM_CLOSE:
                OverlayNative.DestroyWindow(hwnd);
                return 0;
            case OverlayNative.WM_DESTROY:
                _destroyed = true;
                CleanupGdi();
                OverlayNative.KillTimer(hwnd, 1);
                OverlayNative.PostQuitMessage(0);
                return 0;
            default:
                return OverlayNative.DefWindowProcW(hwnd, msg, wParam, lParam);
        }
    }

    // ==================== 跟随游戏窗口 ====================

    /// <summary>
    /// 每次 tick（250ms）：更新游戏窗口 → **只在游戏处于前台时显示** → 需要时重绘。
    ///
    /// 为什么必须有"前台"这道判断：遮罩是独立的顶层窗口，光靠 z-order 的话，
    /// 用户切到浏览器/桌面时它仍会留在最上面（实测反馈就是"悬浮在所有窗口"）。
    /// 现在它既挂在游戏窗口的 owner 链上，又在前台不是游戏时主动隐藏 —— 双保险。
    /// </summary>
    private static void OnTick() {
        // 空闲隐藏放最前面：不管自检还是正常模式，10 秒没有新的前台内容就收起来
        if (HideIfIdle()) {
            return;
        }
        if (_selfTest) {
            Redraw();       // 自检模式锚在屏幕上：不跟游戏窗口，也不做前台判断
            return;
        }
        UpdateGameWindow();
        if (_gameHwnd == 0) {
            HideOverlay();
            return;
        }
        if (OverlayNative.GetForegroundWindow() != _gameHwnd) {
            HideOverlay();      // 游戏不在前台 → 跟着消失；回到前台时下一次 tick 会自动再显示
            return;
        }
        Redraw();
    }

    /// <summary>
    /// 空闲隐藏：距最后一条前台内容超过 <see cref="OverlayLines.IdleHideMs"/> 就收起遮罩，
    /// **并且把内容清掉** —— 否则下次配对时会把几分钟前的旧密钥一起摆回屏幕上，
    /// 而用户要的就是"只看刚配上的那条"。返回 true 表示这一 tick 已处理完（不必再重绘）。
    ///
    /// 只在"当前正显示"时才动手：已经藏起来了就没什么可收的，也不该反复清内容。
    /// </summary>
    private static bool HideIfIdle() {
        if (!_shown || !OverlayLines.ShouldHide(Environment.TickCount64, Volatile.Read(ref _lastPushTicks))) {
            return false;
        }
        lock (Lock) {
            Content.Clear();
        }
        Interlocked.Increment(ref _contentVersion);
        HideOverlay();
        return true;
    }

    /// <summary>找游戏主窗口；窗口变了就把遮罩挂到它名下（owner），并作废重绘缓存。</summary>
    private static void UpdateGameWindow() {
        if (_selfTest) {
            return;                      // 自检模式锚在屏幕上，不跟游戏窗口
        }
        uint pid;
        lock (Lock) {
            pid = _gamePid;
        }
        if (pid == 0) {
            return;
        }
        if (_gameHwnd != 0 && OverlayNative.IsWindowVisible(_gameHwnd)) {
            return;                      // 已经找到且还在，不必每 tick 都枚举
        }
        var found = FindGameWindow(pid);
        if (found == _gameHwnd) {
            return;
        }
        _gameHwnd = found;
        _drawnVersion = -1;              // 换窗口/丢窗口都要重画
        if (found != 0) {
            // 把游戏窗口设为 owner：遮罩就跟着游戏走，也不会盖在别的程序上面
            OverlayNative.SetWindowLongPtrW(_hwnd, OverlayNative.GWLP_HWNDPARENT, found);
            Log.Write($"遮罩已挂到游戏窗口 0x{found:X}（只在原神窗口之上显示）");
        }
    }

    /// <summary>
    /// 游戏主窗口 = 属于该进程、可见、没有 owner、且尺寸像主窗口的顶层窗口。
    /// 尺寸过滤是为了排除 Unity 的隐藏/辅助小窗口（原神主窗口是 UnityWndClass）。
    /// </summary>
    private static nint FindGameWindow(uint pid) {
        _findPid = (int) pid;
        _foundHwnd = 0;
        var callback = (nint) (delegate* unmanaged<nint, nint, int>) &EnumWindowsProc;
        OverlayNative.EnumWindows(callback, 0);
        return _foundHwnd;
    }

    [UnmanagedCallersOnly]
    private static int EnumWindowsProc(nint hwnd, nint lParam) {
        OverlayNative.GetWindowThreadProcessId(hwnd, out var pid);
        if (pid != (uint) _findPid || !OverlayNative.IsWindowVisible(hwnd)) {
            return 1;
        }
        if (OverlayNative.GetWindow(hwnd, OverlayNative.GW_OWNER) != 0) {
            return 1;
        }
        if (!OverlayNative.GetWindowRect(hwnd, out var rect) || rect.Width < 200 || rect.Height < 200) {
            return 1;
        }
        _foundHwnd = hwnd;
        return 0;   // 找到即停止枚举
    }

    // ==================== 渲染 ====================

    /// <summary>遮罩贴哪块矩形：正常模式是游戏主窗口，自检模式是整个屏幕。</summary>
    private static bool TryGetAnchorRect(out OverlayNative.RECT rect) {
        rect = default;
        if (_selfTest) {
            rect = new OverlayNative.RECT {
                Left = 0,
                Top = 0,
                Right = OverlayNative.GetSystemMetrics(OverlayNative.SM_CXSCREEN),
                Bottom = OverlayNative.GetSystemMetrics(OverlayNative.SM_CYSCREEN),
            };
            return rect.Width > 0 && rect.Height > 0;
        }
        if (_gameHwnd == 0) {
            return false;
        }
        return OverlayNative.GetWindowRect(_gameHwnd, out rect);
    }

    /// <summary>
    /// 重绘一次（只在主线程调用）。
    ///
    /// ⚠️ **这里绝对不能 Log.Write**：日志会被推送回遮罩 → 内容版本号 +1 → 又触发一次重绘 →
    /// 自激成每秒几百次的重绘风暴（实测踩过：一条临时诊断日志把版本号从 1080 冲到 1600+，
    /// 日志文件也跟着膨胀）。重绘路径上唯一允许的日志是"只报一次"的那种 ——
    /// 见 <see cref="WndProc"/> 里 <c>_renderErrorLogged</c> 兜住的那条。
    /// 下面这条"提交失败"只在真失败时才会命中，正常情况下不会写。
    /// </summary>
    private static void Redraw() {
        if (_hwnd == 0 || _destroyed) {
            return;
        }
        OverlayLine[] lines;
        lock (Lock) {
            lines = [.. Content.Snapshot()];
        }
        if (!TryGetAnchorRect(out var game)) {
            HideOverlay();
            return;
        }
        // tick 是 250ms 一次：内容没变、锚点也没变就不必重画（省 GDI 也避免闪一下）
        var version = Volatile.Read(ref _contentVersion);
        if (_shown && version == _drawnVersion && SameRect(game, _drawnAnchor)) {
            return;
        }
        _drawnAnchor = game;
        _drawnVersion = version;

        var scale = OverlayLayout.ScaleFor(game.Width, game.Height);
        var fontHeight = OverlayLayout.FontHeight(scale);
        if (fontHeight != _fontPx) {
            EnsureFonts(fontHeight);
        }
        // 排版一次算清楚（前缀宽度 + 每段正文的起点），"量窗口宽度"和"画"共用同一份结果。
        // 必须用**真正会用到的那条字体链**去量，否则量到的是默认字体的宽度，
        // 按它算出来的窗口会把真正画出来的字截掉一截。
        var layouts = new LineLayout[lines.Length];
        var textWidth = 0;
        for (var i = 0; i < lines.Length; i++) {
            layouts[i] = LayoutLine(lines[i]);
            textWidth = Math.Max(textWidth, layouts[i].TotalWidth);
        }
        var box = OverlayLayout.Compute(game.Width, game.Height, textWidth, lines.Length);
        if (box.Height == 0 || !EnsureSurface(box.Width, box.Height)) {
            HideOverlay();
            return;
        }

        // —— 画：上下左右各 1px 的深灰投影（近似 BGI 的柔光投影），再正文 ——
        var width = box.Width;
        var height = box.Height;
        var buffer = new Span<byte>((void*) _dibBits, width * height * 4);
        buffer.Clear();
        _ = OverlayNative.SetBkMode(_memDc, OverlayNative.TRANSPARENT);
        var padX = OverlayLayout.PadXFor(scale);
        var padY = OverlayLayout.PadYFor(scale);
        var lineHeight = OverlayLayout.LineHeightFor(scale);
        for (var i = 0; i < lines.Length; i++) {
            DrawLine(lines[i], layouts[i], padX, padY + i * lineHeight);
        }
        OverlayNative.GdiFlush();

        OverlayAlpha.ApplyLuminanceAlpha(buffer, width, height);

        // —— 摆：左上角锚定（比例照 BGI 默认 20/1920、822/1080），行数增加时向下生长 ——
        var x = game.Left + box.Left;
        var y = game.Top + box.Top;
        var dst = new OverlayNative.POINT { X = x, Y = y };
        var size = new OverlayNative.SIZE { cx = width, cy = height };
        var src = new OverlayNative.POINT { X = 0, Y = 0 };
        var blend = new OverlayNative.BLENDFUNCTION {
            BlendOp = OverlayNative.AC_SRC_OVER,
            BlendFlags = 0,
            SourceConstantAlpha = 255,
            AlphaFormat = OverlayNative.AC_SRC_ALPHA,
        };
        if (!OverlayNative.UpdateLayeredWindow(_hwnd, 0, ref dst, ref size, _memDc, ref src, 0, ref blend,
                OverlayNative.ULW_ALPHA)) {
            Log.Warn($"遮罩提交失败（Win32 错误 {Marshal.GetLastWin32Error()}）：{width}x{height}");
            return;
        }
        if (!_shown) {
            _shown = true;
            // HWND_TOP 而不是 HWND_TOPMOST：只保证在游戏窗口之上，不抢全局顶层
            OverlayNative.SetWindowPos(_hwnd, OverlayNative.HWND_TOP, x, y, width, height,
                OverlayNative.SWP_NOACTIVATE | OverlayNative.SWP_SHOWWINDOW);
        }
    }

    private static bool SameRect(in OverlayNative.RECT a, in OverlayNative.RECT b) =>
        a.Left == b.Left && a.Top == b.Top && a.Right == b.Right && a.Bottom == b.Bottom;

    /// <summary>
    /// 某一段正文该用哪条字体链：中文段走中文链，ASCII 段走等宽链。
    ///
    /// 为什么必须分：Cascadia Mono / Consolas / Courier New 都没有 CJK 字形，而 GDI 的
    /// 字体链接（FontLink）取决于注册表 —— 本机 Consolas 就没注册 SystemLink，
    /// 靠它等于把可读性交给运气。这就是 BGI"逐字形回退"
    /// （拉丁 Cascadia Mono + 中文 MiSans）在 GDI 下的等价做法，切段由
    /// <see cref="OverlayLines.SplitRuns"/> 负责。
    /// 中文链也没建起来时退回等宽：至少 ASCII 那半截还能看，总比一片空白强。
    /// </summary>
    private static nint FontOf(in OverlayRun run) =>
        run.Cjk && _fontUi != 0 ? _fontUi : _fontMono;

    /// <summary>
    /// 一行的排版结果：前缀宽度、各段正文及其相对起点、整行宽度。
    /// 重点是"量宽度"和"画"共用同一份结果 —— 否则每段都要重复测量，
    /// 而且两次测量之间只要有一点不一致，画出来的字就会和窗口宽度对不上（右边被切掉）。
    /// </summary>
    private sealed class LineLayout {
        public required int TotalWidth { get; init; }
        public required int PrefixWidth { get; init; }
        public required (OverlayRun Run, int Offset)[] Runs { get; init; }
    }

    private static LineLayout LayoutLine(in OverlayLine line) {
        var prefixWidth = MeasurePrefixWidth(line.Prefix);
        var runs = OverlayLines.SplitRuns(line.Message);
        var placed = new (OverlayRun, int)[runs.Length];
        var x = prefixWidth;
        for (var i = 0; i < runs.Length; i++) {
            placed[i] = (runs[i], x);
            x += MeasureWidth(runs[i].Text, FontOf(runs[i]));
        }
        return new LineLayout { TotalWidth = x, PrefixWidth = prefixWidth, Runs = placed };
    }

    /// <summary>用指定字体量一段文字的像素宽度（量完把 DC 里的字体还原）。</summary>
    private static int MeasureWidth(string text, nint font) {
        if (text.Length == 0 || font == 0) {
            return 0;
        }
        var previous = OverlayNative.SelectObject(_memDc, font);
        var rect = new OverlayNative.RECT();
        OverlayNative.DrawTextW(_memDc, text, text.Length, ref rect,
            OverlayNative.DT_CALCRECT | OverlayNative.DT_SINGLELINE | OverlayNative.DT_NOPREFIX);
        OverlayNative.SelectObject(_memDc, previous);
        return rect.Width;
    }

    /// <summary>
    /// 量前缀宽度，要把**行尾那个空格**算进去 —— 否则正文会紧贴着 `]` 画，看着挤成一团。
    ///
    /// 为什么用"尾部补一个哨兵字符再减掉"这种绕法：`DrawText` 的 DT_CALCRECT 对行尾空白
    /// 的处理跨版本不一致（可能丢掉），直接量 `"[20:46:54 INF] "` 拿到的宽度不一定含那个空格。
    /// 补一个 `|` 顶住行尾之后再减掉 `|` 自身的宽度，两种行为下结果都对。
    /// </summary>
    private static int MeasurePrefixWidth(string prefix) =>
        MeasureWidth(prefix + "|", _fontMono) - MeasureWidth("|", _fontMono);

    /// <summary>
    /// 画一行：前缀用等宽字体、正文各段用各自字体，按 <see cref="LineLayout"/> 里算好的起点依次排。
    /// 投影是四向各 1px 的深灰 —— 每一段都要投影，否则中英交界处会缺一块暗边。
    /// </summary>
    private static void DrawLine(in OverlayLine line, LineLayout layout, int x, int y) {
        foreach (var (dx, dy) in ShadowOffsets) {
            DrawTextAt(line.Prefix, _fontMono, x + dx, y + dy, Style.ShadowColor);
            foreach (var (run, offset) in layout.Runs) {
                DrawTextAt(run.Text, FontOf(run), x + offset + dx, y + dy, Style.ShadowColor);
            }
        }
        DrawTextAt(line.Prefix, _fontMono, x, y, Style.TextColor);
        foreach (var (run, offset) in layout.Runs) {
            DrawTextAt(run.Text, FontOf(run), x + offset, y, Style.TextColor);
        }
    }

    /// <summary>在 (x,y) 用指定字体画一段文字：矩形给足宽度（DT_LEFT 不裁剪），画完还原字体。</summary>
    private static void DrawTextAt(string text, nint font, int x, int y, uint color) {
        if (text.Length == 0 || font == 0) {
            return;
        }
        var previous = OverlayNative.SelectObject(_memDc, font);
        _ = OverlayNative.SetTextColor(_memDc, color);
        var rect = new OverlayNative.RECT { Left = x, Top = y, Right = x + 16 + text.Length * 24, Bottom = y + 128 };
        OverlayNative.DrawTextW(_memDc, text, text.Length, ref rect, DrawFlags());
        OverlayNative.SelectObject(_memDc, previous);
    }

    private static uint DrawFlags() =>
        OverlayNative.DT_LEFT | OverlayNative.DT_SINGLELINE | OverlayNative.DT_NOPREFIX;

    private static void HideOverlay() {
        if (_shown) {
            _shown = false;
            OverlayNative.ShowWindow(_hwnd, OverlayNative.SW_HIDE);
        }
    }

    /// <summary>确保 DIB 存在且尺寸正确（尺寸变了就重建）。</summary>
    private static bool EnsureSurface(int width, int height) {
        if (_dib != 0 && width == _dibWidth && height == _dibHeight) {
            return true;
        }
        if (_dib != 0) {
            OverlayNative.SelectObject(_memDc, 0);
            OverlayNative.DeleteObject(_dib);
            _dib = 0;
            _dibBits = 0;
        }
        var info = new OverlayNative.BITMAPINFO {
            bmiHeader = new OverlayNative.BITMAPINFOHEADER {
                biSize = (uint) Marshal.SizeOf<OverlayNative.BITMAPINFOHEADER>(),
                biWidth = width,
                biHeight = -height,          // 负高度 = 自顶向下，行序与我们的写入一致
                biPlanes = 1,
                biBitCount = 32,
                biCompression = 0,           // BI_RGB
            },
        };
        _dib = OverlayNative.CreateDIBSection(_memDc, in info, OverlayNative.DIB_RGB_COLORS, out _dibBits, 0, 0);
        if (_dib == 0 || _dibBits == 0) {
            Log.Warn("遮罩位图创建失败（GDI 资源不足？）");
            return false;
        }
        OverlayNative.SelectObject(_memDc, _dib);
        _dibWidth = width;
        _dibHeight = height;
        return true;
    }

    private static void EnsureFonts(int fontHeight) {
        if (_fontMono != 0) {
            OverlayNative.DeleteObject(_fontMono);
            _fontMono = 0;
        }
        if (_fontUi != 0) {
            OverlayNative.DeleteObject(_fontUi);
            _fontUi = 0;
        }
        _fontPx = fontHeight;
        _fontMono = CreateFontChecked(fontHeight, Style.MonoChain, out var monoFace);
        _fontUi = CreateFontChecked(fontHeight, Style.CjkChain, out var uiFace);
        Log.Write($"遮罩字体: 等宽前缀={monoFace} 中文正文={uiFace}（字符高度 {fontHeight}px）");
    }

    /// <summary>
    /// 私有加载字体文件（`AddFontResourceExW` + `FR_PRIVATE`）：只对本进程可见，不装进系统。
    ///
    /// 为什么需要它：BGI 的中文用的是它**随包分发的 MiSans**，而 MiSans 在绝大多数机器上
    /// 并没有安装。想让遮罩字形与 BGI 完全一致，最省事的办法就是把那个 ttf 放到 exe 旁边
    /// （或用 `GMK_OVERLAY_FONT_FILE` 指过去），由启动器临时加载 ——
    /// 用户不必去装字体，也不会污染系统字体表、不影响别的程序。
    ///
    /// 加载失败**不算错误**：中文链会自动退到系统雅黑（`CreateFontChecked` 会校验）。
    /// </summary>
    private static void LoadPrivateFont() {
        var path = Style.PrivateFontFile ?? FindDefaultFontFile();
        if (path == null) {
            return;
        }
        if (!File.Exists(path)) {
            Log.Warn($"GMK_OVERLAY_FONT_FILE 指向的字体文件不存在，中文改用系统字体: {path}");
            return;
        }
        var loaded = OverlayNative.AddFontResourceExW(path, OverlayNative.FR_PRIVATE, 0);
        if (loaded <= 0) {
            Log.Warn($"私有加载字体失败（Win32 错误 {Marshal.GetLastWin32Error()}），中文改用系统字体: {path}");
            return;
        }
        Log.Write($"已私有加载字体 {Path.GetFileName(path)}（{loaded} 个字体，未安装到系统）");
    }

    /// <summary>没显式指定字体文件时，按 <see cref="DefaultFontFileNames"/> 找一份（找不到返回 null）。</summary>
    private static string? FindDefaultFontFile() {
        foreach (var candidate in DefaultFontFileNames) {
            if (File.Exists(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    /// <summary>
    /// 按候选链创建字体，并用 `GetTextFaceW` 校验 GDI **真的选中**了它。
    /// 为什么必须校验：缺字体时 GDI 会静默替换（常常换成比例字体），
    /// 不校验就会悄悄失去等宽 —— 密钥那种十六进制串一旦不对齐就没法看。
    /// </summary>
    private static nint CreateFontChecked(int fontHeight, string[] faces, out string usedFace) {
        usedFace = "(失败)";
        char* buffer = stackalloc char[64];      // 循环外分配（放循环里会被 CA2014 判为潜在栈溢出）
        foreach (var face in faces) {
            var font = OverlayNative.CreateFontW(-fontHeight, 0, 0, 0, OverlayNative.FW_NORMAL, 0, 0, 0,
                OverlayNative.DEFAULT_CHARSET, OverlayNative.OUT_TT_PRECIS, OverlayNative.CLIP_DEFAULT_PRECIS,
                OverlayNative.ANTIALIASED_QUALITY, OverlayNative.FF_MODERN, face);
            if (font == 0) {
                continue;
            }
            var previous = OverlayNative.SelectObject(_memDc, font);
            var count = OverlayNative.GetTextFaceW(_memDc, 64, buffer);
            OverlayNative.SelectObject(_memDc, previous);
            var actual = count > 1 ? new string(buffer, 0, count - 1) : "";
            if (actual.Equals(face, StringComparison.OrdinalIgnoreCase)) {
                usedFace = actual;
                return font;
            }
            OverlayNative.DeleteObject(font);   // GDI 换成了别的字体 → 这个不算命中，试下一个
        }
        return 0;
    }

    private static void CleanupGdi() {
        if (_fontMono != 0) {
            OverlayNative.DeleteObject(_fontMono);
            _fontMono = 0;
        }
        if (_fontUi != 0) {
            OverlayNative.DeleteObject(_fontUi);
            _fontUi = 0;
        }
        if (_dib != 0) {
            OverlayNative.SelectObject(_memDc, 0);
            OverlayNative.DeleteObject(_dib);
            _dib = 0;
            _dibBits = 0;
        }
        if (_memDc != 0) {
            OverlayNative.DeleteDC(_memDc);
            _memDc = 0;
        }
    }
}
