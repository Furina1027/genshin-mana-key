using System.Runtime.InteropServices;

namespace GenshinSniffer;

/// <summary>
/// 遮罩窗口用到的 Win32 接口。
///
/// 为什么手写 <c>[LibraryImport]</c> 而不是继续用 CsWin32：这里用到的是"GDI 画布 + 分层窗口合成"
/// （CreateDIBSection / UpdateLayeredWindow / DrawTextW）这套冷门 API，CsWin32 生成的友好重载
/// 在它们上面形状不一，手写能保证 ABI 精确、且 NativeAOT 下零反射。项目里已有的 CsWin32 用法
/// （进程/线程/内存操作）原样不动。
///
/// 命名与常量都按 Win32 原名，便于对照文档；只声明实际用到的那些。
/// </summary>
internal static unsafe partial class OverlayNative {

    // ==================== 窗口样式与消息 ====================

    public const uint WS_POPUP = 0x80000000;
    public const uint WS_EX_LAYERED = 0x00080000;
    public const uint WS_EX_TRANSPARENT = 0x00000020;   // 鼠标穿透
    public const uint WS_EX_TOPMOST = 0x00000008;
    public const uint WS_EX_NOACTIVATE = 0x08000000;    // 不抢焦点
    public const uint WS_EX_TOOLWINDOW = 0x00000080;    // 不进 Alt+Tab

    public const int SW_HIDE = 0;
    public const int SW_SHOWNOACTIVATE = 4;

    public static readonly nint HWND_TOPMOST = -1;
    public static readonly nint HWND_NOTOPMOST = -2;
    public static readonly nint HWND_TOP = 0;
    /// <summary>SetWindowLongPtrW 的索引：设置顶层窗口的 owner。</summary>
    public const int GWLP_HWNDPARENT = -8;
    public const uint SWP_NOSIZE = 0x0001;
    public const uint SWP_NOACTIVATE = 0x0010;
    public const uint SWP_SHOWWINDOW = 0x0040;

    public const uint WM_DESTROY = 0x0002;
    public const uint WM_CLOSE = 0x0010;
    public const uint WM_TIMER = 0x0113;
    public const uint WM_NCHITTEST = 0x0084;
    public static readonly nint HTTRANSPARENT = -1;

    /// <summary>自定义消息：有新内容要重绘（跨线程只传这个，不直接碰窗口）。</summary>
    public const uint WM_OVERLAY_UPDATE = 0x8001;       // WM_APP + 1

    /// <summary>自定义消息：游戏已退出，结束消息循环。</summary>
    public const uint WM_OVERLAY_GAME_EXIT = 0x8002;    // WM_APP + 2

    // ==================== GDI ====================

    public const int TRANSPARENT = 1;
    public const uint DT_LEFT = 0x0000;
    public const uint DT_SINGLELINE = 0x0020;
    public const uint DT_NOPREFIX = 0x0800;
    public const uint DT_CALCRECT = 0x0400;
    public const uint DIB_RGB_COLORS = 0;
    public const uint ULW_ALPHA = 0x00000002;
    public const byte AC_SRC_OVER = 0;
    public const byte AC_SRC_ALPHA = 1;
    public const int FW_NORMAL = 400;
    public const int FW_SEMIBOLD = 600;
    /// <summary>灰度抗锯齿（不用 ClearType，否则边缘会有彩色条纹，见 OverlayAlpha 的注释）。</summary>
    public const uint ANTIALIASED_QUALITY = 4;
    public const uint DEFAULT_CHARSET = 1;
    public const uint OUT_TT_PRECIS = 4;
    public const uint CLIP_DEFAULT_PRECIS = 0;
    public const uint FF_MODERN = 0x30;

    public const uint GW_OWNER = 4;
    public const int SM_CXSCREEN = 0;
    public const int SM_CYSCREEN = 1;

    // ==================== 结构 ====================

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {
        public int Left, Top, Right, Bottom;

        public readonly int Width => Right - Left;
        public readonly int Height => Bottom - Top;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct POINT {
        public int X, Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SIZE {
        public int cx, cy;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct BLENDFUNCTION {
        public byte BlendOp, BlendFlags, SourceConstantAlpha, AlphaFormat;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BITMAPINFOHEADER {
        public uint biSize;
        public int biWidth, biHeight;
        public ushort biPlanes, biBitCount;
        public uint biCompression, biSizeImage;
        public int biXPelsPerMeter, biYPelsPerMeter;
        public uint biClrUsed, biClrImportant;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BITMAPINFO {
        public BITMAPINFOHEADER bmiHeader;
        public uint bmiColors;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG {
        public nint hwnd;
        public uint message;
        public nint wParam, lParam;
        public uint time;
        public POINT pt;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WNDCLASSW {
        public uint style;
        public nint lpfnWndProc;
        public int cbClsExtra, cbWndExtra;
        public nint hInstance, hIcon, hCursor, hbrBackground, lpszMenuName, lpszClassName;
    }

    // ==================== user32 ====================

    [LibraryImport("user32.dll", EntryPoint = "RegisterClassW", SetLastError = true)]
    public static partial ushort RegisterClassW(in WNDCLASSW lpWndClass);

    [LibraryImport("user32.dll", EntryPoint = "CreateWindowExW", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    public static partial nint CreateWindowExW(uint dwExStyle, string lpClassName, string lpWindowName,
        uint dwStyle, int x, int y, int nWidth, int nHeight,
        nint hWndParent, nint hMenu, nint hInstance, nint lpParam);

    [LibraryImport("user32.dll", EntryPoint = "DefWindowProcW")]
    public static partial nint DefWindowProcW(nint hWnd, uint msg, nint wParam, nint lParam);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DestroyWindow(nint hWnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool ShowWindow(nint hWnd, int nCmdShow);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetWindowPos(nint hWnd, nint hWndInsertAfter, int x, int y, int cx, int cy, uint flags);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetWindowRect(nint hWnd, out RECT lpRect);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool EnumWindows(nint lpEnumFunc, nint lParam);

    [LibraryImport("user32.dll")]
    public static partial uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);

    [LibraryImport("user32.dll")]
    public static partial nint GetForegroundWindow();

    /// <summary>设置/读取窗口的 owner（GWLP_HWNDPARENT）——用来把遮罩挂到游戏窗口名下。</summary>
    [LibraryImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    public static partial nint SetWindowLongPtrW(nint hWnd, int nIndex, nint dwNewLong);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsWindowVisible(nint hWnd);

    [LibraryImport("user32.dll")]
    public static partial nint GetWindow(nint hWnd, uint uCmd);

    [LibraryImport("user32.dll", SetLastError = true)]
    public static partial nuint SetTimer(nint hWnd, nuint nIDEvent, uint uElapse, nint lpTimerFunc);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool KillTimer(nint hWnd, nuint uIDEvent);

    [LibraryImport("user32.dll", EntryPoint = "PostMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PostMessageW(nint hWnd, uint msg, nint wParam, nint lParam);

    [LibraryImport("user32.dll", EntryPoint = "GetMessageW")]
    public static partial int GetMessageW(out MSG lpMsg, nint hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool TranslateMessage(in MSG lpMsg);

    [LibraryImport("user32.dll", EntryPoint = "DispatchMessageW")]
    public static partial nint DispatchMessageW(in MSG lpMsg);

    [LibraryImport("user32.dll")]
    public static partial void PostQuitMessage(int nExitCode);

    [LibraryImport("user32.dll", EntryPoint = "MessageBoxW", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int MessageBoxW(nint hWnd, string lpText, string lpCaption, uint uType);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool UpdateLayeredWindow(nint hWnd, nint hdcDst, ref POINT pptDst, ref SIZE psize,
        nint hdcSrc, ref POINT pptSrc, uint crKey, ref BLENDFUNCTION pblend, uint dwFlags);

    /// <summary>GetConsoleWindow 在 **kernel32.dll**（不是 user32）。</summary>
    [LibraryImport("kernel32.dll")]
    public static partial nint GetConsoleWindow();

    [LibraryImport("user32.dll")]
    public static partial int GetSystemMetrics(int nIndex);

    // ==================== gdi32 ====================

    [LibraryImport("gdi32.dll")]
    public static partial nint CreateCompatibleDC(nint hdc);

    [LibraryImport("gdi32.dll")]
    public static partial nint CreateDIBSection(nint hdc, in BITMAPINFO pbmi, uint usage,
        out nint ppvBits, nint hSection, uint offset);

    [LibraryImport("gdi32.dll")]
    public static partial nint SelectObject(nint hdc, nint h);

    [LibraryImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DeleteObject(nint ho);

    [LibraryImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DeleteDC(nint hdc);

    [LibraryImport("gdi32.dll")]
    public static partial int SetBkMode(nint hdc, int mode);

    [LibraryImport("gdi32.dll")]
    public static partial uint SetTextColor(nint hdc, uint color);

    /// <summary>注意：DrawTextW 在 **user32.dll**，不在 gdi32（冒烟测试当场抓到过一次）。</summary>
    [LibraryImport("user32.dll", EntryPoint = "DrawTextW", StringMarshalling = StringMarshalling.Utf16)]
    public static partial int DrawTextW(nint hdc, string lpchText, int cchText, ref RECT lprc, uint format);

    [LibraryImport("gdi32.dll", EntryPoint = "CreateFontW", StringMarshalling = StringMarshalling.Utf16)]
    public static partial nint CreateFontW(int cHeight, int cWidth, int cEscapement, int cOrientation,
        int cWeight, uint bItalic, uint bUnderline, uint bStrikeOut, uint iCharSet,
        uint iOutPrecision, uint iClipPrecision, uint iQuality, uint iPitchAndFamily, string pszFaceName);

    /// <summary>读出 DC 里**实际选中**的字体名（用来校验 GDI 没有静默替换成别的字体）。</summary>
    [LibraryImport("gdi32.dll", EntryPoint = "GetTextFaceW")]
    public static partial int GetTextFaceW(nint hdc, int c, char* lpFaceName);

    /// <summary>
    /// 把一个字体文件加载给**本进程**用（配合 <see cref="FR_PRIVATE"/>）：
    /// 不用装进系统字体表、不影响别的程序、进程退出即失效。返回值是加载成功的字体数（0 = 失败）。
    /// 这是"想让遮罩用上和 BetterGI 一模一样的 MiSans，又不想让用户去装字体"的正解。
    /// </summary>
    [LibraryImport("gdi32.dll", EntryPoint = "AddFontResourceExW", StringMarshalling = StringMarshalling.Utf16,
        SetLastError = true)]
    public static partial int AddFontResourceExW(string lpszFilename, uint fl, nint pdv);

    /// <summary>`AddFontResourceExW` 的 FR_PRIVATE：只对本进程可见。</summary>
    public const uint FR_PRIVATE = 0x10;

    [LibraryImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GdiFlush();

    // ==================== kernel32 ====================

    /// <summary>给 GUI 子系统进程按需分配一个控制台（GMK_CONSOLE=1 排障用）。</summary>
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool AllocConsole();

    [LibraryImport("kernel32.dll", EntryPoint = "GetModuleHandleW")]
    public static partial nint GetModuleHandleW(nint lpModuleName);
}
