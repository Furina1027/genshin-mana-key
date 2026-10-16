using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Diagnostics.ToolHelp;
using Windows.Win32.System.LibraryLoader;
using Windows.Win32.System.Threading;
using static Windows.Win32.System.Memory.VIRTUAL_ALLOCATION_TYPE;
using static Windows.Win32.System.Memory.PAGE_PROTECTION_FLAGS;
using static Windows.Win32.System.Memory.VIRTUAL_FREE_TYPE;

namespace GenshinSniffer.Utilities;

/// <summary>
/// 以挂起方式创建游戏进程（反作弊加载前抢到全权限句柄），注入 DLL 后恢复主线程。
/// 自 YaeAchievement（GPL-3.0）。
/// </summary>
internal sealed unsafe class GameProcess {

    /// <summary>ERROR_BAD_LENGTH：取快照的过程中目标模块列表变了，重取一次即可。</summary>
    private const uint ErrorBadLength = 24;

    /// <summary>等待远程 LoadLibraryW 返回的上限（毫秒）。</summary>
    private const uint RemoteLoadTimeoutMs = 2000;

    public uint Id { get; }

    public HANDLE Handle { get; }

    public HANDLE MainThreadHandle { get; }

    public event Action? OnExit;

    public uint ExitCode { get; private set; }

    /// <summary>最近一次注入失败的原因；LoadLibrary 返回 false 时由 Main 统一打印（库不自己退出进程）。</summary>
    public Exception? LastInjectionError { get; private set; }

    public GameProcess(string path) {
        const PROCESS_CREATION_FLAGS flags = PROCESS_CREATION_FLAGS.CREATE_SUSPENDED;
        Span<char> cmdLines = stackalloc char[1]; // "\0"
        var si = new STARTUPINFOW {
            cb = (uint) sizeof(STARTUPINFOW)
        };
        var wd = Path.GetDirectoryName(path)!;
        if (!Native.CreateProcess(path, ref cmdLines, null, null, false, flags, null, wd, si, out var pi)) {
            throw Win32Error("CreateProcess");
        }
        Id = pi.dwProcessId;
        Handle = pi.hProcess;
        MainThreadHandle = pi.hThread;
        // 退出监视线程在这里就起，但订阅（OnExit += ...）由 Main 在做注入**之前**完成：
        // 注入要花时间（远程线程 + 模块枚举），这段窗口里游戏若崩掉，晚订阅就永远收不到退出事件。
        Task.Run(() => {
            using var safeHandle = new SafeFileHandle(Handle, ownsHandle: false);
            Native.WaitForSingleObject(safeHandle, 0xFFFFFFFF); // INFINITE
            Native.GetExitCodeProcess(safeHandle, out var exitCode);
            ExitCode = exitCode;
            try {
                OnExit?.Invoke();
            } catch (Exception e) {
                // 回调是启动器自己的代码，但这里绝不能把异常抛回未观察的 Task（会静默变成 UnobservedTaskException）
                Log.Write($"OnExit 处理异常（已忽略）：{e.Message}");
            }
        });
    }

    /// <summary>
    /// 注入：在目标进程里 LoadLibraryW(注入 DLL)，再按导出 YaeMain 的 RVA 起远程线程。
    /// 失败返回 false 并把原因放进 <see cref="LastInjectionError"/> ——
    /// 旧实现在失败路径上直接 Environment.Exit(-1)：库带进程级副作用，既没法测试也没法复用，
    /// 退出码与提示统一交给 Main。
    /// </summary>
    public bool LoadLibrary(string libPath) {
        try {
            var hKrnl32 = NativeLibrary.Load("kernel32");
            var mLoadLibraryW = NativeLibrary.GetExport(hKrnl32, "LoadLibraryW");
            // 显式写满 libPathLen + 2 字节（UTF-16 的 \0 终止符也在内）：
            // 旧实现申请 +2 却只写 libPathLen 字节，靠"新分配的页必定是 0"兜底 —— 那是侥幸正确，
            // 一旦目标进程那块内存不干净，远程 LoadLibraryW 就会读到一条没有终止符的路径。
            var pathBytes = new byte[(libPath.Length * sizeof(char)) + sizeof(char)];
            Encoding.Unicode.GetBytes(libPath, 0, libPath.Length, pathBytes, 0); // 末尾两字节保持 0 = \0
            var lpLibPath = Native.VirtualAllocEx(Handle, null, (nuint) pathBytes.Length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (lpLibPath == null) {
                throw Win32Error("VirtualAllocEx");
            }
            var hThread = default(HANDLE);
            try {
                fixed (byte* lpBuffer = pathBytes) {
                    if (!Native.WriteProcessMemory(Handle, lpLibPath, lpBuffer, (nuint) pathBytes.Length)) {
                        throw Win32Error("WriteProcessMemory");
                    }
                }
                var lpStartAddress = (delegate* unmanaged[Stdcall]<void*, uint>) mLoadLibraryW; // THREAD_START_ROUTINE
                hThread = Native.CreateRemoteThread(Handle, null, 0, lpStartAddress, lpLibPath, 0);
                if (hThread.IsNull) {
                    throw Win32Error("CreateRemoteThread");
                }
                if (Native.WaitForSingleObject(hThread, RemoteLoadTimeoutMs) != WAIT_EVENT.WAIT_OBJECT_0) {
                    Log.Write($"等待远程 LoadLibraryW 超过 {RemoteLoadTimeoutMs} ms，继续按已加载处理。");
                }
            } finally {
                // 无论成功、超时还是抛异常都在这里回收：旧实现只在 wait 成功时才 VirtualFreeEx，
                // 超时路径既漏远程参数内存又漏线程句柄。
                Native.VirtualFreeEx(Handle, lpLibPath, 0, MEM_RELEASE);
                if (!hThread.IsNull) {
                    Native.CloseHandle(hThread);
                }
            }
            // 按模块文件名找基址（szModule 比被规范化过的 szExePath 稳），顺带复核"注入确实生效"
            var moduleBase = FindModuleBase(this, Path.GetFileName(libPath));
            if (moduleBase == 0) {
                throw new InvalidOperationException($"目标进程中找不到模块 {Path.GetFileName(libPath)}（注入未生效）。");
            }
            Log.Write($"DLL 已加载，base=0x{moduleBase:X}");
            var baseAddress = (byte*) moduleBase;
            // 本地以 DONT_RESOLVE_DLL_REFERENCES 映射同一份 DLL，用「导出地址 - 本地基址」得到 YaeMain 的 RVA
            using var libHandle = Native.LoadLibraryEx(libPath, LOAD_LIBRARY_FLAGS.DONT_RESOLVE_DLL_REFERENCES);
            if (libHandle.IsInvalid) {
                throw Win32Error("LoadLibraryEx");
            }
            var libMainProc = Native.GetProcAddress(libHandle, "YaeMain");
            if (libMainProc.IsNull) {
                throw Win32Error("GetProcAddress(YaeMain)");
            }
            var libMainProcRva = libMainProc.Value - libHandle.DangerousGetHandle();
            var lpStartAddress2 = (delegate* unmanaged[Stdcall]<void*, uint>) (baseAddress + libMainProcRva); // THREAD_START_ROUTINE
            var hThread2 = Native.CreateRemoteThread(Handle, null, 0, lpStartAddress2, null, 0);
            if (hThread2.IsNull) {
                throw Win32Error("CreateRemoteThread(YaeMain)");
            }
            Native.CloseHandle(hThread2);
            Log.Write("YaeMain 线程已创建。");
            return true;
        } catch (Exception e) when (e is Win32Exception or InvalidOperationException or IOException
                                        or DllNotFoundException or EntryPointNotFoundException) {
            LastInjectionError = e;
            return false;
        }
    }

    public bool ResumeMainThread() => Native.ResumeThread(MainThreadHandle) != 0xFFFFFFFF;

    public bool Terminate(uint exitCode) => Native.TerminateProcess(Handle, exitCode);

    /// <summary>
    /// 在目标进程中按模块名查基址（GetModuleHandle 在游戏进程里被反作弊屏蔽，所以由启动器用模块快照查）。
    ///
    /// 为什么优先比 szModule：szExePath 会被系统规范化（大小写、8.3 短名、分隔符），
    /// 拿它跟传进来的 libPath 做**大小写敏感**的 == 比较，正是以前报 "No matching module found" 的原因。
    /// 返回 0 = 没找到；Main 也用它复核注入结果，不单信"注入函数自己说成功"。
    /// </summary>
    public static ulong FindModuleBase(GameProcess proc, string moduleName) {
        var wantFileName = Path.GetFileName(moduleName);
        using var hSnap = OpenModuleSnapshot(proc.Id);
        if (hSnap == null) {
            return 0;
        }
        var moduleEntry = new MODULEENTRY32 {
            dwSize = (uint) sizeof(MODULEENTRY32)
        };
        if (!Native.Module32First(hSnap, ref moduleEntry)) {
            return 0;
        }
        do {
            if (string.Equals(ReadAnsiString(moduleEntry.szModule.AsReadOnlySpan()), wantFileName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(ReadAnsiString(moduleEntry.szExePath.AsReadOnlySpan()), moduleName, StringComparison.OrdinalIgnoreCase)) {
                return (ulong) moduleEntry.modBaseAddr;
            }
        } while (Native.Module32Next(hSnap, ref moduleEntry));
        return 0;
    }

    /// <summary>
    /// 打开模块快照。ERROR_BAD_LENGTH(24) 说明枚举期间模块列表变了 → 重取；
    /// 失败（Invalid）的句柄也要立刻 Dispose（SafeHandle 约定），否则 CA2000/句柄泄漏。
    /// </summary>
    private static SafeFileHandle? OpenModuleSnapshot(uint processId) {
        for (var attempt = 0; attempt < 16; attempt++) {
            var hSnap = Native.CreateToolhelp32Snapshot_SafeHandle(CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE, processId);
            if (!hSnap.IsInvalid) {
                return hSnap;
            }
            var error = Marshal.GetLastPInvokeError();
            hSnap.Dispose();
            if (error != ErrorBadLength) {
                return null;
            }
        }
        return null;
    }

    /// <summary>
    /// MODULEENTRY32 是 ANSI 结构（CHAR 数组）。模块文件名是 ASCII，用 Latin1「一字节一字符」转换最确定；
    /// 走 Encoding.Default 会随机器 ACP 变化（GBK / UTF-8 不等），反而更容易误判。
    /// </summary>
    private static string ReadAnsiString(ReadOnlySpan<CHAR> buffer) {
        var length = 0;
        while (length < buffer.Length && buffer[length].Value != 0) {
            length++;
        }
        var chars = new char[length];
        for (var i = 0; i < length; i++) {
            chars[i] = (char) (byte) buffer[i].Value;
        }
        return new string(chars);
    }

    /// <summary>
    /// 构造带 Win32 错误码的异常，并把 API 名放进 Data["api"]。
    /// 必须在 API 返回失败后**立刻**调用：GetLastPInvokeError 读的是本线程"最后一次 P/Invoke 的错误"，
    /// 中间再插别的 P/Invoke 就会读到别的错误码。
    /// （旧写法 new Win32Exception { Data = ... } 走的是无参构造 → Message 是空串，错误信息全丢。）
    /// </summary>
    private static Win32Exception Win32Error(string api) {
        var error = new Win32Exception(Marshal.GetLastPInvokeError());
        error.Data["api"] = api;
        return error;
    }

}
