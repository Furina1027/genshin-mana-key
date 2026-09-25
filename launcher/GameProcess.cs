using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
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

    public uint Id { get; }

    public HANDLE Handle { get; }

    public HANDLE MainThreadHandle { get; }

    public event Action? OnExit;

    public GameProcess(string path) {
        const PROCESS_CREATION_FLAGS flags = PROCESS_CREATION_FLAGS.CREATE_SUSPENDED;
        Span<char> cmdLines = stackalloc char[1]; // "\0"
        var si = new STARTUPINFOW {
            cb = (uint) sizeof(STARTUPINFOW)
        };
        var wd = Path.GetDirectoryName(path)!;
        if (!Native.CreateProcess(path, ref cmdLines, null, null, false, flags, null, wd, si, out var pi)) {
            throw new ApplicationException($"CreateProcess fail: {Marshal.GetLastPInvokeErrorMessage()}");
        }
        Id = pi.dwProcessId;
        Handle = pi.hProcess;
        MainThreadHandle = pi.hThread;
        Task.Run(() => {
            using var safeHandle = new SafeFileHandle(Handle, ownsHandle: false);
            Native.WaitForSingleObject(safeHandle, 0xFFFFFFFF); // INFINITE
            Native.GetExitCodeProcess(safeHandle, out var exitCode);
            ExitCode = exitCode;
            OnExit?.Invoke();
        });
    }

    public uint ExitCode { get; private set; }

    public void LoadLibrary(string libPath) {
        try {
            var hKrnl32 = NativeLibrary.Load("kernel32");
            var mLoadLibraryW = NativeLibrary.GetExport(hKrnl32, "LoadLibraryW");
            var libPathLen = (uint) libPath.Length * sizeof(char);
            var lpLibPath = Native.VirtualAllocEx(Handle, null, libPathLen + 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (lpLibPath == null) {
                throw new Win32Exception { Data = { { "api", "VirtualAllocEx" } } };
            }
            fixed (void* lpBuffer = libPath) {
                if (!Native.WriteProcessMemory(Handle, lpLibPath, lpBuffer, libPathLen)) {
                    throw new Win32Exception { Data = { { "api", "WriteProcessMemory" } } };
                }
            }
            var lpStartAddress = (delegate* unmanaged[Stdcall]<void*, uint>) mLoadLibraryW; // THREAD_START_ROUTINE
            var hThread = Native.CreateRemoteThread(Handle, null, 0, lpStartAddress, lpLibPath, 0);
            if (hThread.IsNull) {
                throw new Win32Exception { Data = { { "api", "CreateRemoteThread" } } };
            }
            if (Native.WaitForSingleObject(hThread, 2000) == 0) {
                Native.VirtualFreeEx(Handle, lpLibPath, 0, MEM_RELEASE);
            }
            // Get lib base address in target process
            byte* baseAddress = null;
            SafeFileHandle hSnap;
            do {
                hSnap = Native.CreateToolhelp32Snapshot_SafeHandle(CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE, Id);
                if (Marshal.GetLastSystemError() is not (0 or 24)) { // ERROR_BAD_LENGTH
                    break;
                }
            } while (hSnap.IsInvalid);
            if (hSnap.IsInvalid) {
                throw new Win32Exception { Data = { { "api", "CreateToolhelp32Snapshot" } } };
            }
            using (hSnap) {
                var moduleEntry = new MODULEENTRY32 {
                    dwSize = (uint) sizeof(MODULEENTRY32)
                };
                if (Native.Module32First(hSnap, ref moduleEntry)) {
                    do {
                        if (new string((sbyte*) &moduleEntry.szExePath._0) == libPath) {
                            baseAddress = moduleEntry.modBaseAddr;
                            break;
                        }
                    } while (Native.Module32Next(hSnap, ref moduleEntry));
                }
            }
            if (baseAddress == null) {
                throw new InvalidOperationException("No matching module found in target process.");
            }
            Log.Write($"DLL 已加载，base={((nint) baseAddress):X}");
            //
            using var libHandle = Native.LoadLibraryEx(libPath, LOAD_LIBRARY_FLAGS.DONT_RESOLVE_DLL_REFERENCES);
            if (libHandle.IsInvalid) {
                throw new Win32Exception { Data = { { "api", "LoadLibraryEx" } } };
            }
            var libMainProc = Native.GetProcAddress(libHandle, "YaeMain");
            if (libMainProc.IsNull) {
                throw new Win32Exception { Data = { { "api", "GetProcAddress" } } };
            }
            var libMainProcRVA = libMainProc.Value - libHandle.DangerousGetHandle();
            var lpStartAddress2 = (delegate* unmanaged[Stdcall]<void*, uint>) (baseAddress + libMainProcRVA); // THREAD_START_ROUTINE
            //
            var hThread2 = Native.CreateRemoteThread(Handle, null, 0, lpStartAddress2, null, 0);
            if (hThread2.IsNull) {
                throw new Win32Exception { Data = { { "api", "CreateRemoteThread2" } } };
            }
            Log.Write("YaeMain 线程已创建。");
            Native.CloseHandle(hThread2);
            Native.CloseHandle(hThread);
        } catch (Win32Exception e) {
            _ = Terminate(0);
            Console.WriteLine($"注入失败 ({e.Data["api"]}): {e.Message}");
            Environment.Exit(-1);
        }
    }

    public bool ResumeMainThread() => Native.ResumeThread(MainThreadHandle) != 0xFFFFFFFF;

    public bool Terminate(uint exitCode) => Native.TerminateProcess(Handle, exitCode);

    /// <summary>
    /// 在目标进程中按模块名查基址（GetModuleHandle 在游戏进程里被反作弊屏蔽，
    /// 所以由启动器用模块快照查）。
    /// </summary>
    public static ulong FindModuleBase(GameProcess proc, string moduleName) {
        SafeFileHandle hSnap;
        do {
            hSnap = Native.CreateToolhelp32Snapshot_SafeHandle(CREATE_TOOLHELP_SNAPSHOT_FLAGS.TH32CS_SNAPMODULE, proc.Id);
            if (Marshal.GetLastSystemError() is not (0 or 24)) {
                break;
            }
        } while (hSnap.IsInvalid);
        if (hSnap.IsInvalid) {
            return 0;
        }
        using (hSnap) {
            var moduleEntry = new MODULEENTRY32 {
                dwSize = (uint) sizeof(MODULEENTRY32)
            };
            if (Native.Module32First(hSnap, ref moduleEntry)) {
                do {
                    if (new string((sbyte*) &moduleEntry.szModule._0) == moduleName) {
                        return (ulong) moduleEntry.modBaseAddr;
                    }
                } while (Native.Module32Next(hSnap, ref moduleEntry));
            }
        }
        return 0;
    }

}
