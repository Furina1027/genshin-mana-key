using System.ComponentModel;
using Windows.Win32;
using Windows.Win32.Foundation;
using static Windows.Win32.System.Threading.PROCESS_ACCESS_RIGHTS;

// ReSharper disable CheckNamespace

namespace System.Diagnostics;

[EditorBrowsable(EditorBrowsableState.Never)]
internal static class ProcessExtensions {

    public static unsafe string? GetFileName(this Process process) {
        using var hProc = Native.OpenProcess_SafeHandle(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint) process.Id);
        if (hProc.IsInvalid) {
            return null;
        }
        var sProcPath = stackalloc char[32767];
        return Native.GetModuleFileNameEx((HANDLE) hProc.DangerousGetHandle(), HMODULE.Null, sProcPath, 32767) == 0
            ? null
            : new string(sProcPath);
    }

}
