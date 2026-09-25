using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace GenshinSniffer.Utilities;

internal static unsafe partial class Native {

    #region GetModuleHandle

    [LibraryImport("KERNEL32.dll", EntryPoint = "GetModuleHandleW")]
    private static partial nint GetModuleHandleW(char* moduleName);

    private static nint GetModuleHandleWByName(string moduleName) {
        fixed (char* pName = moduleName) {
            return GetModuleHandleW(pName);
        }
    }

    #endregion

    #region PEB module walk

    [LibraryImport("NTDLL.dll", EntryPoint = "RtlGetCurrentPeb")]
    private static partial nint RtlGetCurrentPeb();

    /// <summary>
    /// 找 GameAssembly.dll 基址。优先 GetModuleHandle（游戏进程内名字查找
    /// 实测被反作弊屏蔽返回 0），回退到手动遍历 PEB 的 InLoadOrder 模块链表。
    /// </summary>
    public static nint FindGameAssemblyBase() {
        var byName = GetModuleHandleWByName("GameAssembly.dll");
        if (byName != 0) {
            return byName;
        }
        var peb = RtlGetCurrentPeb();
        if (peb == 0) {
            return 0;
        }
        var ldr = *(nint*) (peb + 0x18);
        var head = ldr + 0x10; // InLoadOrderModuleList
        var entry = *(nint*) head;
        var guard = 0;
        while (entry != head && entry != 0 && guard++ < 512) {
            var dllBase = *(nint*) (entry + 0x30);
            var nameLen = *(ushort*) (entry + 0x68);      // BaseDllName.Length
            var nameBuf = *(nint*) (entry + 0x70);        // BaseDllName.Buffer
            if (nameLen == 0x20 && nameBuf != 0 && CompareName(nameBuf, "GameAssembly.dll")) {
                return dllBase;
            }
            entry = *(nint*) entry;
        }
        return 0;
    }

    private static bool CompareName(nint buffer, string name) {
        for (var i = 0; i < name.Length; i++) {
            var c = *(char*) (buffer + i * 2);
            // 大小写不敏感：主模块名在 PEB 里的大小写不保证与原文件名一致
            if (c != name[i] && char.ToLowerInvariant(c) != char.ToLowerInvariant(name[i])) {
                return false;
            }
        }
        return true;
    }

    /// <summary>按名查找任意已加载模块（PEB 遍历）</summary>
    public static nint FindModuleBase(string moduleName) {
        var byName = GetModuleHandleWByName(moduleName);
        if (byName != 0) {
            return byName;
        }
        var peb = RtlGetCurrentPeb();
        if (peb == 0) {
            return 0;
        }
        var ldr = *(nint*) (peb + 0x18);
        var head = ldr + 0x10;
        var entry = *(nint*) head;
        var guard = 0;
        while (entry != head && entry != 0 && guard++ < 512) {
            var dllBase = *(nint*) (entry + 0x30);
            var nameLen = *(ushort*) (entry + 0x68);
            var nameBuf = *(nint*) (entry + 0x70);
            if (nameBuf != 0 && nameLen == moduleName.Length * 2 && CompareName(nameBuf, moduleName)) {
                return dllBase;
            }
            entry = *(nint*) entry;
        }
        return 0;
    }

    #endregion

    #region Export resolution

    /// <summary>内存中解析模块导出（ANSI 名比较）</summary>
    public static nint GetExportAddress(nint module, string export) {
        if (module == 0) {
            return 0;
        }
        var dos = *(ushort*) module;
        if (dos != 0x5A4D) {
            return 0;
        }
        var eLfanew = *(int*) (module + 0x3C);
        var nt = module + eLfanew;
        if (*(uint*) nt != 0x4550) {
            return 0;
        }
        var opt = nt + 0x18;
        var magic = *(ushort*) opt;
        // DataDirectories[0] = Export Directory: PE32+ 在 opt+0x70, PE32 在 opt+0x60
        var exportDirRva = magic == 0x20B ? *(uint*) (opt + 0x70) : *(uint*) (opt + 0x60);
        if (exportDirRva == 0) {
            return 0;
        }
        // RVA->文件偏移（内存映像中 RVA==偏移，无需转换）
        var dir = module + exportDirRva;
        var numberOfNames = *(int*) (dir + 0x18);
        var addrFuncs = module + *(int*) (dir + 0x1C);
        var addrNames = module + *(int*) (dir + 0x20);
        var addrOrds = module + *(int*) (dir + 0x24);
        for (var i = 0; i < numberOfNames; i++) {
            // 名称表/地址表条目都是 4 字节 RVA（v4 曾按 8 字节指针读 → 读出野指针 → AV，侦察线程当场死掉）
            var nameRva = *(uint*) (addrNames + i * 4);
            if (nameRva == 0) {
                continue;
            }
            if (AsciiEquals(module + (nint) nameRva, export)) {
                var ord = *(ushort*) (addrOrds + i * 2);
                var funcRva = *(uint*) (addrFuncs + ord * 4);
                return module + (nint) funcRva;
            }
        }
        return 0;
    }

    private static bool AsciiEquals(nint ptr, string s) {
        for (var i = 0; i < s.Length; i++) {
            if (*(byte*) (ptr + i) != (byte) s[i]) {
                return false;
            }
        }
        return *(byte*) (ptr + s.Length) == 0;
    }

    #endregion

    #region 安全内存读取（扫对象字段时必须先验证，否则野指针会带走游戏进程）

    [LibraryImport("KERNEL32.dll", EntryPoint = "VirtualQuery")]
    private static partial nuint VirtualQuery(void* lpAddress, void* lpBuffer, nuint dwLength);

    private const uint MEM_COMMIT = 0x1000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_WRITECOPY = 0x08;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint PAGE_GUARD = 0x100;

    /// <summary>地址区间是否已提交且可读（PAGE_GUARD / PAGE_NOACCESS 一律判不可读）。</summary>
    public static bool IsReadable(nint addr, int size) {
        if (addr == 0 || size <= 0) {
            return false;
        }
        // MEMORY_BASIC_INFORMATION (x64): RegionSize @+0x18, State @+0x20, Protect @+0x24
        byte* pMbi = stackalloc byte[48];
        var cur = addr;
        var remain = size;
        var guard = 0;
        while (remain > 0 && guard++ < 64) {
            for (var i = 0; i < 48; i++) {
                pMbi[i] = 0;
            }
            if (VirtualQuery((void*) cur, pMbi, 48) == 0) {
                return false;
            }
            var regionSize = *(nuint*) (pMbi + 0x18);
            var state = *(uint*) (pMbi + 0x20);
            var protect = *(uint*) (pMbi + 0x24);
            if (state != MEM_COMMIT || (protect & 0xFF) == PAGE_NOACCESS || (protect & PAGE_GUARD) != 0) {
                return false;
            }
            var prot = protect & 0xFF;
            var ok = prot is PAGE_READONLY or PAGE_READWRITE or PAGE_WRITECOPY
                or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;
            if (!ok) {
                return false;
            }
            var chunk = (long) regionSize;
            if (chunk <= 0) {
                return false;
            }
            var step = chunk > remain ? remain : (int) chunk;
            cur += step;
            remain -= step;
        }
        return remain <= 0;
    }

    public static bool TryReadPtr(nint addr, out nint value) {
        value = 0;
        if (!IsReadable(addr, 8)) {
            return false;
        }
        value = *(nint*) addr;
        return true;
    }

    #endregion

    #region RestoreVirtualProtect

    [LibraryImport("KERNEL32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualProtect(void* lpAddress, nuint dwSize, uint flNewProtect, uint* lpflOldProtect);

    public const uint PAGE_EXECUTE_READWRITE = 0x40;

    /// <summary>
    /// 还原 ntdll 的 NtProtectVirtualMemory syscall stub（自 YaeAchievement）。
    /// 星铁反作弊会内联挂钩该导出（把 stub 开头改成 jmp 以监控 VirtualProtect），
    /// 先还原 stub 再挂 MinHook 才能安全修改代码段；否则对代码段的 VirtualProtect
    /// 会被反作弊拦截并直接终止进程。
    /// </summary>
    public static bool RestoreVirtualProtect() {
        if (!NativeLibrary.TryLoad("ntdll.dll", out var hPtr)) {
            return false;
        }
        if (!NativeLibrary.TryGetExport(hPtr, "NtProtectVirtualMemory", out var mPtr)) {
            return false;
        }
        // 4C 8B D1         mov     r10, rcx
        // B8               mov     eax, $imm32
        if (*(uint*) (mPtr - 0x20) != 0xB8D18B4C) { // previous（stub 已被改写则放弃）
            return false;
        }
        var syscallNumber = (ulong) *(uint*) (mPtr - 0x1C) + 1;
        var old = 0u;
        if (!VirtualProtect((void*) mPtr, 1, PAGE_EXECUTE_READWRITE, &old)) {
            return false;
        }
        *(ulong*) mPtr = 0xB8D18B4C | syscallNumber << 32;
        return VirtualProtect((void*) mPtr, 1, old, &old);
    }

    #endregion

}

internal static partial class MinHook {

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_Initialize")]
    private static partial uint MinHookInitialize();

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_CreateHook")]
    private static partial uint MinHookCreate(nint pTarget, nint pDetour, out nint ppOriginal);

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_EnableHook")]
    private static partial uint MinHookEnable(nint pTarget);

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_DisableHook")]
    private static partial uint MinHookDisable(nint pTarget);

    static MinHook() {
        var result = MinHookInitialize();
        if (result != 0) {
            throw new InvalidOperationException($"Failed to initialize MinHook: {result}");
        }
    }

    public static void Attach(nint origin, nint handler, out nint trampoline) {
        uint result;
        if ((result = MinHookCreate(origin, handler, out trampoline)) != 0) {
            throw new InvalidOperationException($"Failed to create hook: {result}");
        }
        if ((result = MinHookEnable(origin)) != 0) {
            throw new InvalidOperationException($"Failed to enable hook: {result}");
        }
    }

    /// <summary>分步接口: 先 Create(只读目标+建跳板), 后 Enable(写补丁)——用于定位崩溃阶段</summary>
    public static void Create(nint origin, nint handler, out nint trampoline) {
        var result = MinHookCreate(origin, handler, out trampoline);
        if (result != 0) {
            throw new InvalidOperationException($"Failed to create hook: {result}");
        }
    }

    public static void Enable(nint origin) {
        var result = MinHookEnable(origin);
        if (result != 0) {
            throw new InvalidOperationException($"Failed to enable hook: {result}");
        }
    }

    public static void Disable(nint origin) {
        MinHookDisable(origin);
    }

}
