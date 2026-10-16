using System.Runtime.InteropServices;

namespace GenshinSniffer.Utilities;

internal static unsafe partial class Native {

    #region PEB module walk

    [LibraryImport("KERNEL32.dll", EntryPoint = "GetModuleHandleW")]
    private static partial nint GetModuleHandleW(char* moduleName);

    private static nint GetModuleHandleWByName(string moduleName) {
        fixed (char* pName = moduleName) {
            return GetModuleHandleW(pName);
        }
    }

    [LibraryImport("NTDLL.dll", EntryPoint = "RtlGetCurrentPeb")]
    private static partial nint RtlGetCurrentPeb();

    /// <summary>
    /// 按名查找任意已加载模块。优先 GetModuleHandle（在游戏进程内对某些名字会被反作弊
    /// 屏蔽成 0），失败则手动遍历 PEB 的 InLoadOrder 模块链表。
    /// </summary>
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
        var head = ldr + 0x10; // InLoadOrderModuleList
        var entry = *(nint*) head;
        var guard = 0;
        while (entry != head && entry != 0 && guard++ < 512) {
            var dllBase = *(nint*) (entry + 0x30);
            var nameLen = *(ushort*) (entry + 0x68);      // BaseDllName.Length（字节数）
            var nameBuf = *(nint*) (entry + 0x70);        // BaseDllName.Buffer
            // 长度必须与目标名严格相等 —— 旧版这里写死 == 0x20 再逐个字符比较，
            // 等于把"名字前缀"当成了"名字"（A9 已删除那个函数）。这里按长度过滤后再比字符。
            if (nameBuf != 0 && nameLen == moduleName.Length * 2 && CompareName(nameBuf, moduleName)) {
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

    /// <summary>MEMORY_BASIC_INFORMATION (x64) 固定布局：RegionSize @+0x18, State @+0x20, Protect @+0x24</summary>
    private const int MbiSize = 48;

    /// <summary>哪些页保护位算"可读"（PAGE_GUARD 单独判定）。</summary>
    private static bool IsReadProtect(uint protect) =>
        protect is PAGE_READONLY or PAGE_READWRITE or PAGE_WRITECOPY
            or PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE or PAGE_EXECUTE_WRITECOPY;

    /// <summary>地址区间是否已提交且可读（PAGE_GUARD / PAGE_NOACCESS 一律判不可读）。</summary>
    public static bool IsReadable(nint addr, int size) {
        if (addr == 0 || size <= 0) {
            return false;
        }
        byte* pMbi = stackalloc byte[MbiSize];
        var cur = addr;
        var remain = size;
        var guard = 0;
        while (remain > 0 && guard++ < 64) {
            for (var i = 0; i < MbiSize; i++) {
                pMbi[i] = 0;
            }
            if (VirtualQuery((void*) cur, pMbi, MbiSize) == 0) {
                return false;
            }
            var regionSize = *(nuint*) (pMbi + 0x18);
            var state = *(uint*) (pMbi + 0x20);
            var protect = *(uint*) (pMbi + 0x24);
            if (state != MEM_COMMIT || (protect & 0xFF) == PAGE_NOACCESS || (protect & PAGE_GUARD) != 0) {
                return false;
            }
            if (!IsReadProtect(protect & 0xFF)) {
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

    /// <summary>
    /// 最近一次 VirtualQuery 得到的区域视图。
    ///
    /// 为什么要它（A11）：对象字段扫描会在**同一个 4KB 区域**里连续查几十个地址，
    /// 每个字段一次 VirtualQuery 纯属白花的系统调用。
    ///
    /// 为什么刻意不做跨调用的长期缓存：区域可能在两次调用之间被释放或改保护，
    /// 把"不可读"错判成"可读"就是一次访问违例 —— 那正是本文件存在的意义。
    /// 所以这个结构只允许"紧邻的几次判断"复用，用完即弃。
    /// </summary>
    public readonly struct Region {
        public readonly nint Base;
        public readonly nint End;
        public readonly bool Readable;

        internal Region(nint start, nint end, bool readable) {
            Base = start;
            End = end;
            Readable = readable;
        }

        /// <summary>区间是否完整落在本区域内（不落则调用方必须回退到完整校验）。</summary>
        public bool Covers(nint addr, int size) =>
            size >= 0 && addr >= Base && addr + size <= End;
    }

    /// <summary>查询 addr 所在内存区域；失败（地址非法）返回 false。</summary>
    public static bool TryQueryRegion(nint addr, out Region region) {
        region = default;
        if (addr == 0) {
            return false;
        }
        byte* pMbi = stackalloc byte[MbiSize];
        for (var i = 0; i < MbiSize; i++) {
            pMbi[i] = 0;
        }
        if (VirtualQuery((void*) addr, pMbi, MbiSize) == 0) {
            return false;
        }
        var regionSize = *(nuint*) (pMbi + 0x18);
        if (regionSize == 0) {
            return false;
        }
        var state = *(uint*) (pMbi + 0x20);
        var protect = *(uint*) (pMbi + 0x24);
        var readable = state == MEM_COMMIT && (protect & PAGE_GUARD) == 0 && IsReadProtect(protect & 0xFF);
        region = new Region(addr, addr + (nint) regionSize, readable);
        return true;
    }

    /// <summary>区域视图优先、不覆盖时回退到完整校验（同一个地址不会被 VirtualQuery 两次）。</summary>
    public static bool IsReadableIn(in Region region, nint addr, int size) =>
        region.Covers(addr, size) ? region.Readable : IsReadable(addr, size);

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
    /// 还原 ntdll 的 NtProtectVirtualMemory syscall stub（做法自 YaeAchievement）。
    /// 反作弊会内联挂钩该导出（把 stub 开头改成 jmp 以监控 VirtualProtect），
    /// 先还原 stub 再挂 MinHook 才能安全修改代码段；否则对代码段的 VirtualProtect
    /// 会被反作弊拦截并直接终止进程。
    ///
    /// 本次修正三处明确缺陷（A10）：
    ///   · 保护长度原来传 1 字节、却往目标写 8 字节 —— 后 7 字节仍是只读，写入即访问违例；
    ///   · 还原保护时输入/输出复用同一个变量 —— 旧值被自己的输出覆盖，还原的是"我们刚设的保护"；
    ///   · 解引用之前没有任何可读性校验。
    /// </summary>
    public static bool RestoreVirtualProtect() {
        if (!NativeLibrary.TryLoad("ntdll.dll", out var hPtr)) {
            return false;
        }
        if (!NativeLibrary.TryGetExport(hPtr, "NtProtectVirtualMemory", out var mPtr)) {
            return false;
        }
        // 上游的写法：stub-0x20 处应当是 "4C 8B D1 B8"（mov r10,rcx; mov eax,imm32），
        // 系统调用号紧跟在 +4（即 stub-0x1C）。★注意这里校验 mPtr-0x20、却把结果写到 mPtr，
        // 两个地址并不一致 —— 疑似上游把 NtAllocateVirtualMemory / NtProtectVirtualMemory
        // 两个 stub 的布局写混了。本次**保持既有行为**（不凭猜测改成"读写同一地址"），
        // 只补上可读性校验，等有游戏实测再复核。
        if (!IsReadable(mPtr - 0x20, 8) || !IsReadable(mPtr, 8)) {
            return false;
        }
        if (*(uint*) (mPtr - 0x20) != 0xB8D18B4C) {
            return false;   // stub 不是预期序言（已被改写？）→ 放弃，别硬写
        }
        var syscallNumber = (ulong) *(uint*) (mPtr - 0x1C) + 1;
        var oldProtect = 0u;                       // 输入用独立变量
        if (!VirtualProtect((void*) mPtr, 8, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        *(ulong*) mPtr = 0xB8D18B4C | syscallNumber << 32;
        var restoreOld = 0u;                       // 还原也用独立变量，不能被上一次的输出顶掉
        return VirtualProtect((void*) mPtr, 8, oldProtect, &restoreOld);
    }

    #endregion

}

/// <summary>
/// MinHook 的显式初始化包装。
///
/// 为什么不用静态构造函数（A9）：静态构造一旦抛异常，CLR 会把该类型永久标记为不可用，
/// 之后每次触碰都是 TypeInitializationException —— "挂钩失败"升级成"整个模块不可诊断"，
/// 而且第一次失败的真实原因只能从异常里猜。改成 TryInitialize 返回 bool + LastError。
///
/// 本类型不再有任何可能抛异常的静态初始化路径（唯一的静态状态是 int 字段）。
/// </summary>
internal static partial class MinHook {

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_Initialize")]
    private static partial uint MinHookInitialize();

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_CreateHook")]
    private static partial uint MinHookCreate(nint pTarget, nint pDetour, out nint ppOriginal);

    [LibraryImport("libMinHook.x64", EntryPoint = "MH_EnableHook")]
    private static partial uint MinHookEnable(nint pTarget);

    private const int StateUninitialized = 0;
    private const int StateReady = 1;
    private const int StateFailed = 2;
    private const int StateInitializing = 3;

    private static int _state = StateUninitialized;
    private static int _lastError;

    /// <summary>最近一次 MinHook 调用的返回码（0 = 成功）；失败原因靠它写进日志。</summary>
    public static int LastError => Volatile.Read(ref _lastError);

    /// <summary>
    /// 幂等初始化。失败后不再重试：MH_Initialize 失败基本是环境问题（缺 libMinHook.x64 等），
    /// 重试只会把日志刷满。可以被任意线程并发调用，只有第一个线程真正执行初始化。
    /// </summary>
    public static bool TryInitialize() {
        var state = Volatile.Read(ref _state);
        if (state == StateReady) {
            return true;
        }
        if (state != StateUninitialized) {
            // StateFailed：已是永久失败，不再重试；StateInitializing：别的线程正在初始化，
            // 这里刻意不阻塞等待 —— 调用可能发生在 detour 内，绝不能 Sleep。
            return false;
        }
        if (Interlocked.CompareExchange(ref _state, StateInitializing, StateUninitialized) != StateUninitialized) {
            return Volatile.Read(ref _state) == StateReady;
        }
        var result = MinHookInitialize();
        Volatile.Write(ref _lastError, (int) result);
        Volatile.Write(ref _state, result == 0 ? StateReady : StateFailed);
        return result == 0;
    }

    /// <summary>
    /// 挂一个钩子。返回 false 表示没挂上（LastError 里有 MH 的返回码），**不抛异常** ——
    /// 调用点据此跳过并打日志，而不是让异常穿过 detour 带走游戏进程。
    /// </summary>
    public static bool Attach(nint origin, nint handler, out nint trampoline) {
        trampoline = 0;
        if (origin == 0 || handler == 0) {
            Volatile.Write(ref _lastError, -1);
            return false;
        }
        if (!TryInitialize()) {
            return false;
        }
        var result = MinHookCreate(origin, handler, out var original);
        if (result != 0) {
            Volatile.Write(ref _lastError, (int) result);
            return false;
        }
        result = MinHookEnable(origin);
        Volatile.Write(ref _lastError, (int) result);
        if (result != 0) {
            // Enable 失败 = 目标代码段没有被改写，此时 trampoline 用不上；
            // 返回 0 让"false 就意味着不可调用"这条约定保持唯一。
            return false;
        }
        trampoline = original;
        return true;
    }
}
