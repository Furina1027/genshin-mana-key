using System.Runtime.InteropServices;
using GenshinSniffer.Utilities;

namespace GenshinSniffer;

/// <summary>
/// GenshinManaKey 注入 DLL —— 截获原神（hk4e）7.1 国服过场动画的 CRI Mana 解密密钥。
///
/// === 本版（v2 诊断版）要解决的问题 ===
/// 首轮实测：钩子全部挂上、MANAFILE 正常触发，但 4 个设密钥函数**一次都没被调用**，
/// 而播放的文件确认是 method2-aes（nonce 非零，md5 与我们的样本一致）
/// ⇒ 密钥**不是"每次播放"设的**，而是启动期一次性配置（CriWareDecrypter / CriManaPlugin），
///   或干脆不经这些托管 API。上一版是"先放行主线程、后挂钩子"，正好会漏掉启动期那一下。
///
/// 本版三处改动：
///   1. **先把所有钩子挂完，最后才放行主线程**（进程是挂起创建的，主模块此刻已映射）；
///   2. 扩大覆盖面：托管 SetFile（拿到 CriMana.Player 实例）+ 2 个未定性的新增方法
///      + 启动期 CRI 配置函数（CriWareDecrypter / CriManaPlugin）；
///   3. **对象字段扫描**：在 SetFile / Decrypter.Initialize 时扫对象内存，直接找出 8/16/24/32
///      字节的密钥数组（7.1 给 CriMana.Player 新增了 videoKey/audioKey/videoAesKey 字段）。
///
/// 目标客户端：**仅国服** `YuanShen.exe`（bilibili 版，CRC32 0xE597A764 = 7.1 国服）。
///
/// 上报协议（与 launcher 的配对逻辑对齐）：
///   MANAFILE  [i] &lt;路径&gt;                NativeMethods_SetFile（native 层，带 playerIndex）
///   MANAFILE2 &lt;路径&gt;                    SetFile（托管层，兜底）
///   MANAKEY2  {video:X16} {audio:X16}     托管 SetVideoAudioDecryptionKeys
///   MANAKEY3  {audio:X16} AES={hex}       托管 SetVideoAesKeyAudioDecryptionKey
///   MANAKEYN2 [i] {video:X16} {audio:X16} NativeMethods_SetVideoAudioDecryptionKeys
///   MANAKEYN3 [i] {audio:X16} AES={hex}   NativeMethods_SetVideoAesKeyAudioDecryptionKey2
///   OBJKEY / OBJDMP / DIAG                诊断行（launcher 当普通日志打印）
///
/// 铁律：任何回调都不得抛出未处理异常 —— NativeAOT 下会直接带走整个游戏进程。
/// </summary>
internal static unsafe class Application {

    private static bool _initialized;

    /// <summary>国服 7.1 各函数 RVA（相对 exe 基址，il2cpp 段内）。</summary>
    private static class Cn {
        // —— 密钥通路（由 7.0↔7.1 指纹序列对齐 + methodPointer 表索引定位，双路径互验一致）——
        public const uint SetVideoAudioKeys = 0x070546F0;         // 托管
        public const uint SetVideoAesKeyAudio = 0x07054B80;       // 托管
        public const uint NativeSetVideoAudioKeys = 0x070547F0;   // → cri_ware_unity!CRIWARE948D1068
        public const uint NativeSetVideoAesKeyAudio = 0x07054A70; // → cri_ware_unity!CRIWARE1E4885A8
        public const uint NativeSetFile = 0x070538C0;             // 文件名来源
        public const uint ManagedSetFile = 0x07053800;            // 托管 SetFile（拿 player 实例）
        // —— 7.1 该类新增、尚未定性的两个方法 ——
        public const uint Unk5 = 0x07057BF0;
        public const uint Unk6 = 0x07057C80;
        // —— key 管理器小方法（this=manager，this+0x50=binder，this+0x30=player）——
        public const uint KeyFeed = 0x06C4EA80;
        // —— 启动期 CRI 配置（7.0 指纹迁移，唯一命中且 delta 一致）——
        public const uint DecrypterInitConfig = 0x06FE9890;       // CriWareDecrypter.Initialize(Config)
        public const uint DecrypterInit2 = 0x06FE98C0;            // CriWareDecrypter.Initialize(str,b,b)
        public const uint DecrypterNative = 0x06FE9C10;           // CriWareDecrypter.CRIWARE1859E5C2
        public const uint PluginSetConfigParams = 0x06F54B70;     // CriManaPlugin.SetConfigParameters
        public const uint PluginSetConfigAdditional = 0x06F54D40; // CriManaPlugin.SetConfigAdditonalParameters_PC
    }

    private static nint _base;

    [UnmanagedCallersOnly(EntryPoint = "YaeMain")]
    private static uint Awake(nint hModule) {
        if (Interlocked.Exchange(ref _initialized, true)) {
            return 1;
        }
        try {
            Goshujin.Init();

            // ★ 进程被挂起创建 → 主模块此刻已映射，可以先把钩子全部挂好，最后再放行主线程。
            //   上一版先放行后挂钩，正好漏掉"游戏启动早期一次性设 key"的窗口。
            var found = false;
            for (var i = 0; i < 200; i++) {
                var m = Native.FindModuleBase("YuanShen.exe");
                if (m != 0) {
                    _base = m;
                    found = true;
                    break;
                }
                Thread.Sleep(50);
            }
            if (!found) {
                Goshujin.Report("未找到 YuanShen.exe 主模块，退出");
                Goshujin.ResumeMainThread();
                return 0;
            }
            Goshujin.Report($"原神国服主模块 base = {_base:X}");
            if (!Native.RestoreVirtualProtect()) {
                Goshujin.Report("RestoreVirtualProtect 失败（继续尝试挂钩）");
            }

            AttachCore();
            AttachDiagnostics();
            if (FullDiagnostics) {
                Goshujin.Report("诊断钩子已启用（GMK_FULL=1）");
            }

            // v5：FS 侦察默认关闭 —— 实测只要这个后台线程存在，视频就无法播放
            // （v3/v4 两次验证：线程在 → 放不了；v2 无此线程 → 正常。机制未知，
            //   疑似反作弊监控注入模块创建的新线程）。要启用设 GMK_FS=1。
            if (FsWatcher) {
                var watcher = new Thread(FsWatcherLoop) { IsBackground = true, Name = "gmk-fswatch" };
                watcher.Start();
                Goshujin.Report("FSWATCH 线程已启动（等待 cri_ware_unity.dll 加载）");
            }

            Goshujin.Report("全部挂钩完成（含启动期配置函数），现在放行主线程");
            Goshujin.ResumeMainThread();
        } catch (Exception e) {
            try { Goshujin.Report($"YaeMain error: {e.Message}"); } catch { }
            try { Goshujin.ResumeMainThread(); } catch { }
        }
        return 0;
    }

    // ==================== 通用工具 ====================

    private static bool IsUsableRva(nint addr) {
        if (addr == 0) {
            return false;
        }
        var b0 = *(byte*) addr;
        return b0 is 0x55 or 0x53 or 0x56 or 0x57 or 0x41 or 0x48;
    }

    private static string ReadIl2CppString(nint s) {
        if (s == 0) {
            return "(null)";
        }
        try {
            if (!Native.IsReadable(s, 0x18)) {
                return "(unreadable)";
            }
            var len = *(int*) (s + 0x10);
            if (len is < 0 or > 1024) {
                return $"(bad len {len})";
            }
            if (!Native.IsReadable(s + 0x14, len * 2)) {
                return "(unreadable chars)";
            }
            return new string((char*) (s + 0x14), 0, len);
        } catch {
            return "(read error)";
        }
    }

    private static string ReadIl2CppByteArrayHex(nint arr) {
        if (arr == 0) {
            return "";
        }
        try {
            if (!Native.IsReadable(arr, 0x20)) {
                return "(unreadable)";
            }
            var len = *(uint*) (arr + 0x18);
            if (len is > 0 and <= 64 && Native.IsReadable(arr + 0x20, (int) len)) {
                return Convert.ToHexString(new ReadOnlySpan<byte>((void*) (arr + 0x20), (int) len));
            }
            return $"len={len}";
        } catch {
            return "(read error)";
        }
    }

    private static string HexOf(nint addr, int size) {
        if (addr == 0 || size <= 0 || !Native.IsReadable(addr, size)) {
            return "(unreadable)";
        }
        return Convert.ToHexString(new ReadOnlySpan<byte>((void*) addr, size));
    }

    /// <summary>
    /// 扫描对象字段，找出「看起来像字节数组的密钥」：指向的 Il2CppArray 头部长度 8/16/24/32 且数据非全零。
    /// 同时 dump 对象前 0x80 字节，便于人工核对。
    /// </summary>
    private static void ScanObjectForKeys(string tag, nint obj, int maxOff = 0x400) {
        if (obj == 0 || !Native.IsReadable(obj, 0x20)) {
            return;
        }
        try {
            if (Native.IsReadable(obj, 0x80)) {
                Goshujin.Report($"OBJDMP {tag} obj={obj:X} {Convert.ToHexString(new ReadOnlySpan<byte>((void*) obj, 0x80))}");
            }
        } catch { }
        for (var off = 0x10; off <= maxOff; off += 8) {
            try {
                if (!Native.TryReadPtr(obj + off, out var p) || p == 0) {
                    continue;
                }
                if (!Native.IsReadable(p, 0x28)) {
                    continue;
                }
                var len = *(uint*) (p + 0x18);
                if (len is not (8 or 16 or 24 or 32)) {
                    continue;
                }
                if (!Native.IsReadable(p + 0x20, (int) len)) {
                    continue;
                }
                var span = new ReadOnlySpan<byte>((void*) (p + 0x20), (int) len);
                var allZero = true;
                foreach (var b in span) {
                    if (b != 0) {
                        allZero = false;
                        break;
                    }
                }
                if (allZero) {
                    continue;
                }
                Goshujin.Report($"OBJKEY {tag} +0x{off:X3} len={len} {Convert.ToHexString(span)}");
            } catch { }
        }
    }

    /// <summary>通用挂钩：宽签名（8 参数）。真实参数更少时被调方忽略多余的，安全。</summary>
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> AttachWide(
        string name, uint rva, delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> handler) {
        var target = _base + (int) rva;
        if (!IsUsableRva(target)) {
            Goshujin.Report($"[skip] {name} 目标无效 (0x{target:X})");
            return null;
        }
        MinHook.Attach(target, (nint) handler, out var trampoline);
        Goshujin.Report($"hook {name} @ 0x{target:X}");
        return (delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void>) trampoline;
    }

    // ==================== 核心钩子（密钥通路） ====================

    private static delegate* unmanaged<nint, ulong, ulong, void> _mvak;
    private static delegate* unmanaged<nint, nint, ulong, void> _mvaak;
    private static delegate* unmanaged<int, ulong, ulong, void> _nvak;
    private static delegate* unmanaged<int, nint, ulong, void> _nvaak;
    private static delegate* unmanaged<int, nint, nint, void> _nf;

    private static void AttachCore() {
        try {
            var t = _base + (int) Cn.SetVideoAudioKeys;
            if (IsUsableRva(t)) {
                delegate* unmanaged<nint, ulong, ulong, void> h = &OnManagedVideoAudioKeys;
                MinHook.Attach(t, (nint) h, out var tr);
                _mvak = (delegate* unmanaged<nint, ulong, ulong, void>) tr;
                Goshujin.Report($"hook SetVideoAudioDecryptionKeys @ 0x{t:X}");
            }
        } catch (Exception e) { Goshujin.Report($"S2 失败: {e.Message}"); }

        try {
            var t = _base + (int) Cn.SetVideoAesKeyAudio;
            if (IsUsableRva(t)) {
                delegate* unmanaged<nint, nint, ulong, void> h = &OnManagedVideoAesKeyAudio;
                MinHook.Attach(t, (nint) h, out var tr);
                _mvaak = (delegate* unmanaged<nint, nint, ulong, void>) tr;
                Goshujin.Report($"hook SetVideoAesKeyAudioDecryptionKey @ 0x{t:X}");
            }
        } catch (Exception e) { Goshujin.Report($"S3 失败: {e.Message}"); }

        try {
            var t = _base + (int) Cn.NativeSetVideoAudioKeys;
            if (IsUsableRva(t)) {
                delegate* unmanaged<int, ulong, ulong, void> h = &OnNativeVideoAudioKeys;
                MinHook.Attach(t, (nint) h, out var tr);
                _nvak = (delegate* unmanaged<int, ulong, ulong, void>) tr;
                Goshujin.Report($"hook NativeMethods_SetVideoAudioDecryptionKeys @ 0x{t:X}");
            }
        } catch (Exception e) { Goshujin.Report($"N2 失败: {e.Message}"); }

        try {
            var t = _base + (int) Cn.NativeSetVideoAesKeyAudio;
            if (IsUsableRva(t)) {
                delegate* unmanaged<int, nint, ulong, void> h = &OnNativeVideoAesKeyAudio;
                MinHook.Attach(t, (nint) h, out var tr);
                _nvaak = (delegate* unmanaged<int, nint, ulong, void>) tr;
                Goshujin.Report($"hook NativeMethods_SetVideoAesKeyAudioDecryptionKey2 @ 0x{t:X}");
            }
        } catch (Exception e) { Goshujin.Report($"N3 失败: {e.Message}"); }

        try {
            var t = _base + (int) Cn.NativeSetFile;
            if (IsUsableRva(t)) {
                delegate* unmanaged<int, nint, nint, void> h = &OnNativeSetFile;
                MinHook.Attach(t, (nint) h, out var tr);
                _nf = (delegate* unmanaged<int, nint, nint, void>) tr;
                Goshujin.Report($"hook NativeMethods_SetFile @ 0x{t:X}（文件名来源）");
            }
        } catch (Exception e) { Goshujin.Report($"NF 失败: {e.Message}"); }
    }

    [UnmanagedCallersOnly]
    private static void OnManagedVideoAudioKeys(nint self, ulong videoKey, ulong audioKey) {
        try { _mvak(self, videoKey, audioKey); } catch { }
        try { Goshujin.Report($"MANAKEY2 {videoKey:X16} {audioKey:X16}"); } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnManagedVideoAesKeyAudio(nint self, nint aesArray, ulong audioKey) {
        try { _mvaak(self, aesArray, audioKey); } catch { }
        try { Goshujin.Report($"MANAKEY3 {audioKey:X16} AES={ReadIl2CppByteArrayHex(aesArray)}"); } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnNativeVideoAudioKeys(int playerIndex, ulong videoKey, ulong audioKey) {
        try { _nvak(playerIndex, videoKey, audioKey); } catch { }
        try { Goshujin.Report($"MANAKEYN2 [{playerIndex}] {videoKey:X16} {audioKey:X16}"); } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnNativeVideoAesKeyAudio(int playerIndex, nint aesArray, ulong audioKey) {
        try { _nvaak(playerIndex, aesArray, audioKey); } catch { }
        try {
            Goshujin.Report($"MANAKEYN3 [{playerIndex}] {audioKey:X16} AES={ReadIl2CppByteArrayHex(aesArray)}");
        } catch { }
    }

    private static int _cSetFileN;
    private static int _cKlassDump;

    /// <summary>
    /// 启发式定位对象的 Il2CppClass.methods：扫 klass 内 8 对齐字段，找「指向指针数组、
    /// 且数组前 4 项都是 MethodInfo*（其 +0x0 是 il2cpp 段函数指针）」的槽位，把方法 RVA 全列出来。
    /// </summary>
    private static void DumpClassMethods(string tag, nint obj) {
        try {
            nint klass = 0;
            try { Native.TryReadPtr(obj, out klass); } catch { }
            if (obj == 0 || klass == 0 || !Native.IsReadable(klass, 0x600)) {
                if (klass != 0) {
                    try { Goshujin.Report($"{tag}KLASS klass={klass:X}"); } catch { }
                }
                return;
            }
            Goshujin.Report($"{tag}KLASS klass={klass:X}");
            // 原始 klass 字节（离线解析 methods 数组，启发式失败时的兜底）
            try { Goshujin.Report($"{tag}KLASSDUMP {Convert.ToHexString(new ReadOnlySpan<byte>((void*) klass, 0x600))}"); } catch { }
            var lo = _base + 0x6000000;
            var hi = _base + 0x1E000000;
            for (var off = 0x40; off <= 0x5F0; off += 8) {
                if (!Native.TryReadPtr(klass + off, out var arr) || arr == 0 || !Native.IsReadable(arr, 16)) {
                    continue;
                }
                var ok = 0;
                for (var i = 0; i < 4; i++) {
                    if (!Native.TryReadPtr(arr + 8 * i, out var mi) || mi == 0 || !Native.IsReadable(mi, 8)) {
                        break;
                    }
                    if (!Native.TryReadPtr(mi, out var mp) || mp < lo || mp >= hi) {
                        break;
                    }
                    ok++;
                }
                if (ok < 2) {
                    continue;
                }
                var sb = new System.Text.StringBuilder();
                var n = 0;
                for (var i = 0; i < 160; i++) {
                    if (!Native.TryReadPtr(arr + 8 * i, out var mi) || mi == 0 || !Native.IsReadable(mi, 8)) {
                        break;
                    }
                    if (!Native.TryReadPtr(mi, out var mp)) {
                        break;
                    }
                    sb.Append((mp - _base).ToString("X")).Append(' ');
                    n++;
                }
                if (n == 0) {
                    continue;
                }
                Goshujin.Report($"{tag}METHODS off=0x{off:X} ok={ok} n={n}");
                for (var s = 0; s < sb.Length; s += 1800) {
                    var len = Math.Min(1800, sb.Length - s);
                    Goshujin.Report($"{tag}M{s / 1800} {sb.ToString(s, len)}");
                }
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnNativeSetFile(int playerIndex, nint binder, nint path) {
        try { _nf(playerIndex, binder, path); } catch { }
        try { Volatile.Write(ref _bcArm, 1); } catch { }
        try {
            Goshujin.Report($"MANAFILE [{playerIndex}] {ReadIl2CppString(path)}");
            if (Interlocked.Increment(ref _cSetFileN) <= 10) {
                ScanObjectForKeys($"SetFileBinder[{playerIndex}]", binder, 0x300);
                try { Goshujin.Report($"BINDERDUMP {HexOf(binder, 0x100)}"); } catch { }
                if (_cSetFileN <= 3) {
                    DumpClassMethods($"BINDER{playerIndex}_", binder);
                    try { Goshujin.Report($"CONST5784500 {HexOf(_base + 0x5784500, 0x40)}"); } catch { }
                }
                ReportDecoderKey("OnSetFile");
            }
        } catch { }
    }

    // ==================== 诊断钩子 ====================

    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _setFileM;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _unk5;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _unk6;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _decInit;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _decInit2;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _decNative;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _plgParams;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _plgAdditional;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _keyFeed;

    private static int _cSetFileM, _cUnk, _cDecInit, _cDecNative, _cPlg;
    private static int _cBinderWalked, _cKeyFeed;
    private static int _cCriKey;
    private static nint _criBase;

    /// <summary>
    /// v13：纯内存读取 CRI 的 CriCipher AES 密钥（**不挂钩、不修改 cri_ware_unity.dll 的任何字节**）。
    ///
    /// 依据（本轮 Ghidra 反编译 + 字符串实证）：
    ///   · cri_ware_unity.dll 内含 "Microsoft Primitive Provider" / "AES" / "ChainingModeECB"
    ///     → CRI 用 BCrypt AES-ECB 自行构造 CTR 密钥流（只有 BCryptEncrypt，无 Decrypt，正是流模式特征）；
    ///   · 这解释了为什么 CRI DLL 里既没有 S-box 表也没有 AES-NI 指令；
    ///   · CriCipher_Create (RVA 0x132DFE) 把密钥写入 context：
    ///         *(ctx+0x20) = key[0..7]   *(ctx+0x28) = key[8..15]
    ///     → **context +0x20 就是 16 字节 AES key**；
    ///   · 全局单例 context 指针位于 RVA 0x26A7B0（对应报错 "Only one decrypter is creatable"）。
    ///
    /// 只读内存，不在 CRI 模块内写任何钩子——此前 v4 挂钩 CRI DLL 导致视频无法播放。
    /// </summary>
    private static void ReportCriCipherKey(string tag) {
        try {
            if (Interlocked.Increment(ref _cCriKey) > 8) {
                return;
            }
            if (_criBase == 0) {
                _criBase = Native.FindModuleBase("cri_ware_unity.dll");
            }
            if (_criBase == 0) {
                Goshujin.Report($"CRICIPHER [{tag}] cri_ware_unity.dll 未加载");
                return;
            }
            Goshujin.Report($"CRICIPHER [{tag}] cri=@0x{_criBase:X}");

            // 1) 单例 cipher context（RVA 0x26A7B0）
            nint ctx = 0;
            try { Native.TryReadPtr(_criBase + 0x26A7B0, out ctx); } catch { }
            if (ctx != 0 && Native.IsReadable(ctx, 0x48)) {
                Goshujin.Report($"CRICTX ctx=0x{ctx:X} {HexOf(ctx, 0x48)}");
                Goshujin.Report($"CRIKEY [{tag}] {HexOf(ctx + 0x20, 16)}");
            } else {
                Goshujin.Report($"CRICTX 单例指针不可读 raw=0x{ctx:X}");
            }

            // 2) 兜底：扫 .data 0x26A000~0x26B000，跟随所有可读指针，dump 目标 0x48 字节并单独报 +0x20 的 16 字节
            var found = 0;
            for (var off = 0x26A000; off < 0x26B000 && found < 14; off += 8) {
                nint p = 0;
                try { if (!Native.TryReadPtr(_criBase + off, out p) || p == 0) { continue; } } catch { continue; }
                if (p < 0x10000 || p > 0x7FFFFFFFFFFF) { continue; }
                if (!Native.IsReadable(p, 0x48)) { continue; }
                found++;
                Goshujin.Report($"CRIDATA +0x{off:X} -> 0x{p:X} {HexOf(p, 0x48)}");
                Goshujin.Report($"CRIDATAKEY +0x{off:X} {HexOf(p + 0x20, 16)}");
            }
            if (found == 0) {
                Goshujin.Report("CRIDATA (无可读指针)");
            }
        } catch { }
    }

    private static void AttachDiagnostics() {
        try { _setFileM = AttachWide("SetFile(managed)", Cn.ManagedSetFile, &OnManagedSetFile); }
        catch (Exception e) { Goshujin.Report($"SetFile(managed) 失败: {e.Message}"); }

        try { _unk5 = AttachWide("CriManaNew#5", Cn.Unk5, &OnUnk5); }
        catch (Exception e) { Goshujin.Report($"#5 失败: {e.Message}"); }
        try { _unk6 = AttachWide("CriManaNew#6", Cn.Unk6, &OnUnk6); }
        catch (Exception e) { Goshujin.Report($"#6 失败: {e.Message}"); }

        try { _decInit = AttachWide("CriWareDecrypter.Initialize(Config)", Cn.DecrypterInitConfig, &OnDecInit); }
        catch (Exception e) { Goshujin.Report($"Decrypter.Initialize 失败: {e.Message}"); }
        try { _decInit2 = AttachWide("CriWareDecrypter.Initialize(str,b,b)", Cn.DecrypterInit2, &OnDecInit2); }
        catch (Exception e) { Goshujin.Report($"Decrypter.Initialize2 失败: {e.Message}"); }
        try { _decNative = AttachWide("CriWareDecrypter.CRIWARE1859E5C2", Cn.DecrypterNative, &OnDecNative); }
        catch (Exception e) { Goshujin.Report($"Decrypter.native 失败: {e.Message}"); }

        try { _plgParams = AttachWide("CriManaPlugin.SetConfigParameters", Cn.PluginSetConfigParams, &OnPlgParams); }
        catch (Exception e) { Goshujin.Report($"Plugin.SetConfigParameters 失败: {e.Message}"); }
        try { _plgAdditional = AttachWide("CriManaPlugin.SetConfigAdditonalParameters_PC", Cn.PluginSetConfigAdditional, &OnPlgAdditional); }
        catch (Exception e) { Goshujin.Report($"Plugin.SetConfigAdditional 失败: {e.Message}"); }

        try { _keyFeed = AttachWide("KeyFeed(manager小方法)", Cn.KeyFeed, &OnKeyFeed); }
        catch (Exception e) { Goshujin.Report($"KeyFeed 失败: {e.Message}"); }
        // v14：尝试钩 bcrypt.dll（系统库）。此时可能尚未加载，后续钩子会重试。
        AttachBcrypt("core");
    }

    /// <summary>托管 SetFile —— 第一个参数就是 CriMana.Player 实例，直接扫它的字段找密钥。</summary>
    [UnmanagedCallersOnly]
    private static void OnManagedSetFile(nint self, nint path, nint a3, nint a4,
        nint a5, nint a6, nint a7, nint a8) {
        try { if (_setFileM != null) _setFileM(self, path, a3, a4, a5, a6, a7, a8); } catch { }
        // v16：播放已开始 → 允许记录 BCryptEncrypt（此前遥测刷屏占满配额）
        try { Volatile.Write(ref _bcArm, 1); } catch { }
        try {
            var txt = ReadIl2CppString(path);
            s_curFile = System.IO.Path.GetFileName(txt ?? "");   // v17：密钥是 per-video 的，记录归属
            if (Interlocked.Increment(ref _cSetFileM) <= 10) {
                Goshujin.Report($"DIAG SetFile self={self:X} {txt}");
                ScanObjectForKeys("Player", self);
                // v13：读取 CRI 的 AES 密钥（纯内存读取，不改 CRI DLL）
                ReportCriCipherKey(txt);
                // v14：钩 bcrypt.dll（系统库）
                AttachBcrypt("SetFile");
                // v9：从 Player+0x78 → +0x10 走到真正的 binder 对象（类槽 0x59EBE68 的实例）
                try {
                    if (Interlocked.CompareExchange(ref _cBinderWalked, 1, 0) == 0
                        && Native.TryReadPtr(self + 0x78, out var holder) && holder != 0
                        && Native.TryReadPtr(holder + 0x10, out var binder) && binder != 0) {
                        Goshujin.Report($"VBINDER holder={holder:X} binder={binder:X}");
                        ScanObjectForKeys("VBinder", binder, 0x200);
                        DumpClassMethods("VBINDER_", binder);
                        try { Goshujin.Report($"VBINDERP {HexOf(binder, 0x100)}"); } catch { }
                    }
                } catch { }
            } else {
                Goshujin.Report($"MANAFILE2 {txt}");
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnUnk5(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_unk5 != null) _unk5(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cUnk) <= 12) {
                Goshujin.Report($"DIAG new#5 a1={a1:X} a2={a2:X} a3={a3:X} a4={a4:X} h2={HexOf(a2, 0x20)}");
                ScanObjectForKeys("new#5", a1, 0x100);
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnUnk6(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_unk6 != null) _unk6(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cUnk) <= 12) {
                Goshujin.Report($"DIAG new#6 a1={a1:X} a2={a2:X} a3={a3:X} a4={a4:X} h2={HexOf(a2, 0x20)}");
                ScanObjectForKeys("new#6", a1, 0x100);
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnDecInit(nint cfg, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        // v14：CRI 初始化阶段就尝试钩 bcrypt（密钥可能在这一步生成）
        AttachBcrypt("DecInit");
        try { if (_decInit != null) _decInit(cfg, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cDecInit) <= 6) {
                // Config+0x10 = 参与 key 派生的字符串（key = default ^ hash(str)）
                nint str = 0;
                try { if (cfg != 0 && Native.TryReadPtr(cfg + 0x10, out var s)) { str = s; } } catch { }
                Goshujin.Report($"DIAG Decrypter.Initialize(Config) cfg={cfg:X} str={ReadIl2CppString(str)}");
                try { if (cfg != 0) { Goshujin.Report($"DIAG CFGDUMP {HexOf(cfg, 0x40)}"); } } catch { }
            }
            // 关键：Initialize 会把 56 位 key 写进全局 RVA 0x5785430 —— 直接读结果
            ReportDecoderKey("DecInit");
        } catch { }
    }

    // ==================== v14：钩 bcrypt.dll 拿 AES 密钥 ====================

    private static nint _bcryptBase;
    private static int _bcAttached, _cBcKey, _cBcEnc, _bcArm;
    private static string? s_curFile;

    private static delegate* unmanaged<nint, nint, nint, uint, nint, uint, uint, int> _bcGenKey;
    private static delegate* unmanaged<nint, nint, uint, nint, nint, uint, nint, uint, nint, uint, int> _bcEnc;

    /// <summary>
    /// v14：钩 bcrypt.dll 的 BCryptGenerateSymmetricKey / BCryptEncrypt。
    ///
    /// 为什么可以钩：**bcrypt.dll 是 Windows 系统库**，不是米哈游的 cri_ware_unity.dll。
    /// v4 的教训是挂钩 CRI DLL（游戏自有模块）会触发反作弊软响应 → 视频放不出来，
    /// 所以这里刻意只碰系统库，CRI DLL 一个字节都不改。
    ///
    /// 依据：CRI 的 CriCipher 用 BCrypt + ChainingModeECB 自行构造 CTR 密钥流，
    /// 因此 BCryptGenerateSymmetricKey 的 pbSecret/cbSecret 就是那 16 字节 AES key；
    /// BCryptEncrypt 的 (IV, 输入, 输出) 还能反推 counter 构造方式。
    /// </summary>
    private static void AttachBcrypt(string site) {
        if (Volatile.Read(ref _bcAttached) != 0) {
            return;
        }
        try {
            if (_bcryptBase == 0) {
                _bcryptBase = Native.FindModuleBase("bcrypt.dll");
            }
            if (_bcryptBase == 0) {
                Goshujin.Report($"BCRYPT [{site}] bcrypt.dll 未加载（稍后重试）");
                return;
            }
            var pGen = Native.GetExportAddress(_bcryptBase, "BCryptGenerateSymmetricKey");
            var pEnc = Native.GetExportAddress(_bcryptBase, "BCryptEncrypt");
            Goshujin.Report($"BCRYPT [{site}] mod=0x{_bcryptBase:X} gen=0x{pGen:X} enc=0x{pEnc:X}");
            if (pGen != 0) {
                delegate* unmanaged<nint, nint, nint, uint, nint, uint, uint, int> h = &OnBcGenKey;
                MinHook.Attach(pGen, (nint) h, out var tr);
                _bcGenKey = (delegate* unmanaged<nint, nint, nint, uint, nint, uint, uint, int>) tr;
            }
            if (pEnc != 0) {
                delegate* unmanaged<nint, nint, uint, nint, nint, uint, nint, uint, nint, uint, int> h2 = &OnBcEnc;
                MinHook.Attach(pEnc, (nint) h2, out var tr2);
                _bcEnc = (delegate* unmanaged<nint, nint, uint, nint, nint, uint, nint, uint, nint, uint, int>) tr2;
            }
            Volatile.Write(ref _bcAttached, 1);
            Goshujin.Report("BCRYPT 已挂钩（系统库 bcrypt.dll，未改动 CRI DLL）");
        } catch (Exception e) {
            Goshujin.Report($"BCRYPT [{site}] 挂钩失败: {e.Message}");
        }
    }

    [UnmanagedCallersOnly]
    private static int OnBcGenKey(nint hAlg, nint phKey, nint pbKeyObj, uint cbKeyObj,
        nint pbSecret, uint cbSecret, uint flags) {
        var g = _bcGenKey;
        var r = g != null ? g(hAlg, phKey, pbKeyObj, cbKeyObj, pbSecret, cbSecret, flags) : 0;
        try {
            var n = Interlocked.Increment(ref _cBcKey);
            if (n <= 60 && cbSecret is > 0 and <= 64 && Native.IsReadable(pbSecret, (int) cbSecret)) {
                // v17：带上当前播放的文件名 —— 密钥是 per-video 的（实测 SLT 与 HE 不同），
                // 一次会话依次播放多个视频即可逐个拿到各自的密钥。
                Goshujin.Report($"BCKEY #{n} file={s_curFile ?? "?"} len={cbSecret} {HexOf(pbSecret, (int) cbSecret)}");
            }
        } catch { }
        return r;
    }

    [UnmanagedCallersOnly]
    private static int OnBcEnc(nint hKey, nint pbInput, uint cbInput, nint pPad,
        nint pbIV, uint cbIV, nint pbOut, uint cbOut, nint pcbRes, uint flags) {
        var e = _bcEnc;
        // v16：三重过滤，确保抓到的是「视频解密的 counter 块」而不是游戏遥测上报。
        //  ① 只在播放开始（SetFile 触发）之后才记录 —— 遥测在播放前就刷屏了；
        //  ② 长度是 16 的倍数（CRI 用 AES-ECB 加密 counter 块生成密钥流）；
        //  ③ 输入不是可打印 ASCII —— 遥测的输入是 "POST /collector/api/report HTTP/"
        //     和 {"logs":... 这类文本，而 counter 块是含 nonce 的二进制。
        // v15 只用了 ②，但遥测长度（496/1024/752/2080）恰好也都是 16 的倍数，过滤失效。
        string? head = null;
        int n = 0;
        if (Volatile.Read(ref _bcArm) != 0 && cbInput > 0 && cbInput % 16 == 0 && cbInput <= 0x400000) {
            var isText = true;
            if (Native.IsReadable(pbInput, 8)) {
                for (var k = 0; k < 8; k++) {
                    var b = *(byte*) (pbInput + k);
                    if (b < 0x20 || b > 0x7E) { isText = false; break; }
                }
            }
            if (!isText) {
                n = Interlocked.Increment(ref _cBcEnc);
                if (n <= 200) {
                    try {
                        var ivl = (int) Math.Min(cbIV, 16u);
                        var inl = (int) Math.Min(cbInput, 32u);
                        var iv = cbIV > 0 && Native.IsReadable(pbIV, ivl) ? HexOf(pbIV, ivl) : "-";
                        var inp = Native.IsReadable(pbInput, inl) ? HexOf(pbInput, inl) : "-";
                        head = $"BCENC #{n} cbIn={cbInput} cbIV={cbIV} IV={iv} IN={inp}";
                    } catch { }
                }
            }
        }
        var r = e != null ? e(hKey, pbInput, cbInput, pPad, pbIV, cbIV, pbOut, cbOut, pcbRes, flags) : 0;
        if (head != null) {
            try {
                var outl = (int) Math.Min(cbOut, 32u);
                var outp = cbOut > 0 && Native.IsReadable(pbOut, outl) ? HexOf(pbOut, outl) : "-";
                Goshujin.Report(head + $" OUT={outp}");
            } catch {
                Goshujin.Report(head);
            }
        }
        return r;
    }

    /// <summary>读解密器派生 key 的全局位（RVA 0x5785430，紧邻 tcp/shared_ptr）。</summary>
    private static void ReportDecoderKey(string tag) {
        try {
            if (Native.TryReadPtr(_base + 0x5785430, out var key) && key != 0) {
                Goshujin.Report($"DECKEY [{tag}] {(ulong) key:X16}");
            }
        } catch { }
    }

    /// <summary>
    /// v12：读 CRI 解密回调（Decrypter 注册给 CRIWARE8F9AABA8 的委托目标）。
    /// 全局 RVA 0x588D600 → 结构体；+0x8 = 原生回调（thunk 0x140001FE0 从 obj+0x10 取的目标）。
    /// 回调代码前 0x40 字节足够离线反推出托管方法地址。
    /// </summary>
    private static void ReportDecCallback(string tag) {
        try {
            if (!Native.TryReadPtr(_base + 0x588D600, out var obj) || obj == 0 || !Native.IsReadable(obj, 0x28)) {
                return;
            }
            Goshujin.Report($"DECCALLBACK [{tag}] obj={obj:X} dump={HexOf(obj, 0x28)}");
            if (Native.TryReadPtr(obj + 8, out var cb) && cb != 0) {
                var where = (cb >= _base && cb < _base + 0x1A880000) ? $"exe+0x{cb - _base:X}" : "non-exe";
                Goshujin.Report($"DECCB [{tag}] cb={cb:X} ({where}) code={HexOf(cb, 0x40)}");
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnDecInit2(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_decInit2 != null) _decInit2(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cDecInit) <= 6) {
                Goshujin.Report($"DIAG Decrypter.Initialize2 str={ReadIl2CppString(a1)} b2={a2} b3={a3}");
            }
            ReportDecoderKey("DecInit2");
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnDecNative(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_decNative != null) _decNative(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cDecNative) <= 8) {
                Goshujin.Report($"DIAG Decrypter.native a1={a1} a2={a2} a3={a3:X} a4={a4:X} h3={HexOf(a3, 0x20)}");
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnPlgParams(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        AttachBcrypt("PlgParams");
        try { if (_plgParams != null) _plgParams(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cPlg) <= 8) {
                Goshujin.Report($"DIAG Plugin.SetConfigParameters a1={a1} a2={a2} a3={a3} a4={a4} a5={a5:X}");
                ScanObjectForKeys("PluginCfg", a5, 0x100);
            }
        } catch { }
    }

    /// <summary>
    /// key 管理器小方法（0x6C4EA80）：this=manager，this+0x30=Player，this+0x50=binder（解密器）。
    /// 方法入口时 binder 已创建（方法内部才会把它绑到 Player+0x78）——在这里 dump 正合适。
    /// </summary>
    [UnmanagedCallersOnly]
    private static void OnKeyFeed(nint mgr, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_keyFeed != null) _keyFeed(mgr, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cKeyFeed) <= 3) {
                nint binder = 0;
                try { Native.TryReadPtr(mgr + 0x50, out binder); } catch { }
                Goshujin.Report($"KEYFEED mgr={mgr:X} player={(mgr != 0 && Native.TryReadPtr(mgr + 0x30, out var pl) ? pl : 0):X} binder={binder:X}");
                ReportDecCallback("KeyFeed");
                // v13：读取 CRI 的 AES 密钥（纯内存读取，不改 CRI DLL）
                ReportCriCipherKey("KeyFeed");
                // v14：钩 bcrypt.dll（系统库）
                AttachBcrypt("KeyFeed");
                if (binder != 0) {
                    ScanObjectForKeys("VBinder", binder, 0x200);
                    DumpClassMethods("VBINDER_", binder);
                    try { Goshujin.Report($"VBINDERP {HexOf(binder, 0x100)}"); } catch { }
                }
                // holder（Player+0x78 的对象，BinderSet 的另一端）
                if (mgr != 0 && Native.TryReadPtr(mgr + 0x30, out var player) && player != 0
                    && Native.TryReadPtr(player + 0x78, out var holder) && holder != 0) {
                    try { Goshujin.Report($"HOLDERP {HexOf(holder, 0x80)}"); } catch { }
                    DumpClassMethods("HOLDER_", holder);
                }
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static void OnPlgAdditional(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_plgAdditional != null) _plgAdditional(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        try {
            if (Interlocked.Increment(ref _cPlg) <= 8) {
                Goshujin.Report($"DIAG Plugin.SetConfigAdditional a1={a1} a2={a2} a3={a3}");
            }
        } catch { }
    }

    // ==================== v4：CRI FS 就地解密回调捕获（收缩版） ====================
    //
    // v3 教训：
    //   1. GetModuleHandleW 在游戏进程内被反作弊屏蔽（Native.cs 注释已写明）→ 侦察线程永远找不到
    //      cri_ware_unity.dll，一行 FSREG 都没有。必须用 Native.FindModuleBase（PEB 遍历）。
    //   2. 「视频播放不了」的最可疑原因：v3 在 il2cpp 段挂了 13 处代码补丁，HoYoKProtect 大概率
    //      做代码完整性检测 → 软性反篡改（视频功能失效）。v4 默认只保留 v1 实测不影响播放的
    //      5 个核心钩子；诊断钩子（8 个）只在 FULL=1 时启用。
    //   3. 回调 detour 若声明为 void 返回，真回调返回 BOOL 时返回值被毁 → 解密失败。
    //      v4 回调 detour 改为 nint 返回并透传原函数结果。

    /// <summary>是否启用 8 个诊断钩子（会显著增大 il2cpp 代码补丁面积，可能触发反作弊软响应）。</summary>
    private static bool FullDiagnostics => Environment.GetEnvironmentVariable("GMK_FULL") == "1";

    /// <summary>是否启用 CRI FS 侦察线程（实测会令视频无法播放，默认关闭）。</summary>
    private static bool FsWatcher => Environment.GetEnvironmentVariable("GMK_FS") == "1";

    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _fsSetDecCb;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, nint> _fsDecCbTrampoline;

    private static nint _criModule;          // cri_ware_unity.dll 基址
    private static nint _fsDecCb;            // 游戏注册的解密回调
    private static int  _fsRegCount, _fsCbCount;
    private static int  _fsAttachState;      // 0=待捕获 1=已捕获待挂钩 2=已挂/已放弃

    private static void FsWatcherLoop() {
        try { Goshujin.Report("FSWATCH: 线程已进入"); } catch { }
        // 1) 等 cri_ware_unity.dll 被加载（PEB 遍历，GetModuleHandle 被反作弊屏蔽不可用）
        nint mod = 0;
        for (var i = 0; i < 3000 && mod == 0; i++) {           // 最多 ~10 分钟
            Thread.Sleep(200);
            try { mod = Native.FindModuleBase("cri_ware_unity.dll"); } catch { }
        }
        if (mod == 0) {
            try { Goshujin.Report("FSWATCH: cri_ware_unity.dll 未加载，放弃"); } catch { }
            return;
        }
        _criModule = mod;
        try { Goshujin.Report($"FSWATCH: cri_ware_unity.dll @ {mod:X}"); } catch { }

        var proc = Native.GetExportAddress(mod, "criFsLoader_SetInplaceDecryptionCbFunc");
        if (proc == 0) {
            try { Goshujin.Report("FSWATCH: 无 criFsLoader_SetInplaceDecryptionCbFunc 导出"); } catch { }
            return;
        }
        try { Goshujin.Report($"FSWATCH: criFsLoader_SetInplaceDecryptionCbFunc @ {proc:X}"); } catch { }
        try {
            delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> h = &OnFsSetDecCb;
            MinHook.Attach(proc, (nint) h, out var tr);
            _fsSetDecCb = (delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void>) tr;
            try { Goshujin.Report("FSWATCH: 注册函数已挂钩"); } catch { }
        } catch (Exception e) {
            try { Goshujin.Report($"FSWATCH: 注册函数挂钩失败 {e.Message}"); } catch { }
            return;
        }

        // 2) 等游戏注册回调 → 挂回调本身（拿明文/密文对 + 回调代码归属）
        for (var i = 0; i < 3000 && Volatile.Read(ref _fsAttachState) == 0; i++) {
            Thread.Sleep(200);
        }
        if (Volatile.Read(ref _fsAttachState) != 1) {
            return;   // 没等到注册
        }
        Thread.Sleep(300);                                     // 稳一下
        var cb = Volatile.Read(ref _fsDecCb);
        try {
            delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, nint> h = &OnFsDecCb;
            MinHook.Attach(cb, (nint) h, out var tr2);
            _fsDecCbTrampoline = (delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, nint>) tr2;
            Volatile.Write(ref _fsAttachState, 2);
            try { Goshujin.Report($"FSWATCH: 解密回调已挂钩 @ {cb:X}"); } catch { }
        } catch (Exception e) {
            Volatile.Write(ref _fsAttachState, 2);
            try { Goshujin.Report($"FSWATCH: 回调挂钩失败 {e.Message}"); } catch { }
        }
    }

    /// <summary>回调地址落在哪个模块（exe / cri dll / 其它）。</summary>
    private static string LocateAddress(nint addr) {
        if (addr >= _base && addr < _base + 0x20000000) {
            return $"exe+0x{addr - _base:X}";
        }
        if (_criModule != 0 && addr >= _criModule && addr < _criModule + 0x400000) {
            return $"cri+0x{addr - _criModule:X}";
        }
        return "?";
    }

    [UnmanagedCallersOnly]
    private static void OnFsSetDecCb(nint loader, nint cbfunc, nint udata, nint a4, nint a5, nint a6, nint a7, nint a8) {
        try { if (_fsSetDecCb != null) _fsSetDecCb(loader, cbfunc, udata, a4, a5, a6, a7, a8); } catch { }
        try {
            var n = Interlocked.Increment(ref _fsRegCount);
            // code 前 0x100 字节：够静态识别 reverse-pinvoke 包装并定位托管方法
            Goshujin.Report($"FSREG #{n} loader={loader:X} cbfunc={cbfunc:X} [{LocateAddress(cbfunc)}] udata={udata:X}");
            Goshujin.Report($"FSREGCODE #{n} {HexOf(cbfunc, 0x100)}");
            if (cbfunc != 0 && Interlocked.CompareExchange(ref _fsDecCb, cbfunc, 0) == 0) {
                Volatile.Write(ref _fsAttachState, 1);         // 通知 watcher 去挂回调
            }
        } catch { }
    }

    [UnmanagedCallersOnly]
    private static nint OnFsDecCb(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var t = _fsDecCbTrampoline;
        var n = Interlocked.Increment(ref _fsCbCount);
        string? pre2 = null, pre3 = null;
        if (n <= 16) {
            pre2 = HexOf(a2, 0x30);
            pre3 = HexOf(a3, 0x30);
        }
        nint result = 0;
        try { if (t != null) result = t(a1, a2, a3, a4, a5, a6, a7, a8); } catch { }
        if (n <= 16) {
            try {
                Goshujin.Report($"FSCALL #{n} a1={a1:X} a2={a2:X} a3={a3:X} a4={a4:X} a5={a5:X} ret={result:X}");
                Goshujin.Report($"  pre  a2={pre2}  a3={pre3}");
                Goshujin.Report($"  post a2={HexOf(a2, 0x30)}  a3={HexOf(a3, 0x30)}");
            } catch { }
        }
        return result;
    }

}
