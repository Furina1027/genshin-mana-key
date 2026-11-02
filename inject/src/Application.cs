using System.Runtime.InteropServices;
using System.Text;
using GenshinSniffer.Utilities;

namespace GenshinSniffer;

/// <summary>
/// GenshinManaKey 注入 DLL —— 截获原神（hk4e）7.1 过场动画的 CRI Mana 解密密钥。
///
/// === 本版（v20）相对上一版的改动要点 ===
///   · **删除全部诊断钩子**（原 GMK_FULL 下的 4 个 MANAKEY + 9 个侦察钩子）：
///     2026-10-16 多轮实测，7.x 的密钥只走 bcrypt 通路（BCKEY），托管 MANAKEY 钩子
///     整场游戏 0 次调用；对象扫描/KLASS dump/CRICIPHER/DECKEY 只服务于逆向调查。
///     删掉后 il2cpp 补丁面积恒为 1 处，版本更新也只需迁移 1 个 RVA（见 update_rva.py）。
///     历史代码见 git（v19 及之前）。
///   · 保留的可选项：GMK_BC=0 关 bcrypt 钩子；GMK_FS=1 启用 CRI FS 侦察线程
///     （无 RVA 依赖，不参与版本更新）；GMK_REUSE=1 允许"同钥换视频"补报。
///
/// 密钥链路（全部实测依据）：
///   文件名  NativeMethods_SetFile（il2cpp，唯一稳定触发的钩子）→ s_curFile
///   密钥    BCryptGenerateSymmetricKey（bcrypt.dll，系统库）的 pbSecret = 16 字节 AES key
///   归属    BCKEY 行自带 file=，launcher 的 KeyPairing 直接落 paired_keys.json
///
/// 目标客户端：国服 YuanShen.exe / 国际服 GenshinImpact.exe。
///
/// 上报协议（前缀与字段位置不得改动，启动器按它解析；0xFC/0xFD/0xFE 语义由 Goshujin 负责）：
///   MANAFILE  [i] &lt;路径&gt;      NativeMethods_SetFile（native 层，带 playerIndex）★ 唯一的 il2cpp 钩子
///   BCKEY / BCENC             bcrypt.dll 钩子产出（密钥本体 / 密钥流验证）
///   FSWATCH / FSREG / FSCALL  仅 GMK_FS=1（CRI FS 就地解密回调捕获）
///   EXC / EXCSUM              异常诊断行
///
/// 铁律：任何回调都不得抛出未处理异常 —— NativeAOT 下会直接带走整个游戏进程。
/// 因此所有 catch 都是"全捕获 + LogException"：捕获是为了活着，上报是为了**看得见**。
/// </summary>
internal static unsafe class Application {

    private static bool _initialized;
    private static nint _base;
    private static PeImage? _pe;
    private static RvaSet? _selected;
    private static string _mainModuleName = "(未识别)";

    /// <summary>实测到的 exe 版本指纹（头 64KB 的 CRC32；0 = 还没算 / 读不到）。</summary>
    private static uint _versionFingerprint;

    /// <summary>指纹比对结果。默认 <see cref="VersionGuard.State.Unchecked"/> = 行为与"没有这个机制"完全一致。</summary>
    private static VersionGuard.State _versionState = VersionGuard.State.Unchecked;

    /// <summary>NF 收到过几个"不像视频文件"的名字（用于限速上报，见 OnNativeSetFile）。</summary>
    private static int _nfSuspectCount;

    /// <summary>
    /// 当前生效的 RVA 常量集：Awake 里按主模块名选定，未选定时按国服。
    /// 刻意用属性而不是"字段直接初始化成 Cn"：静态字段按**文本顺序**初始化，
    /// 写成 `= Cn` 会在 Cn 还没赋值时就读它（编译器 CS8601 报的正是这个顺序错误）。
    /// </summary>
    private static RvaSet Rva => _selected ?? Cn;

    // ==================== RVA 常量集（A7：国服 / 国际服各一套） ====================

    /// <summary>
    /// 一套 RVA 常量。**0 = 该服务器未定位此钩子**，一律跳过并在日志里说明。
    /// 绝不编造 RVA：地址蒙错时若恰好通过序言校验，被改掉的就是别的函数的代码，
    /// 游戏行为会变得无法解释（比重启一次工具贵得多）。
    ///
    /// v20 起只保留 NF（NativeMethods_SetFile）：它是唯一需要的 il2cpp 钩子（文件名来源），
    /// 也让 update_rva.py 的迁移清单缩到 1 项。真名 CriWare.CriMana.Player.NativeMethods_SetFile，
    /// 可用 genshin-metadata 的 methods.csv 按名直读（全名稳定，CRI 包装类不受混淆影响）。
    /// </summary>
    private sealed class RvaSet {
        public string Name = "";

        /// <summary>
        /// 这一版 exe 的版本指纹（头 64KB 的 CRC32，见 <see cref="VersionGuard"/>）。
        /// **0 = 未登记**，不是错误：此时只能靠四道门自保，日志会说明。
        /// 由 tools\update_rva.py 在迁移成功后自动写回，所以它和 NativeSetFile 永远是同一版的。
        /// </summary>
        public uint Fingerprint;

        public uint NativeSetFile;              // NF ★文件名来源，唯一的 il2cpp 钩子
    }

    /// <summary>
    /// 国服 7.1（YuanShen.exe）。已用「国际服 7.1 全量 idx→RVA 表 + 国服实测锚点标定位移 0x3120」
    /// 反查确认，并与 genshin-metadata/cn/out/methods.csv（idx75746）逐一核对一致。
    /// Fingerprint = 0xC66689B9 = CRC32(exe 头 SizeOfHeaders=0x400 字节)，已用
    /// rva_cache\YuanShen.exe（7.1 国服）实际算过；注意它**不等于**"文件前 64KB 的 CRC32"
    /// （那是 0xE597A764，在内存镜像里算不出来，见 VersionGuard 的口径说明）。
    /// </summary>
    private static readonly RvaSet Cn = new() {
        Name = "国服 YuanShen.exe 7.1",
        Fingerprint = 0xC66689B9,
        NativeSetFile = 0x070538C0,
    };

    /// <summary>
    /// 国际服 GenshinImpact.exe。来源：README 的 RVA 表（= 国际服 7.1 全量 idx→RVA 表直接读出来的值）。
    /// Fingerprint = 0（未登记）：本机没有国际服客户端，**没实测过就不填**（编一个假指纹比不填更糟）。
    /// 写成 <c>0x00000000</c> 而不是裸 <c>0</c>：update_rva.py 的常量正则只认 <c>0x</c> 字面量，
    /// 写成裸 0 会让这一行既读不到也写不回，国际服就永远登记不上指纹。
    /// 在国际服客户端上跑一次 update_rva.cmd 会自动补上。
    /// </summary>
    private static readonly RvaSet Gl = new() {
        Name = "国际服 GenshinImpact.exe（仅文件名 RVA 已定位）",
        Fingerprint = 0x00000000,
        NativeSetFile = 0x070507A0,
    };

    /// <summary>主模块候选名 → 决定用哪套 RVA 常量（A7）。</summary>
    private static readonly string[] MainModuleNames = { "YuanShen.exe", "GenshinImpact.exe" };

    // ==================== 入口 ====================

    [UnmanagedCallersOnly(EntryPoint = "YaeMain")]
    private static uint Awake(nint hModule) {
        if (Interlocked.Exchange(ref _initialized, true)) {
            return 1;
        }
        try {
            Goshujin.Init();
            // 开关组合先落日志：事后翻日志时"这轮到底开没开 GMK_FS/GMK_BC"是最常见的问题（A13）
            TryReport(Options.Describe());
            // 会话结束汇总异常计数。注意：注入 DLL 不走正常的托管卸载路径，
            // 这个事件能否触发没有实测条件（不能运行游戏），所以 LogException 里
            // 还有"每累计 100 次异常就打一行汇总"的兜底。
            Safe("Awake:ProcessExit", () => AppDomain.CurrentDomain.ProcessExit += (_, _) => ReportExceptionSummary("ProcessExit"));

            // ★ 进程被挂起创建 → 主模块此刻已映射，可以先把钩子全部挂好，最后再放行主线程。
            //   上一版"先放行后挂钩"正好漏掉"游戏启动早期一次性设 key"的窗口。
            if (!AwaitMainModule()) {
                Goshujin.ResumeMainThread();
                return 0;
            }
            // 版本自证：先算指纹、再决定挂不挂（只影响日志与 GMK_STRICT=1 的可选拦截，
            // 默认路径的挂钩行为与不检查时完全一致 —— 见 CheckVersion 的说明）
            Safe("Awake:CheckVersion", CheckVersion);
            if (!MinHook.TryInitialize()) {
                Goshujin.Report($"MinHook 初始化失败（MH 错误码 {MinHook.LastError}），放弃全部挂钩");
                Goshujin.ResumeMainThread();
                return 0;
            }
            if (!Native.RestoreVirtualProtect()) {
                Goshujin.Report("RestoreVirtualProtect 失败（继续尝试挂钩）");
            }

            AttachCore();

            // bcrypt 是**系统库**钩子，不是 il2cpp 代码补丁，所以不跟诊断钩子一起门控：
            // 实测日志（run/dumper.log）里 MANAKEY2/3/N2/N3 与 DECKEY 全是 0 条，
            // 唯一真正产出密钥的就是这条 BCKEY 路径 —— 一起门控掉默认运行就一个密钥都拿不到。
            // 用 GMK_BC=0 可单独关闭（万一事实证明系统库补丁也影响播放）。
            if (Options.BcryptHook) {
                AttachBcrypt("core");
            } else {
                Goshujin.Report("bcrypt 钩子已按 GMK_BC=0 关闭");
            }

            // v5：FS 侦察默认关闭 —— 实测只要这个后台线程存在，视频就无法播放
            // （v3/v4 两次验证：线程在 → 放不了；v2 无此线程 → 正常。机制未知，
            //   疑似反作弊监控注入模块创建的新线程）。要启用设 GMK_FS=1。
            if (Options.FsWatcher) {
                var watcher = new Thread(FsWatcherLoop) { IsBackground = true, Name = "gmk-fswatch" };
                watcher.Start();
                Goshujin.Report("FSWATCH 线程已启动（等待 cri_ware_unity.dll 加载）");
            }

            Goshujin.Report($"全部挂钩完成（{_mainModuleName} / {Rva.Name}），现在放行主线程");
            Goshujin.ResumeMainThread();
        } catch (Exception e) {
            LogException("Awake", e);
            Safe("Awake:resume", Goshujin.ResumeMainThread);
        }
        return 0;
    }

    /// <summary>
    /// 等主模块映射好，并据其名字选定 RVA 常量集。
    /// 进程是挂起创建的，主模块此刻已在 PEB 里，所以正常是第一次循环就命中。
    /// </summary>
    private static bool AwaitMainModule() {
        for (var i = 0; i < 200; i++) {
            foreach (var name in MainModuleNames) {
                var module = Native.FindModuleBase(name);
                if (module == 0) {
                    continue;
                }
                _base = module;
                _mainModuleName = name;
                // A7：按主模块名选常量集，并把选择结果打进日志（分段偏移全靠它解释）
                _selected = name == "GenshinImpact.exe" ? Gl : Cn;
                Goshujin.Report($"主模块 {name} base = 0x{_base:X}，生效 RVA 常量集 = {Rva.Name}");
                if (PeImage.TryCreate(_base, out var pe)) {
                    _pe = pe;
                } else {
                    Goshujin.Report("PE 节表解析失败：RVA 只能退回「可读性 + 序言」校验，模块范围用兜底常量");
                }
                return true;
            }
            Thread.Sleep(50);
        }
        Goshujin.Report("未找到主模块（YuanShen.exe / GenshinImpact.exe），退出");
        return false;
    }

    /// <summary>
    /// 版本自证：把 **exe 磁盘文件头部**的 CRC32 与常量集里登记的 <see cref="RvaSet.Fingerprint"/> 比对。
    ///
    /// **这个方法默认不改变任何行为**（不拒绝挂钩、不动归属），只多打一两行日志：
    ///   · 匹配   → "版本指纹匹配 …"，说明这版 RVA 确实是给这版 exe 的；
    ///   · 未登记 → "版本指纹未登记 …"，提示跑一次 update_rva 登记（国际服当前就是这种）；
    ///   · 不匹配 → "⚠ 版本指纹不匹配 …"，游戏已更新而 RVA 还是旧的 —— 这是唯一会让
    ///              GMK_STRICT=1 生效的状态（见 AttachCore），默认仍然照挂，只是把话说清楚。
    ///   · 读不到 → 跳过判定（宁可不说，也不要说错）。
    ///
    /// ★ 为什么判定读**磁盘文件**而不是现成的内存镜像（2026-11-02 实跑教训）：
    ///   带保护壳的客户端（本 exe 有 `.tls` 段 + TLS 目录）会在注入线程启动时先跑 TLS 回调，
    ///   于是等这里读头部时，内存里的那 1KB 早被壳改写过 —— 同一版客户端实测
    ///   磁盘 0xC66689B9 / 内存 0x9735915B。拿内存值比对就会每次误报"游戏已更新"，
    ///   而且一开 GMK_STRICT=1 就会误杀 NF（NF 没了 → 文件名归属全丢 → 所有 BCKEY 被拒收）。
    ///   所以内存值只作为参照写进日志，**不参与判定**。
    ///
    /// 为什么不默认拦：一次正常更新后如果忘了跑 update_rva，用户至少还能拿到 key（只是没有
    /// 文件名）；把"宁可少挂"的选择权交给 GMK_STRICT 这个显式开关。
    /// </summary>
    private static void CheckVersion() {
        var expected = Rva.Fingerprint;

        // ① 判定来源：磁盘上的 exe 文件（与 tools\update_rva.py 读的是同一个文件、同一段字节）
        if (!TryHashFileHeader(out var fileCrc, out var fileLen, out var why)) {
            Goshujin.Report($"版本指纹：读不到 exe 文件（{why}），跳过校验（RVA 只能靠四道门自保）");
            return;
        }

        // ② 参照：内存镜像头部。只记录，永不参与判定（保护壳会改写它，见方法注释）
        var memoryNote = TryHashModuleHeader(out var memoryCrc, out _)
            ? $"内存镜像头部 0x{memoryCrc:X8}（仅参照：保护壳会改写，不参与判定）"
            : "内存镜像头部不可读";

        _versionFingerprint = fileCrc;
        _versionState = VersionGuard.Compare(fileCrc, expected);
        Goshujin.Report($"版本指纹：磁盘文件头部 0x{fileCrc:X8}；{memoryNote}");
        Goshujin.Report(VersionGuard.Describe(_versionState, fileCrc, expected, fileLen));
    }

    /// <summary>
    /// 算 **磁盘上本进程 exe 文件**头部（前 SizeOfHeaders 字节）的 CRC32。
    ///
    /// 路径取 <see cref="Environment.ProcessPath"/> —— 本 DLL 注入在游戏进程里，它就是游戏 exe。
    /// 打开方式必须是 `FileShare.ReadWrite | Delete`：exe 正被本进程映射着，独占打开会失败。
    /// 读失败一律返回 false（**绝不回退到内存值**，那正是误报的来源）。
    /// </summary>
    private static bool TryHashFileHeader(out uint crc, out int length, out string why) {
        crc = 0;
        length = 0;
        // 主用 P/Invoke（注入环境里最确定），拿不到再退回框架实现
        var path = Native.GetProcessImagePath() ?? Environment.ProcessPath;
        if (string.IsNullOrEmpty(path)) {
            why = "拿不到进程 exe 路径";
            return false;
        }
        try {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            var buffer = new byte[VersionGuard.FingerprintBytes];
            var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            if (read < 0x40) {
                why = $"exe 头部只读到 {read} 字节";
                return false;
            }
            if (!VersionGuard.TryHashHeader(buffer.AsSpan(0, read), out crc, out length)) {
                why = $"头部声明的 SizeOfHeaders 超过可读的 {read} 字节";
                return false;
            }
            why = "";
            return true;
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException
                                        or NotSupportedException or ArgumentException) {
            why = e.GetType().Name;
            return false;
        } catch (Exception e) {
            LogException("CheckVersion:file", e);
            why = e.GetType().Name;
            return false;
        }
    }

    /// <summary>算当前**内存镜像**头部的 CRC32（只用来写日志做参照，不参与判定）。</summary>
    private static bool TryHashModuleHeader(out uint crc, out int length) {
        crc = 0;
        length = 0;
        var probe = VersionGuard.FingerprintBytes;
        if (_pe != null && _pe.SizeOfImage < (uint) probe) {
            probe = (int) _pe.SizeOfImage;
        }
        if (!Native.IsReadable(_base, probe)) {
            probe = VersionGuard.FingerprintFallbackBytes;
            if (!Native.IsReadable(_base, probe)) {
                return false;
            }
        }
        return VersionGuard.TryHashHeader(new ReadOnlySpan<byte>((void*) _base, probe), out crc, out length);
    }

    // ==================== 异常诊断（A8） ====================
    //
    // 铁律的另一半：捕获是为了不让异常带走游戏进程，但"全捕获"不等于"全静默"。
    // 统一收口在这里：同一个 site 只报前 3 次（热路径按帧调用，不这样会刷爆管道），
    // 之后只累加计数；计数在会话结束时（或每累计 100 次时）汇总成一行。

    private static readonly Lock _excGate = new();
    private static readonly Dictionary<string, int> _excCounts = new(StringComparer.Ordinal);
    private static int _excTotal;
    private static int _excReportFailures;

    /// <summary>同一 site 最多上报几次（超出的只计数）。</summary>
    private const int ExceptionReportLimit = 3;

    /// <summary>
    /// 统一异常上报。<paramref name="site"/> 必须是常量字符串（字面量）：热路径上
    /// 只有前 3 次真的会拼消息，之后这里只剩一次字典查找，不产生堆分配。
    /// 本方法自身绝不抛异常。
    /// </summary>
    private static void LogException(string site, Exception e) {
        int seen;
        using (_excGate.EnterScope()) {
            _excCounts.TryGetValue(site, out var previous);
            seen = previous + 1;
            _excCounts[site] = seen;
        }
        if (seen <= ExceptionReportLimit) {
            try {
                Goshujin.Report($"EXC {site} #{seen} {e.GetType().Name}: {e.Message}");
            } catch (Exception) {
                // 管道已断（游戏/启动器先退出）时上报必然失败 —— 这是预期内的，
                // 但不能完全静默：计数留给会话结束的 EXCSUM 行。
                Interlocked.Increment(ref _excReportFailures);
            }
        }
        if (Interlocked.Increment(ref _excTotal) % 100 == 0) {
            // 兜底汇总：ProcessExit 不一定触发（注入 DLL 没有正常的卸载路径）
            ReportExceptionSummary("milestone");
        }
    }

    /// <summary>冷路径专用：把一段可能抛异常的诊断/挂钩代码包起来，出错只记账不抛出。</summary>
    private static void Safe(string site, Action action) {
        try {
            action();
        } catch (Exception e) {
            LogException(site, e);
        }
    }

    /// <summary>上报一行：连"上报失败"都要记数，避免日志静默地少一行。</summary>
    private static void TryReport(string message) {
        try {
            Goshujin.Report(message);
        } catch (Exception) {
            Interlocked.Increment(ref _excReportFailures);
        }
    }

    /// <summary>把每个 site 的异常计数汇总一行（会话结束 / 每 100 次异常时）。</summary>
    private static void ReportExceptionSummary(string where) {
        string detail;
        var total = 0;
        var sites = 0;
        try {
            var sb = new StringBuilder(256);
            using (_excGate.EnterScope()) {
                foreach (var pair in _excCounts) {
                    sb.Append(pair.Key).Append('=').Append(pair.Value).Append(' ');
                    total += pair.Value;
                }
                sites = _excCounts.Count;
            }
            detail = sb.ToString();
        } catch (Exception e) {
            LogException("ReportExceptionSummary:collect", e);
            return;
        }
        // 锁外再上报：Report 可能抛异常，而它内部还会走 LogException（会再拿同一把锁）
        try {
            Goshujin.Report($"EXCSUM [{where}] sites={sites} total={total} " +
                            $"reportFailures={Volatile.Read(ref _excReportFailures)} " +
                            $"pipeWriteFailures={Goshujin.WriteFailures} {detail}");
        } catch (Exception) {
            Interlocked.Increment(ref _excReportFailures);
        }
    }

    // ==================== 通用工具 ====================

    /// <summary>
    /// 校验 RVA 能不能当挂钩目标（A4）。顺序不能颠倒：
    ///   ① RVA 为 0 → 该服务器未定位，按设计跳过（不猜、不编造）；
    ///   ② 先用 PE 节表确认落在**可执行节**内 —— 游戏一更新 RVA 就整体位移，
    ///      旧 RVA 很可能落在数据节甚至模块外，直接解引用就是一次访问违例；
    ///   ③ 再验可读性（Native 的规矩）；
    ///   ④ 最后才做最小序言校验（函数开头的 push/sub/mov 前缀）。
    /// 任何一步失败都打日志说明"RVA 可能已过期"，绝不静默跳过。
    /// </summary>
    private static bool TryResolveTarget(string name, uint rva, out nint target) {
        target = 0;
        if (rva == 0) {
            Goshujin.Report($"[skip] {name}: RVA=0（该服务器未定位此钩子，按设计跳过）");
            return false;
        }
        if (_pe != null && !_pe.IsExecutableRva(rva)) {
            Goshujin.Report($"[skip] {name}: RVA 0x{rva:X} 不在可执行节内（RVA 可能已过期），跳过");
            return false;
        }
        var addr = _base + (int) rva;
        if (!Native.IsReadable(addr, 16)) {
            Goshujin.Report($"[skip] {name}: RVA 0x{rva:X} → 0x{addr:X} 不可读（RVA 可能已过期），跳过");
            return false;
        }
        var b0 = *(byte*) addr;
        // 序言判据见 Prologue.cs（抽出去是为了让单测能直接覆盖这段安全关键逻辑）
        if (!Prologue.LooksLikeFunctionEntry(new ReadOnlySpan<byte>((void*) addr, Prologue.WindowSize))) {
            Goshujin.Report($"[skip] {name}: RVA 0x{rva:X} → 0x{addr:X} 序言不像函数入口 b0=0x{b0:X2}（RVA 可能已过期），跳过");
            return false;
        }
        target = addr;
        return true;
    }

    /// <summary>地址是否落在主模块内（优先 PE 的 SizeOfImage，PE 解析失败才用兜底范围常量）。</summary>
    private static bool IsInExe(nint addr) =>
        _pe != null
            ? _pe.Contains(addr)
            : addr >= _base && addr < _base + (int) Offsets.FallbackModuleSize;

    private static string ReadIl2CppString(nint s) {
        if (s == 0) {
            return "(null)";
        }
        try {
            if (!Native.IsReadable(s, 0x18)) {
                return "(unreadable)";
            }
            var len = *(int*) (s + Offsets.StringLengthOffset);
            if (len is < 0 or > 1024) {
                return $"(bad len {len})";
            }
            if (!Native.IsReadable(s + Offsets.StringCharsOffset, len * 2)) {
                return "(unreadable chars)";
            }
            return new string((char*) (s + Offsets.StringCharsOffset), 0, len);
        } catch (Exception e) {
            LogException("ReadIl2CppString", e);
            return "(read error)";
        }
    }

    /// <summary>
    /// 记录当前正在播放的文件名（A2）。统一负责 <see cref="Path.GetFileName"/>。
    ///
    /// 为什么不能"解不出来就写 (null)"：密钥是 per-video 的，BCKEY 靠这个字段归属到视频；
    /// 一旦把不可用的解析结果写进去，后面所有 BCKEY 都会挂到 "(null)" 上 —— 实测日志里
    /// 60 条 BCKEY 全部 file=(null) 就是这个原因。所以解析失败时**保留上一次的有效名字**。
    ///
    /// 入参是已经解析好的托管字符串：调用点还要用它打 MANAFILE/DIAG 行，
    /// 传字符串可以避免同一个 path 被解析两次（每次都是一次堆分配）。
    /// </summary>
    private static string? SetCurrentFile(string raw) {
        // ReadIl2CppString 的失败哨兵都以 '(' 开头：(null)/(unreadable)/(bad len N)/(read error)
        if (raw.Length == 0 || raw[0] == '(') {
            return null;
        }
        var name = Path.GetFileName(raw);
        if (name.Length == 0) {
            return null;
        }
        // 跨线程访问：写用 Volatile.Write，读用 Volatile.Read（见 PublishBcKey）
        var previous = Volatile.Read(ref s_curFile);
        Volatile.Write(ref s_curFile, name);
        // 返回"确实换文件了"时的新名字：调用方据此决定要不要补报仍然生效的密钥
        return string.Equals(name, previous, StringComparison.Ordinal) ? null : name;
    }

    /// <summary>
    /// 这个字符串像不像一个 CRI Mana 视频路径（用于发现"NF 挂错函数"，**不参与归属判定**）。
    ///
    /// 判据刻意只有两条：① 不是解析失败哨兵（以 <c>'('</c> 开头）；② 以 <c>.usm</c> 结尾
    /// （大小写不敏感，实测报的是 <c>Cs_ZD_….usm</c>）。判据越宽越好 —— 它只用来写日志，
    /// 一旦误判成"不像"，代价是多一行 WRN，而不是丢名字。
    /// </summary>
    private static bool LooksLikeVideoPath(string raw) =>
        raw.Length > 4 && raw[0] != '(' && raw.EndsWith(".usm", StringComparison.OrdinalIgnoreCase);

    private static string HexOf(nint addr, int size) {
        if (addr == 0 || size <= 0 || !Native.IsReadable(addr, size)) {
            return "(unreadable)";
        }
        return Convert.ToHexString(new ReadOnlySpan<byte>((void*) addr, size));
    }

    /// <summary>
    /// 分块十六进制 dump（A11）：原来 klass dump 是**一行 3072 字符**，
    /// 启动器的行缓冲/日志查看器会把它截断，等于白 dump。按 ≤512 字符一行切。
    /// </summary>
    private static void DumpHexChunked(string tag, nint addr, int size) {
        if (addr == 0 || size <= 0 || !Native.IsReadable(addr, size)) {
            Goshujin.Report($"{tag} (unreadable)");
            return;
        }
        for (var offset = 0; offset < size; offset += Offsets.MaxHexDumpBytesPerLine) {
            var len = Math.Min(Offsets.MaxHexDumpBytesPerLine, size - offset);
            Goshujin.Report($"{tag} +0x{offset:X4} {Convert.ToHexString(new ReadOnlySpan<byte>((void*) (addr + offset), len))}");
        }
    }

    // ==================== 核心钩子（唯一的 il2cpp 钩子：NF = 文件名来源） ====================
    //
    // 为什么只有 1 个（实测 2026-10-16，v20 定稿）：
    //   7.1 的密钥只走 bcrypt 通路（BCKEY/BCENC），不经过任何托管/包装 API
    //  （原 S2/S3/N2/N3 四个 MANAKEY 钩子整场游戏 0 次调用，已随诊断一起删除）。
    //   NativeMethods_SetFile 提供"当前播放的视频文件名"，是密钥归属的唯一来源。

    private static delegate* unmanaged<int, nint, nint, void> _nf;

    /// <summary>
    /// 唯一的 il2cpp 钩子：<c>NativeMethods_SetFile(int, IntPtr, string)</c>。
    ///
    /// 它是"密钥 → 视频文件名"归属的唯一来源，而且实测在所有服务器/版本上都稳定触发
    /// （日志里的 <c>★ 文件 [i]: Cs_ZD_…</c> 就是它）。密钥本身来自 bcrypt 钩子（不在 il2cpp 段）。
    /// </summary>
    private static void AttachCore() {
        // GMK_STRICT=1 且"指纹已登记但不匹配" → 主动不挂。
        // 只有 Mismatch 才拦：Unregistered（例如国际服还没登记指纹）如果也拦，
        // 这个开关会让人一个钩子都挂不上，反而比不检查更糟。
        if (Options.StrictVersion && _versionState == VersionGuard.State.Mismatch) {
            Goshujin.Report("[skip] NativeMethods_SetFile: GMK_STRICT=1 且版本指纹不匹配 → " +
                            "不挂 NF（避免把补丁打到别的函数上）。跑 tools\\update_rva.cmd 迁移后重试");
            return;
        }
        if (TryResolveTarget("NativeMethods_SetFile", Rva.NativeSetFile, out var nf)) {
            Safe("AttachCore:NF", () => {
                delegate* unmanaged<int, nint, nint, void> h = &OnNativeSetFile;
                if (MinHook.Attach(nf, (nint) h, out var tr)) {
                    _nf = (delegate* unmanaged<int, nint, nint, void>) tr;
                    Goshujin.Report($"hook NativeMethods_SetFile @ 0x{nf:X}（文件名来源）");
                } else {
                    Goshujin.Report($"hook NativeMethods_SetFile 失败（MH 错误码 {MinHook.LastError}）");
                }
            });
        }
    }

    /// <summary>
    /// 原生 NativeMethods_SetFile(int playerIndex, IntPtr binder, string path)。
    /// 参数顺序已由实测日志确认（path 是第 3 个参数），而且它是**唯一在所有服务器/版本上
    /// 都稳定触发**的钩子 —— 所以文件名归属必须在这里也写一份（A2）。
    /// </summary>
    [UnmanagedCallersOnly]
    private static void OnNativeSetFile(int playerIndex, nint binder, nint path) {
        var original = _nf;
        try {
            if (original != null) {
                original(playerIndex, binder, path);
            }
        } catch (Exception e) {
            LogException("OnNativeSetFile:call", e);
        }

        // v16：播放已开始 → 允许记录 BCryptEncrypt（此前游戏遥测在播放前就把配额刷满了）
        Volatile.Write(ref _bcArm, 1);

        // ★ A2：先归属文件名，再上报 —— MANAFILE 与后续 BCKEY 必须是同一个文件
        var txt = ReadIl2CppString(path);
        var changedFile = SetCurrentFile(txt);

        try {
            Goshujin.Report($"MANAFILE [{playerIndex}] {txt}");
            // 名字形状自证：CRI Mana 只播 .usm，“拿到的名字不像视频文件”是 NF 挂错函数
            //（旧 RVA 恰好过了四道门）唯一能被被动发现的地方。**只观察、不改变归属行为** ——
            // 真正的拦截交给 --old-rva 重迁 + GMK_STRICT，这里绝不擅自丢文件名。
            // 放在 try 里：本文件铁律是任何回调都不得抛出未处理异常（NativeAOT 下会带走游戏）。
            if (!LooksLikeVideoPath(txt)) {
                var suspect = Interlocked.Increment(ref _nfSuspectCount);
                if (suspect <= 3) {
                    Goshujin.Report($"NFWARN #{suspect} 名字不像视频文件（NF 可能挂错函数）：{txt}");
                }
            }
            // 换了视频时把"仍然生效的那把"按新文件名补报一条 —— **默认关闭**（GMK_REUSE=1 才开）：
            // 实测每个视频都会自己重建密钥对象并报 BCKEY，补报只会在换新钥匙时抢跑误报（见 ReportInEffectKey）
            if (changedFile != null) {
                ReportInEffectKey(changedFile);
            }
            // bcrypt 未装上时的重试点：默认模式下这是唯一会触发的回调，而 Awake 只尝试一次
            //（v20 前重试点都在 GMK_FULL 的回调里）。幂等：已装好直接返回。
            if (Options.BcryptHook) {
                AttachBcrypt("OnSetFile");
            }
        } catch (Exception e) {
            LogException("OnNativeSetFile:report", e);
        }
    }

    // ==================== 钩 bcrypt.dll 拿 AES 密钥（A5） ====================
    //
    // 为什么可以钩：**bcrypt.dll 是 Windows 系统库**，不是米哈游的 cri_ware_unity.dll。
    // v4 的教训是挂钩 CRI DLL（游戏自有模块）会触发反作弊软响应 → 视频放不出来，
    // 所以这里刻意只碰系统库，CRI DLL 一个字节都不改。
    //
    // 依据：CRI 的 CriCipher 用 BCrypt + ChainingModeECB 自行构造 CTR 密钥流，
    // 因此 BCryptGenerateSymmetricKey 的 pbSecret/cbSecret 就是那 16 字节 AES key。

    private static nint _bcryptBase;

    /// <summary>0=未安装（可重试） 1=正在安装 2=已安装。bcrypt.dll 未加载时**不置为已安装**，留待重试。</summary>
    private static int _bcAttachState;
    private static int _cBcKey, _cBcKeyUnique, _cBcEnc, _cBcEncUnique, _bcArm;
    private static string? s_curFile;

    private static delegate* unmanaged<nint, nint, nint, uint, nint, uint, uint, int> _bcGenKey;
    private static delegate* unmanaged<nint, nint, uint, nint, nint, uint, nint, uint, nint, uint, int> _bcEnc;

    /// <summary>上次上报的密钥内容（替代原来的"总条数 ≤ 60"硬上限，A3）。</summary>
    private static readonly byte[] _lastBcKey = new byte[Offsets.MaxSecretBytes];
    private static int _lastBcKeyLen;
    private static int _bcKeyRepeat;
    private static int _bcKeyBusy;
    /// <summary>上一次上报的密钥是挂在哪个文件名下的（用来判断"换视频了但钥匙没换"）。</summary>
    private static string _lastBcKeyFile = "";
    /// <summary>"沿用上一次密钥"的补报计数（不是 BCrypt 事件，单独计数以免混淆）。</summary>
    private static int _cReuseKey;

    /// <summary>上次上报的 BCENC 内容指纹（IV + 输入前缀），A3。</summary>
    private static readonly byte[] _lastEncFingerprint = new byte[24];
    private static int _lastEncFingerprintLen;
    private static int _bcEncRepeat;
    private static int _bcEncBusy;

    /// <summary>
    /// 安装 bcrypt 钩子。
    ///
    /// A5 三处修正：
    ///   · 原来"先读标志 → 检查 → 安装 → 写标志"是典型的先检查后使用竞态，而这个方法会被
    ///     OnNativeSetFile 在游戏任意线程并发调用；
    ///     现在用 CompareExchange 抢一次性所有权，抢不到立刻返回。
    ///   · bcrypt.dll 未加载时**不**把状态置成"已安装"（旧代码只在最后统一置位，中途 return 也会
    ///     留下"未安装"，但异常抛出时状态会卡住）——这里用 try/finally 保证异常时状态可恢复重试。
    ///   · 安装仍然发生在 detour 内：硬性约束是"注入模块不得创建新线程"（实测只要新线程存在，
    ///     视频就放不出来）。所以这里刻意用 detour 线程做安装，代价是首次调用会慢一点。
    /// </summary>
    private static void AttachBcrypt(string site) {
        if (Volatile.Read(ref _bcAttachState) == 2) {
            return;
        }
        if (Interlocked.CompareExchange(ref _bcAttachState, 1, 0) != 0) {
            return;   // 已经有线程在装（或装好了），本次直接跳过
        }
        try {
            if (_bcryptBase == 0) {
                _bcryptBase = Native.FindModuleBase("bcrypt.dll");
            }
            if (_bcryptBase == 0) {
                Goshujin.Report($"BCRYPT [{site}] bcrypt.dll 未加载（保持未安装状态，后续钩子会重试）");
                return;
            }
            var pGen = Native.GetExportAddress(_bcryptBase, "BCryptGenerateSymmetricKey");
            var pEnc = Native.GetExportAddress(_bcryptBase, "BCryptEncrypt");
            Goshujin.Report($"BCRYPT [{site}] mod=0x{_bcryptBase:X} gen=0x{pGen:X} enc=0x{pEnc:X}");
            var installed = true;
            if (pGen != 0) {
                delegate* unmanaged<nint, nint, nint, uint, nint, uint, uint, int> h = &OnBcGenKey;
                if (MinHook.Attach(pGen, (nint) h, out var tr)) {
                    _bcGenKey = (delegate* unmanaged<nint, nint, nint, uint, nint, uint, uint, int>) tr;
                } else {
                    installed = false;
                    Goshujin.Report($"BCRYPT [{site}] BCryptGenerateSymmetricKey 挂钩失败（MH 错误码 {MinHook.LastError}）");
                }
            } else {
                installed = false;
            }
            if (pEnc != 0) {
                delegate* unmanaged<nint, nint, uint, nint, nint, uint, nint, uint, nint, uint, int> h2 = &OnBcEnc;
                if (MinHook.Attach(pEnc, (nint) h2, out var tr2)) {
                    _bcEnc = (delegate* unmanaged<nint, nint, uint, nint, nint, uint, nint, uint, nint, uint, int>) tr2;
                } else {
                    installed = false;
                    Goshujin.Report($"BCRYPT [{site}] BCryptEncrypt 挂钩失败（MH 错误码 {MinHook.LastError}）");
                }
            } else {
                installed = false;
            }
            if (installed) {
                Volatile.Write(ref _bcAttachState, 2);
                Goshujin.Report("BCRYPT 已挂钩（系统库 bcrypt.dll，未改动 CRI DLL）");
            }
        } catch (Exception e) {
            LogException("AttachBcrypt", e);
        } finally {
            // 没装成功（DLL 未加载 / 导出找不到 / 抛异常）→ 复位为"未安装"，
            // 让后续 OnNativeSetFile 等冷路径继续重试；绝不能停在"正在安装"把重试永久堵死。
            if (Volatile.Read(ref _bcAttachState) != 2) {
                Volatile.Write(ref _bcAttachState, 0);
            }
        }
    }

    [UnmanagedCallersOnly]
    private static int OnBcGenKey(nint hAlg, nint phKey, nint pbKeyObj, uint cbKeyObj,
        nint pbSecret, uint cbSecret, uint flags) {
        var g = _bcGenKey;
        var r = 0;
        try {
            if (g != null) {
                r = g(hAlg, phKey, pbKeyObj, cbKeyObj, pbSecret, cbSecret, flags);
            }
        } catch (Exception e) {
            LogException("OnBcGenKey:call", e);
        }

        // A3：原来的 `n <= 60` 是"总条数"上限，打满之后整段会话再没有一条 BCKEY
        //（实测日志正好停在 #60，而游戏随后又跑了 4 分钟 —— 之后的视频全部丢密钥）。
        // 改为内容变化才上报，同一把密钥最多重复 3 次（确认稳定），条数不再设上限。
        if (cbSecret is > 0 and <= Offsets.MaxSecretBytes && Native.IsReadable(pbSecret, (int) cbSecret)) {
            try {
                PublishBcKey(pbSecret, (int) cbSecret);
            } catch (Exception e) {
                LogException("OnBcGenKey:report", e);
            }
        }
        return r;
    }

    /// <summary>
    /// 密钥内容去重上报。用一次性所有权包住"比较 + 更新"：否则两个线程会同时判定
    /// "密钥变了"，同一把密钥被重复上报、repeat 计数也被各自重置（A3）。
    /// </summary>
    private static void PublishBcKey(nint pbSecret, int len) {
        if (Interlocked.CompareExchange(ref _bcKeyBusy, 1, 0) != 0) {
            return;   // 另一个线程正在处理，本次跳过（密钥没变的话下一个调用还会来）
        }
        try {
            var key = new ReadOnlySpan<byte>((void*) pbSecret, len);
            var file = Volatile.Read(ref s_curFile) ?? "?";
            var lastLen = Volatile.Read(ref _lastBcKeyLen);
            var keyChanged = lastLen != len || !key.SequenceEqual(new ReadOnlySpan<byte>(_lastBcKey, 0, len));
            // 归属文件也算"变化"：CRI 的 cipher 是全局单例，密钥对象会跨视频复用
            //（实测确认"有的视频密钥确实相同"），只看密钥内容的话，第二个同钥视频会被
            //「同一把最多报 3 次」整段压掉 —— 23:17 那段日志里 RTF_Girl 一条 BCKEY 都没有就是这个原因。
            var fileChanged = !string.Equals(file, _lastBcKeyFile, StringComparison.Ordinal);
            if (keyChanged) {
                key.CopyTo(_lastBcKey);
                Volatile.Write(ref _lastBcKeyLen, len);
                Interlocked.Increment(ref _cBcKeyUnique);
            }
            var changed = keyChanged || fileChanged;
            var repeat = changed ? 1 : Volatile.Read(ref _bcKeyRepeat) + 1;
            if (changed) {
                _lastBcKeyFile = file;
            }
            Volatile.Write(ref _bcKeyRepeat, repeat);
            var total = Interlocked.Increment(ref _cBcKey);
            if (repeat > Offsets.MaxKeyRepeatReports) {
                return;   // 同一「文件 + 密钥」已确认足够，之后只留计数
            }
            // 前缀与 #n/file=/len= 的位置保持不变（启动器按位置解析），新信息一律追加在末尾
            Goshujin.Report($"BCKEY #{total} file={file} len={len} {Convert.ToHexString(key)} " +
                            $"rep={repeat} uni={Volatile.Read(ref _cBcKeyUnique)}");
        } finally {
            Volatile.Write(ref _bcKeyBusy, 0);
        }
    }

    /// <summary>
    /// 把"当前仍然生效的密钥"按新文件名补报一条（带 <c>reuse=1</c> 标记）。
    ///
    /// **默认关闭**（<c>GMK_REUSE=1</c> 才启用），原因见 <see cref="Options.KeyReuse"/>：
    /// 实测每个视频开始时 CRI 都会重建一次密钥对象，BCKEY 那行自带文件名，补报是多余的；
    /// 而且在"下一个视频换新钥匙"时它会把**上一把**钥匙顶着新文件名报出去 ——
    /// 2026-10-16 23:35 的 <c>Cs_ZD_AQ70171401_UR_Girl</c> 先报了 F5AC（错）、同一秒再报 F9E9（对），
    /// 前台因此多出一条错误的"已配对"。
    ///
    /// 代码保留是为了极端场景兜底：万一某个视频一条 BCKEY 都没有，开 <c>GMK_REUSE=1</c>
    /// 就能用"此刻 cipher 单例里仍然生效的那把"把条目补上。
    /// </summary>
    private static void ReportInEffectKey(string file) {
        if (!Options.KeyReuse) {
            return;
        }
        if (Interlocked.CompareExchange(ref _bcKeyBusy, 1, 0) != 0) {
            return;   // 另一个线程正在处理，跳过（下一次 SetFile 还会来）
        }
        try {
            var len = Volatile.Read(ref _lastBcKeyLen);
            if (len <= 0 || len > Offsets.MaxSecretBytes) {
                return;   // 本会话还没抓到过密钥，没什么可补
            }
            if (string.Equals(file, _lastBcKeyFile, StringComparison.Ordinal)) {
                return;   // 就是抓到时那个文件，不必补
            }
            var key = new ReadOnlySpan<byte>(_lastBcKey, 0, len);
            var n = Interlocked.Increment(ref _cReuseKey);
            _lastBcKeyFile = file;          // 归属跟着新文件走（同一把再创建时按"文件变化"继续上报）
            Volatile.Write(ref _bcKeyRepeat, 1);
            Goshujin.Report($"BCKEY reuse#{n} file={file} len={len} {Convert.ToHexString(key)} " +
                            $"reuse=1 uni={Volatile.Read(ref _cBcKeyUnique)}");
        } finally {
            Volatile.Write(ref _bcKeyBusy, 0);
        }
    }

    [UnmanagedCallersOnly]
    private static int OnBcEnc(nint hKey, nint pbInput, uint cbInput, nint pPad,
        nint pbIV, uint cbIV, nint pbOut, uint cbOut, nint pcbRes, uint flags) {
        var e = _bcEnc;
        // v16 三重过滤（保留）：① SetFile 之后才记（遥测在播放前就刷屏）；
        // ② 长度是 16 的倍数（CRI 用 AES-ECB 加密 counter 块生成密钥流）；
        // ③ 输入不是可打印 ASCII（遥测输入是 "POST /collector/..." 这类文本）。
        var seq = 0;
        if (Volatile.Read(ref _bcArm) != 0 && cbInput > 0 && cbInput % 16 == 0 && cbInput <= 0x400000
            && !LooksLikeText(pbInput)) {
            try {
                seq = ClaimEncFingerprint(pbIV, cbIV, pbInput, cbInput);
            } catch (Exception ex) {
                LogException("OnBcEnc:fingerprint", ex);
            }
        }

        var r = 0;
        try {
            if (e != null) {
                r = e(hKey, pbInput, cbInput, pPad, pbIV, cbIV, pbOut, cbOut, pcbRes, flags);
            }
        } catch (Exception ex) {
            LogException("OnBcEnc:call", ex);
        }

        if (seq > 0) {
            try {
                var ivl = (int) Math.Min(cbIV, 16u);
                var inl = (int) Math.Min(cbInput, 32u);
                var outl = (int) Math.Min(cbOut, 32u);
                var iv = cbIV > 0 && Native.IsReadable(pbIV, ivl) ? HexOf(pbIV, ivl) : "-";
                var input = Native.IsReadable(pbInput, inl) ? HexOf(pbInput, inl) : "-";
                var output = cbOut > 0 && Native.IsReadable(pbOut, outl) ? HexOf(pbOut, outl) : "-";
                Goshujin.Report($"BCENC #{seq} cbIn={cbInput} cbIV={cbIV} IV={iv} IN={input} OUT={output} " +
                                $"rep={Volatile.Read(ref _bcEncRepeat)} uni={Volatile.Read(ref _cBcEncUnique)}");
            } catch (Exception ex) {
                LogException("OnBcEnc:report", ex);
            }
        }
        return r;
    }

    /// <summary>输入前 8 字节是否像可打印 ASCII（游戏遥测是文本，counter 块是二进制）。</summary>
    private static bool LooksLikeText(nint p) {
        if (!Native.IsReadable(p, 8)) {
            return false;
        }
        for (var i = 0; i < 8; i++) {
            var b = *(byte*) (p + i);
            if (b < 0x20 || b > 0x7E) {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// BCENC 内容指纹去重（A3）：IV + 输入前 8 字节。
    ///
    /// 为什么不拿整块输入做指纹：counter 的低位每块都递增（实测 IN 从 ...A6 一路涨到 ...BA），
    /// 整块比较等于"每个块都是新记录"，200 条总条数上限就是这样被打满的。
    /// 返回 0 = 本次不上报，否则返回上报序号。热路径：不分配任何堆内存。
    /// </summary>
    private static int ClaimEncFingerprint(nint pbIV, uint cbIV, nint pbInput, uint cbInput) {
        if (Interlocked.CompareExchange(ref _bcEncBusy, 1, 0) != 0) {
            return 0;   // 别的线程正在比较/更新指纹，本次放弃（下一个块还会来）
        }
        try {
            var ivLen = (int) Math.Min(cbIV, 16u);
            var inLen = (int) Math.Min(cbInput, 8u);
            if (ivLen > 0 && !Native.IsReadable(pbIV, ivLen)) {
                ivLen = 0;
            }
            if (!Native.IsReadable(pbInput, inLen)) {
                return 0;
            }
            Span<byte> fingerprint = stackalloc byte[24];
            fingerprint.Clear();
            for (var i = 0; i < ivLen; i++) {
                fingerprint[i] = *(byte*) (pbIV + i);
            }
            for (var i = 0; i < inLen; i++) {
                fingerprint[16 + i] = *(byte*) (pbInput + i);
            }
            var len = 16 + inLen;
            var lastLen = Volatile.Read(ref _lastEncFingerprintLen);
            var changed = lastLen != len
                || !fingerprint[..len].SequenceEqual(new ReadOnlySpan<byte>(_lastEncFingerprint, 0, len));
            int repeat;
            if (changed) {
                fingerprint[..len].CopyTo(_lastEncFingerprint);
                Volatile.Write(ref _lastEncFingerprintLen, len);
                Interlocked.Increment(ref _cBcEncUnique);
                repeat = 1;
            } else {
                repeat = Volatile.Read(ref _bcEncRepeat) + 1;
            }
            Volatile.Write(ref _bcEncRepeat, repeat);
            if (repeat > Offsets.MaxFingerprintRepeatReports) {
                return 0;
            }
            // 上限是"唯一记录数"，不是总条数 —— 不同视频的 counter 基值不同，会各留一条
            if (Volatile.Read(ref _cBcEncUnique) > Offsets.MaxEncUniqueRecords) {
                return 0;
            }
            return Interlocked.Increment(ref _cBcEnc);
        } finally {
            Volatile.Write(ref _bcEncBusy, 0);
        }
    }

    // ==================== CRI FS 就地解密回调捕获（默认关闭，见 GMK_FS） ====================
    //
    // v3 教训：
    //   1. GetModuleHandleW 在游戏进程内被反作弊屏蔽 → 侦察线程永远找不到 cri_ware_unity.dll，
    //      必须用 Native.FindModuleBase（PEB 遍历）。
    //   2. "视频播放不了"的最可疑原因：大面积 il2cpp 代码补丁触发反作弊软响应。
    //   3. 回调 detour 若声明为 void 返回，真回调返回 BOOL 时返回值被毁 → 解密失败。
    //      所以回调 detour 改为 nint 返回并透传原函数结果。

    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> _fsSetDecCb;
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, nint> _fsDecCbTrampoline;

    private static nint _criModule;          // cri_ware_unity.dll 基址
    private static PeImage? _criPe;          // 同一模块的节表（LocateAddress 用 SizeOfImage）
    private static nint _fsDecCb;            // 游戏注册的解密回调
    private static int _fsRegCount, _fsCbCount;
    private static int _fsAttachState;       // 0=待捕获 1=已捕获待挂钩 2=已挂/已放弃

    /// <summary>
    /// FS 侦察线程体（仅 GMK_FS=1 时启动）。外面多包一层捕获：.NET Core 语义下
    /// **任何线程**上的未处理异常都会直接终止进程，侦察线程更不该有这种能力。
    /// </summary>
    private static void FsWatcherLoop() {
        try {
            FsWatcherLoopCore();
        } catch (Exception e) {
            LogException("FsWatcherLoop", e);
        }
    }

    private static void FsWatcherLoopCore() {
        Safe("FsWatcher:enter", () => Goshujin.Report("FSWATCH: 线程已进入"));
        // 1) 等 cri_ware_unity.dll 被加载（PEB 遍历，GetModuleHandle 被反作弊屏蔽不可用）
        nint mod = 0;
        for (var i = 0; i < 3000 && mod == 0; i++) {           // 最多 ~10 分钟
            Thread.Sleep(200);
            mod = Native.FindModuleBase("cri_ware_unity.dll");
        }
        if (mod == 0) {
            Safe("FsWatcher:timeout", () => Goshujin.Report("FSWATCH: cri_ware_unity.dll 未加载，放弃"));
            return;
        }
        _criModule = mod;
        if (PeImage.TryCreate(mod, out var criPe)) {
            _criPe = criPe;
        }
        Safe("FsWatcher:loaded", () => Goshujin.Report($"FSWATCH: cri_ware_unity.dll @ 0x{mod:X}"));

        var proc = Native.GetExportAddress(mod, "criFsLoader_SetInplaceDecryptionCbFunc");
        if (proc == 0) {
            Safe("FsWatcher:noexport", () => Goshujin.Report("FSWATCH: 无 criFsLoader_SetInplaceDecryptionCbFunc 导出"));
            return;
        }
        Safe("FsWatcher:export", () => Goshujin.Report($"FSWATCH: criFsLoader_SetInplaceDecryptionCbFunc @ 0x{proc:X}"));
        delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> h = &OnFsSetDecCb;
        if (!MinHook.Attach(proc, (nint) h, out var tr)) {
            Safe("FsWatcher:attach", () => Goshujin.Report($"FSWATCH: 注册函数挂钩失败（MH 错误码 {MinHook.LastError}）"));
            return;
        }
        _fsSetDecCb = (delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void>) tr;
        Safe("FsWatcher:attached", () => Goshujin.Report("FSWATCH: 注册函数已挂钩"));

        // 2) 等游戏注册回调 → 挂回调本身（拿明文/密文对 + 回调代码归属）
        for (var i = 0; i < 3000 && Volatile.Read(ref _fsAttachState) == 0; i++) {
            Thread.Sleep(200);
        }
        if (Volatile.Read(ref _fsAttachState) != 1) {
            return;   // 没等到注册
        }
        Thread.Sleep(300);                                     // 稳一下
        var cb = Volatile.Read(ref _fsDecCb);
        delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, nint> h2 = &OnFsDecCb;
        if (MinHook.Attach(cb, (nint) h2, out var tr2)) {
            _fsDecCbTrampoline = (delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, nint>) tr2;
            Volatile.Write(ref _fsAttachState, 2);
            Safe("FsWatcher:cb", () => Goshujin.Report($"FSWATCH: 解密回调已挂钩 @ 0x{cb:X}"));
        } else {
            Volatile.Write(ref _fsAttachState, 2);
            Safe("FsWatcher:cbfail", () => Goshujin.Report($"FSWATCH: 回调挂钩失败（MH 错误码 {MinHook.LastError}）"));
        }
    }

    /// <summary>回调地址落在哪个模块（exe / cri dll / 其它），模块范围优先由 PE 节表派生。</summary>
    private static string LocateAddress(nint addr) {
        if (IsInExe(addr)) {
            return $"exe+0x{addr - _base:X}";
        }
        var criSize = _criPe != null ? (nint) _criPe.SizeOfImage : (nint) Offsets.CriModuleFallbackSize;
        if (_criModule != 0 && addr >= _criModule && addr < _criModule + criSize) {
            return $"cri+0x{addr - _criModule:X}";
        }
        return "?";
    }

    [UnmanagedCallersOnly]
    private static void OnFsSetDecCb(nint loader, nint cbfunc, nint udata, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _fsSetDecCb;
        try {
            if (original != null) {
                original(loader, cbfunc, udata, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnFsSetDecCb:call", e);
        }
        try {
            var n = Interlocked.Increment(ref _fsRegCount);
            // code 前 0x100 字节：够静态识别 reverse-pinvoke 包装并定位托管方法
            Goshujin.Report($"FSREG #{n} loader=0x{loader:X} cbfunc=0x{cbfunc:X} [{LocateAddress(cbfunc)}] udata=0x{udata:X}");
            DumpHexChunked($"FSREGCODE #{n}", cbfunc, 0x100);
            if (cbfunc != 0 && Interlocked.CompareExchange(ref _fsDecCb, cbfunc, 0) == 0) {
                Volatile.Write(ref _fsAttachState, 1);         // 通知 watcher 去挂回调
            }
        } catch (Exception e) {
            LogException("OnFsSetDecCb:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static nint OnFsDecCb(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var t = _fsDecCbTrampoline;
        var n = Interlocked.Increment(ref _fsCbCount);
        var report = n <= 16;
        string? pre2 = null;
        string? pre3 = null;
        if (report) {
            pre2 = HexOf(a2, 0x30);
            pre3 = HexOf(a3, 0x30);
        }
        nint result = 0;
        try {
            if (t != null) {
                result = t(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnFsDecCb:call", e);
        }
        if (report) {
            try {
                Goshujin.Report($"FSCALL #{n} a1=0x{a1:X} a2=0x{a2:X} a3=0x{a3:X} a4=0x{a4:X} a5=0x{a5:X} ret=0x{result:X}");
                Goshujin.Report($"  pre  a2={pre2}  a3={pre3}");
                Goshujin.Report($"  post a2={HexOf(a2, 0x30)}  a3={HexOf(a3, 0x30)}");
            } catch (Exception e) {
                LogException("OnFsDecCb:report", e);
            }
        }
        return result;
    }

}
