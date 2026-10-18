using System.Runtime.InteropServices;
using System.Text;
using GenshinSniffer.Utilities;

namespace GenshinSniffer;

/// <summary>
/// GenshinManaKey 注入 DLL —— 截获原神（hk4e）7.1 过场动画的 CRI Mana 解密密钥。
///
/// === 本版（v19）相对上一版的改动要点 ===
///   · **默认只挂 1 个 il2cpp 钩子**（NF = NativeMethods_SetFile，文件名来源）。
///     实测证据（2026-10-16 多轮日志）：默认运行原先挂的 5 个 il2cpp 钩子里，S2/S3/N2/N3
///     指向的方法确实存在，但**整场游戏 0 次调用**（MANAKEY2/3/N2/N3 一条都没有）——
///     7.1 的 CRI 解密走原生 + bcrypt 通路（BCKEY/BCENC）。这 4 个已移到 GMK_FULL=1 下
///     （AttachManaKeyHooks），默认 il2cpp 补丁面积从 5 处降到 1 处。
///   · 顺带修正两处 RVA（见 RvaSet 注释）：S3 国服 0x07054B80→0x070548F0（旧值其实是
///     Player.UpdateWithUserTime）、Unk5/Unk6 各 -0x10（旧值落在函数中间）。
///   · 诊断钩子必须 GMK_FULL=1 —— v4 起的设计，上个版本 Awake 无条件调用 AttachDiagnostics
///     把它架空了（默认运行 14 处 il2cpp 补丁，而 v3 已实测大面积补丁会让视频放不出来）。
///   · 文件名归属：CRI Mana 的托管签名是 SetFile(CriFsBinder binder, string fileName)，
///     arg0=this / arg1=binder / arg2=path。旧代码把 binder 当 path，托管侧文件名永远是 (null)；
///     现在两处（托管 + 原生）都写 s_curFile，且解析失败时**保留上一次的有效名字**。
///   · BCKEY/BCENC 不再有"总条数上限"：密钥是 per-video 的，总条数上限等于"第 N 个视频之后全丢密钥"。
///   · RVA 校验先走 PE 节表（可执行节）+ 可读性，绝不直接解引用过期 RVA（那是一次访问违例）。
///   · 国际服走独立常量集（只填 README 表格里的 5 个 MANAKEY/文件名 RVA），其余一律 0 = 跳过。
///
/// 目标客户端：国服 YuanShen.exe / 国际服 GenshinImpact.exe。
///
/// 上报协议（前缀与字段位置不得改动，启动器按它解析；0xFC/0xFD/0xFE 语义由 Goshujin 负责）：
///   MANAFILE  [i] &lt;路径&gt;                NativeMethods_SetFile（native 层，带 playerIndex）★ 默认就挂
///   MANAFILE2 &lt;路径&gt;                    SetFile（托管层，兜底，仅 GMK_FULL=1）
///   MANAKEY2  {video:X16} {audio:X16}     托管 SetVideoAudioDecryptionKeys（仅 GMK_FULL=1，实测 0 次）
///   MANAKEY3  {audio:X16} AES={hex}       托管 SetVideoAesKeyAudioDecryptionKey（同上）
///   MANAKEYN2 [i] {video:X16} {audio:X16} NativeMethods_SetVideoAudioDecryptionKeys（同上）
///   MANAKEYN3 [i] {audio:X16} AES={hex}   NativeMethods_SetVideoAesKeyAudioDecryptionKey（同上）
///   OBJKEY / OBJDMP / DIAG / BCKEY / BCENC / DECKEY / EXC   诊断行（launcher 当普通日志打印）
///
/// 铁律：任何回调都不得抛出未处理异常 —— NativeAOT 下会直接带走整个游戏进程。
/// 因此所有 catch 都是"全捕获 + LogException"：捕获是为了活着，上报是为了**看得见**
/// （旧版 71 处 `catch { }` 让日志里什么都看不到，出问题只能靠猜）。
/// </summary>
internal static unsafe class Application {

    private static bool _initialized;
    private static nint _base;
    private static PeImage? _pe;
    private static RvaSet? _selected;
    private static string _mainModuleName = "(未识别)";

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
    /// </summary>
    private sealed class RvaSet {
        public string Name = "";
        // —— 默认只挂 NF；下面 4 个 MANAKEY 只在 GMK_FULL=1 时挂 ——
        // 这 4 个的 RVA 都有依据（国服/国际服两套表格交叉验证过），但**实测一次都没被调用**
        //（2026-10-16 那几轮：MANAKEY2/3/N2/N3 全部 0 条，真正产出密钥的是 bcrypt 通路）。
        // 所以它们从默认集合里移出去，默认 il2cpp 补丁从 5 处降到 1 处；留着是为了 GMK_FULL=1 时诊断。
        public uint SetVideoAudioKeys;          // S2 托管（GMK_FULL 诊断）
        public uint SetVideoAesKeyAudio;        // S3 托管（GMK_FULL 诊断）
        public uint NativeSetVideoAudioKeys;    // N2 原生包装（GMK_FULL 诊断）
        public uint NativeSetVideoAesKeyAudio;  // N3 原生包装（GMK_FULL 诊断）
        public uint NativeSetFile;              // NF ★文件名来源，默认唯一挂的 il2cpp 钩子
        // —— 诊断钩子（仅 GMK_FULL=1 时挂）——
        public uint ManagedSetFile;
        public uint Unk5;
        public uint Unk6;
        public uint KeyFeed;
        public uint DecrypterInitConfig;
        public uint DecrypterInit2;
        public uint DecrypterNative;
        public uint PluginSetConfigParams;
        public uint PluginSetConfigAdditional;
    }

    /// <summary>
    /// 国服 7.1（YuanShen.exe）。7.1 的值已用「国际服 7.1 全量 idx→RVA 表 + 国服实测锚点标定位移 0x3120」
    /// 逐个反查确认（见 README「实际起作用的钩子」）：NF/S2/N2/N3 都对，S3 之前错指到
    /// <c>Player.UpdateWithUserTime</c>，已改回真正的 <c>SetVideoAesKeyAudioDecryptionKey</c>。
    /// </summary>
    private static readonly RvaSet Cn = new() {
        Name = "国服 YuanShen.exe 7.1",
        SetVideoAudioKeys = 0x070546F0,
        SetVideoAesKeyAudio = 0x070548F0,
        NativeSetVideoAudioKeys = 0x070547F0,
        NativeSetVideoAesKeyAudio = 0x07054A70,
        NativeSetFile = 0x070538C0,
        ManagedSetFile = 0x07053800,            // 托管 SetFile = Player.SetFile(CriFsBinder, string, SetMode)
        Unk5 = 0x07057BF0,                      // 已用异常目录边界表核过：确实是函数起点（size 133），但没定性
        Unk6 = 0x07057C80,                      // 同上（size 141）；两者都只在 GMK_FULL=1 时挂
        KeyFeed = 0x06C4EA80,                   // key 管理器小方法（this=manager, +0x50=binder）
        DecrypterInitConfig = 0x06FE9890,       // CriWareDecrypter.Initialize(Config)
        DecrypterInit2 = 0x06FE98C0,
        DecrypterNative = 0x06FE9C10,
        PluginSetConfigParams = 0x06F54B70,
        PluginSetConfigAdditional = 0x06F54D40,
    };

    /// <summary>
    /// 国际服 GenshinImpact.exe。来源：README 的 RVA 表（= 国际服 7.1 全量 idx→RVA 表直接读出来的值）
    /// —— 只有这 5 个 MANAKEY/文件名 RVA 有依据，其余诊断项一律 0（未定位 = 跳过），绝不照搬国服偏移。
    /// 其中 S3 的旧值 0x07051A60 实际是 UpdateWithUserTime，已改为真正的 0x070517D0。
    /// </summary>
    private static readonly RvaSet Gl = new() {
        Name = "国际服 GenshinImpact.exe（仅 5 个 MANAKEY/文件名 RVA 已定位，诊断项全部未知）",
        SetVideoAudioKeys = 0x070515D0,
        SetVideoAesKeyAudio = 0x070517D0,
        NativeSetVideoAudioKeys = 0x070516D0,
        NativeSetVideoAesKeyAudio = 0x07051950,
        NativeSetFile = 0x070507A0,
        // ManagedSetFile / Unk5 / Unk6 / KeyFeed / Decrypter* / Plugin* 全部保持 0
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
            // 开关组合先落日志：事后翻日志时"这轮到底开没开 GMK_FULL"是最常见的问题（A13）
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

            // A1：诊断钩子必须真正被门控 —— 诊断钩子会显著扩大 il2cpp 代码补丁面积，
            // 而 v3 实测"大面积补丁 → 视频放不出来"（疑似反作弊代码完整性检测的软响应）。
            if (Options.FullDiagnostics) {
                Goshujin.Report("诊断钩子已启用（GMK_FULL=1，补丁面积大，可能影响播放）");
                AttachDiagnostics();
            } else {
                Goshujin.Report("诊断钩子未启用（默认只挂 1 个 il2cpp 钩子：NativeMethods_SetFile（文件名来源）"
                                + " + bcrypt 的 2 个导出钩子；4 个 MANAKEY 钩子实测 0 次调用，要诊断请设 GMK_FULL=1）");
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

    /// <summary>
    /// il2cpp 代码段范围（判定 klass.methods 里的方法指针是否可信）。
    /// A6：能由节表派生就不写死 —— 只有解析不出 il2cpp 节时才退回上游的经验值。
    /// </summary>
    private static void GetIl2CppRange(out nint low, out nint high) {
        if (_pe != null && _pe.TryGetSectionRange(Offsets.Il2CppSectionName, out low, out high)) {
            return;
        }
        low = _base + (int) Offsets.FallbackIl2CppStart;
        high = _base + (int) Offsets.FallbackIl2CppEnd;
    }

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

    private static string ReadIl2CppByteArrayHex(nint arr) {
        if (arr == 0) {
            return "";
        }
        try {
            if (!Native.IsReadable(arr, 0x20)) {
                return "(unreadable)";
            }
            var len = *(uint*) (arr + Offsets.ArrayLengthOffset);
            if (len is > 0 and <= 64 && Native.IsReadable(arr + Offsets.ArrayDataOffset, (int) len)) {
                return Convert.ToHexString(new ReadOnlySpan<byte>((void*) (arr + Offsets.ArrayDataOffset), (int) len));
            }
            return $"len={len}";
        } catch (Exception e) {
            LogException("ReadIl2CppByteArrayHex", e);
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

    /// <summary>
    /// 逐线程复用的 StringBuilder（A11）：诊断 dump 每个 class 都要拼 160 个方法 RVA，
    /// 每次 new 一个纯属浪费；但共享一个又会被并发 dump 互相踩，所以按线程持有。
    /// </summary>
    [ThreadStatic]
    private static StringBuilder? _scratch;

    private static StringBuilder Scratch {
        get {
            var sb = _scratch;
            if (sb == null) {
                sb = new StringBuilder(1024);
                _scratch = sb;
            }
            return sb;
        }
    }

    /// <summary>
    /// 扫描对象字段，找出「看起来像字节数组的密钥」：指向的 Il2CppArray 头部长度 8/16/24/32 且数据非全零。
    /// 同时 dump 对象前 0x80 字节，便于人工核对。
    ///
    /// 受 GMK_FULL 与调用方计数器双重约束（A11），且同一个内存区域只查一次 VirtualQuery。
    /// </summary>
    private static void ScanObjectForKeys(string tag, nint obj, int maxOff = Offsets.ObjectMaxScanOffset) {
        if (!Options.FullDiagnostics || obj == 0) {
            return;
        }
        if (!Native.TryQueryRegion(obj, out var objRegion) || !Native.IsReadableIn(in objRegion, obj, 0x20)) {
            return;
        }
        try {
            if (Native.IsReadableIn(in objRegion, obj, 0x80)) {
                DumpHexChunked($"OBJDMP {tag} obj=0x{obj:X}", obj, 0x80);
            }
            for (var off = 0x10; off <= maxOff; off += 8) {
                // 字段槽在对象体内，几乎总落在同一个区域 → 复用上面那一次 VirtualQuery
                if (!Native.IsReadableIn(in objRegion, obj + off, 8)) {
                    continue;
                }
                var p = *(nint*) (obj + off);
                if (p == 0) {
                    continue;
                }
                if (!Native.TryQueryRegion(p, out var arrayRegion) || !Native.IsReadableIn(in arrayRegion, p, 0x28)) {
                    continue;
                }
                var len = *(uint*) (p + Offsets.ArrayLengthOffset);
                if (len is not (8 or 16 or 24 or 32)) {
                    continue;
                }
                if (!Native.IsReadableIn(in arrayRegion, p + Offsets.ArrayDataOffset, (int) len)) {
                    continue;
                }
                var span = new ReadOnlySpan<byte>((void*) (p + Offsets.ArrayDataOffset), (int) len);
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
            }
        } catch (Exception e) {
            LogException("ScanObjectForKeys", e);
        }
    }

    /// <summary>
    /// 启发式定位对象的 Il2CppClass.methods：扫 klass 内 8 对齐字段，找「指向指针数组、
    /// 且数组前 4 项都是 MethodInfo*（其 +0x0 是 il2cpp 段函数指针）」的槽位，把方法 RVA 全列出来。
    /// </summary>
    private static void DumpClassMethods(string tag, nint obj) {
        if (!Options.FullDiagnostics || obj == 0) {
            return;
        }
        try {
            if (!Native.TryReadPtr(obj, out var klass) || klass == 0) {
                return;
            }
            if (!Native.IsReadable(klass, Offsets.KlassMaxOffset)) {
                Goshujin.Report($"{tag}KLASS klass=0x{klass:X}（不可读，跳过 dump）");
                return;
            }
            Goshujin.Report($"{tag}KLASS klass=0x{klass:X}");
            // 原始 klass 字节（离线解析 methods 数组，启发式失败时的兜底）
            DumpHexChunked($"{tag}KLASSDUMP", klass, Offsets.KlassMaxOffset);

            GetIl2CppRange(out var low, out var high);
            var sb = Scratch;
            for (var off = Offsets.KlassMethodsScanStart; off <= Offsets.KlassMethodsScanEnd; off += 8) {
                if (!Native.TryReadPtr(klass + off, out var arr) || arr == 0 || !Native.IsReadable(arr, 16)) {
                    continue;
                }
                var plausible = 0;
                for (var i = 0; i < 4; i++) {
                    if (!Native.TryReadPtr(arr + 8 * i, out var mi) || mi == 0 || !Native.IsReadable(mi, 8)) {
                        break;
                    }
                    if (!Native.TryReadPtr(mi, out var mp) || mp < low || mp >= high) {
                        break;
                    }
                    plausible++;
                }
                if (plausible < 2) {
                    continue;
                }
                sb.Clear();
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
                Goshujin.Report($"{tag}METHODS off=0x{off:X} ok={plausible} n={n}");
                for (var s = 0; s < sb.Length; s += Offsets.MaxMethodCharsPerLine) {
                    var len = Math.Min(Offsets.MaxMethodCharsPerLine, sb.Length - s);
                    Goshujin.Report($"{tag}M{s / Offsets.MaxMethodCharsPerLine} {sb.ToString(s, len)}");
                }
            }
        } catch (Exception e) {
            LogException("DumpClassMethods", e);
        }
    }

    /// <summary>
    /// 通用挂钩：宽签名（8 参数）。真实参数更少时被调方忽略多余的，安全。
    /// 返回 null 表示没挂上（RVA=0 / 校验失败 / MinHook 失败），调用方据此跳过。
    /// </summary>
    private static delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> AttachWide(
        string name, uint rva, delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void> handler) {
        if (!TryResolveTarget(name, rva, out var target)) {
            return null;
        }
        if (!MinHook.Attach(target, (nint) handler, out var trampoline)) {
            Goshujin.Report($"[skip] {name}: MinHook 安装失败（MH 错误码 {MinHook.LastError}）");
            return null;
        }
        Goshujin.Report($"hook {name} @ 0x{target:X}");
        return (delegate* unmanaged<nint, nint, nint, nint, nint, nint, nint, nint, void>) trampoline;
    }

    // ==================== 核心钩子：默认**只挂 1 个**（NF = 文件名来源） ====================
    //
    // 为什么砍到 1 个（实测 2026-10-16）：
    //   默认运行的 5 个 il2cpp 补丁里只有 NativeMethods_SetFile 真正需要 —— 它提供"当前播放的视频
    //   文件名"，是密钥归属的唯一来源（MANAFILE）。另外 4 个 MANAKEY（S2/S3/N2/N3）指向的方法确实
    //   存在、也确实标对了（用国际服 7.1 全量 idx→RVA 表 + 国服实测锚点标定位移 0x3120 反查过），
    //   但**整场游戏一次都没被调用**（MANAKEY2/3/N2/N3 = 0 条）：7.1 的 CRI 解密走原生 + bcrypt
    //   通路（BCKEY/BCENC），不经这层托管 API。
    //   少挂 4 个 il2cpp 补丁 = 默认补丁面积降到 1/5，直接降低"补丁被完整性检测/影响播放"的风险。
    //   需要它们做诊断时设 GMK_FULL=1（见 AttachManaKeyHooks）。

    private static delegate* unmanaged<nint, ulong, ulong, void> _mvak;
    private static delegate* unmanaged<nint, nint, ulong, void> _mvaak;
    private static delegate* unmanaged<int, ulong, ulong, void> _nvak;
    private static delegate* unmanaged<int, nint, ulong, void> _nvaak;
    private static delegate* unmanaged<int, nint, nint, void> _nf;

    /// <summary>
    /// 4 个 MANAKEY 钩子（S2/S3/N2/N3）—— **只在 GMK_FULL=1 时挂**。
    ///
    /// 它们本该是"设密钥"的托管/原生入口，但实测 0 次调用（默认运行的日志里 MANAKEY* 一条都没有）。
    /// 保留的原因：万一某个版本又走回托管通路，GMK_FULL=1 一开就能立刻看见，不必重新逆向。
    ///
    /// ★ S3 的国服值 2026-10-18 修正过：旧值 0x07054B80 经反查其实是 <c>Player.UpdateWithUserTime</c>
    ///（会把补丁打到无关函数上），真正的 <c>SetVideoAesKeyAudioDecryptionKey</c> 是 0x070548F0。
    /// </summary>
    private static void AttachManaKeyHooks() {
        if (TryResolveTarget("SetVideoAudioDecryptionKeys", Rva.SetVideoAudioKeys, out var t2)) {
            Safe("AttachCore:S2", () => {
                delegate* unmanaged<nint, ulong, ulong, void> h = &OnManagedVideoAudioKeys;
                if (MinHook.Attach(t2, (nint) h, out var tr)) {
                    _mvak = (delegate* unmanaged<nint, ulong, ulong, void>) tr;
                    Goshujin.Report($"hook SetVideoAudioDecryptionKeys @ 0x{t2:X}");
                } else {
                    Goshujin.Report($"hook SetVideoAudioDecryptionKeys 失败（MH 错误码 {MinHook.LastError}）");
                }
            });
        }

        if (TryResolveTarget("SetVideoAesKeyAudioDecryptionKey", Rva.SetVideoAesKeyAudio, out var t3)) {
            Safe("AttachCore:S3", () => {
                delegate* unmanaged<nint, nint, ulong, void> h = &OnManagedVideoAesKeyAudio;
                if (MinHook.Attach(t3, (nint) h, out var tr)) {
                    _mvaak = (delegate* unmanaged<nint, nint, ulong, void>) tr;
                    Goshujin.Report($"hook SetVideoAesKeyAudioDecryptionKey @ 0x{t3:X}");
                } else {
                    Goshujin.Report($"hook SetVideoAesKeyAudioDecryptionKey 失败（MH 错误码 {MinHook.LastError}）");
                }
            });
        }

        if (TryResolveTarget("NativeMethods_SetVideoAudioDecryptionKeys", Rva.NativeSetVideoAudioKeys, out var n2)) {
            Safe("AttachCore:N2", () => {
                delegate* unmanaged<int, ulong, ulong, void> h = &OnNativeVideoAudioKeys;
                if (MinHook.Attach(n2, (nint) h, out var tr)) {
                    _nvak = (delegate* unmanaged<int, ulong, ulong, void>) tr;
                    Goshujin.Report($"hook NativeMethods_SetVideoAudioDecryptionKeys @ 0x{n2:X}");
                } else {
                    Goshujin.Report($"hook NativeMethods_SetVideoAudioDecryptionKeys 失败（MH 错误码 {MinHook.LastError}）");
                }
            });
        }

        if (TryResolveTarget("NativeMethods_SetVideoAesKeyAudioDecryptionKey2", Rva.NativeSetVideoAesKeyAudio, out var n3)) {
            Safe("AttachCore:N3", () => {
                delegate* unmanaged<int, nint, ulong, void> h = &OnNativeVideoAesKeyAudio;
                if (MinHook.Attach(n3, (nint) h, out var tr)) {
                    _nvaak = (delegate* unmanaged<int, nint, ulong, void>) tr;
                    Goshujin.Report($"hook NativeMethods_SetVideoAesKeyAudioDecryptionKey2 @ 0x{n3:X}");
                } else {
                    Goshujin.Report($"hook NativeMethods_SetVideoAesKeyAudioDecryptionKey2 失败（MH 错误码 {MinHook.LastError}）");
                }
            });
        }
    }

    /// <summary>
    /// 默认运行的**唯一** il2cpp 钩子：<c>NativeMethods_SetFile(int, IntPtr, string)</c>。
    ///
    /// 它是"密钥 → 视频文件名"归属的唯一来源，而且实测在所有服务器/版本上都稳定触发
    /// （日志里的 <c>★ 文件 [i]: Cs_ZD_…</c> 就是它）。密钥本身来自 bcrypt 钩子（不在 il2cpp 段）。
    /// </summary>
    private static void AttachCore() {
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

    [UnmanagedCallersOnly]
    private static void OnManagedVideoAudioKeys(nint self, ulong videoKey, ulong audioKey) {
        var original = _mvak;
        try {
            if (original != null) {
                original(self, videoKey, audioKey);
            }
        } catch (Exception e) {
            LogException("OnManagedVideoAudioKeys:call", e);
        }
        try {
            Goshujin.Report($"MANAKEY2 {videoKey:X16} {audioKey:X16}");
        } catch (Exception e) {
            LogException("OnManagedVideoAudioKeys:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnManagedVideoAesKeyAudio(nint self, nint aesArray, ulong audioKey) {
        var original = _mvaak;
        try {
            if (original != null) {
                original(self, aesArray, audioKey);
            }
        } catch (Exception e) {
            LogException("OnManagedVideoAesKeyAudio:call", e);
        }
        try {
            Goshujin.Report($"MANAKEY3 {audioKey:X16} AES={ReadIl2CppByteArrayHex(aesArray)}");
        } catch (Exception e) {
            LogException("OnManagedVideoAesKeyAudio:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnNativeVideoAudioKeys(int playerIndex, ulong videoKey, ulong audioKey) {
        var original = _nvak;
        try {
            if (original != null) {
                original(playerIndex, videoKey, audioKey);
            }
        } catch (Exception e) {
            LogException("OnNativeVideoAudioKeys:call", e);
        }
        try {
            Goshujin.Report($"MANAKEYN2 [{playerIndex}] {videoKey:X16} {audioKey:X16}");
        } catch (Exception e) {
            LogException("OnNativeVideoAudioKeys:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnNativeVideoAesKeyAudio(int playerIndex, nint aesArray, ulong audioKey) {
        var original = _nvaak;
        try {
            if (original != null) {
                original(playerIndex, aesArray, audioKey);
            }
        } catch (Exception e) {
            LogException("OnNativeVideoAesKeyAudio:call", e);
        }
        try {
            Goshujin.Report($"MANAKEYN3 [{playerIndex}] {audioKey:X16} AES={ReadIl2CppByteArrayHex(aesArray)}");
        } catch (Exception e) {
            LogException("OnNativeVideoAesKeyAudio:report", e);
        }
    }

    private static int _cSetFileN;

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
            // 换了视频时把"仍然生效的那把"按新文件名补报一条 —— **默认关闭**（GMK_REUSE=1 才开）：
            // 实测每个视频都会自己重建密钥对象并报 BCKEY，补报只会在换新钥匙时抢跑误报（见 ReportInEffectKey）
            if (changedFile != null) {
                ReportInEffectKey(changedFile);
            }
            var n = Interlocked.Increment(ref _cSetFileN);
            if (Options.FullDiagnostics && n <= 10) {
                ScanObjectForKeys($"SetFileBinder[{playerIndex}]", binder, 0x300);
                Goshujin.Report($"BINDERDUMP {HexOf(binder, 0x100)}");
                if (n <= 3) {
                    DumpClassMethods($"BINDER{playerIndex}_", binder);
                    Goshujin.Report($"CONST{Offsets.ConstProbe5784500:X} {HexOf(_base + (int) Offsets.ConstProbe5784500, 0x40)}");
                }
            }
            // DECKEY 是核心产出（不是诊断），任何模式下都读
            ReportDecoderKey("OnSetFile");
        } catch (Exception e) {
            LogException("OnNativeSetFile:report", e);
        }
    }

    // ==================== 诊断钩子（仅 GMK_FULL=1 时挂） ====================

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
    private static PeImage? _criPe;

    private static void AttachDiagnostics() {
        // 4 个 MANAKEY（S2/S3/N2/N3）也归到这里：它们实测 0 次调用，默认不挂（省 4 个 il2cpp 补丁），
        // 但 GMK_FULL=1 时仍挂起来，万一某个版本又走回托管通路能立刻看见。
        Safe("Diag:ManaKeyHooks", AttachManaKeyHooks);
        Safe("Diag:SetFile(managed)", () => _setFileM = AttachWide("SetFile(managed)", Rva.ManagedSetFile, &OnManagedSetFile));
        Safe("Diag:CriManaNew#5", () => _unk5 = AttachWide("CriManaNew#5", Rva.Unk5, &OnUnk5));
        Safe("Diag:CriManaNew#6", () => _unk6 = AttachWide("CriManaNew#6", Rva.Unk6, &OnUnk6));
        Safe("Diag:Decrypter.Initialize", () => _decInit = AttachWide("CriWareDecrypter.Initialize(Config)", Rva.DecrypterInitConfig, &OnDecInit));
        Safe("Diag:Decrypter.Initialize2", () => _decInit2 = AttachWide("CriWareDecrypter.Initialize(str,b,b)", Rva.DecrypterInit2, &OnDecInit2));
        Safe("Diag:Decrypter.native", () => _decNative = AttachWide("CriWareDecrypter.CRIWARE1859E5C2", Rva.DecrypterNative, &OnDecNative));
        Safe("Diag:Plugin.SetConfigParameters", () => _plgParams = AttachWide("CriManaPlugin.SetConfigParameters", Rva.PluginSetConfigParams, &OnPlgParams));
        Safe("Diag:Plugin.SetConfigAdditional", () => _plgAdditional = AttachWide("CriManaPlugin.SetConfigAdditonalParameters_PC", Rva.PluginSetConfigAdditional, &OnPlgAdditional));
        Safe("Diag:KeyFeed", () => _keyFeed = AttachWide("KeyFeed(manager小方法)", Rva.KeyFeed, &OnKeyFeed));
        // 注意：AttachBcrypt("core") 不在这里 —— 它在 Awake 的核心路径里，
        // 因为 bcrypt 是系统库（不是 il2cpp 补丁），而且是实测唯一真正产出密钥的路径。
    }

    /// <summary>
    /// 托管 SetFile。
    ///
    /// ★ A2：CRI Mana 的托管签名是 <c>SetFile(CriFsBinder binder, string fileName)</c>，
    /// 作为实例方法它的实际参数是 arg0=this / arg1=binder / arg2=path。
    /// 旧代码把 arg1 当 path，于是托管侧文件名永远读成 (null)（实测 DIAG SetFile self=... (null)，
    /// 同一时刻原生钩子却打出了真实路径）。
    /// </summary>
    [UnmanagedCallersOnly]
    private static void OnManagedSetFile(nint self, nint binder, nint path, nint a4,
        nint a5, nint a6, nint a7, nint a8) {
        var original = _setFileM;
        try {
            if (original != null) {
                original(self, binder, path, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnManagedSetFile:call", e);
        }
        // v16：播放已开始 → 允许记录 BCryptEncrypt
        Volatile.Write(ref _bcArm, 1);
        // 兜底归属：原生钩子是主路径，但托管钩子也写一份（两处都写才能保证不丢）
        var txt = ReadIl2CppString(path);
        SetCurrentFile(txt);
        try {
            var n = Interlocked.Increment(ref _cSetFileM);
            if (n <= 10) {
                Goshujin.Report($"DIAG SetFile self=0x{self:X} binder=0x{binder:X} path={txt}");
                if (Options.FullDiagnostics) {
                    ScanObjectForKeys("Player", self);
                    ReportCriCipherKey(txt);        // 纯内存读取，不改 CRI DLL
                    AttachBcrypt("SetFile");        // 系统库，可能之前还没加载
                    // v9：从 Player+0x78 → +0x10 走到真正的 binder 对象
                    if (Interlocked.CompareExchange(ref _cBinderWalked, 1, 0) == 0
                        && Native.TryReadPtr(self + 0x78, out var holder) && holder != 0
                        && Native.TryReadPtr(holder + 0x10, out var realBinder) && realBinder != 0) {
                        Goshujin.Report($"VBINDER holder=0x{holder:X} binder=0x{realBinder:X}");
                        ScanObjectForKeys("VBinder", realBinder, 0x200);
                        DumpClassMethods("VBINDER_", realBinder);
                        Goshujin.Report($"VBINDERP {HexOf(realBinder, 0x100)}");
                    }
                }
            } else {
                Goshujin.Report($"MANAFILE2 {txt}");
            }
        } catch (Exception e) {
            LogException("OnManagedSetFile:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnUnk5(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _unk5;
        try {
            if (original != null) {
                original(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnUnk5:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cUnk) <= 12) {
                Goshujin.Report($"DIAG new#5 a1=0x{a1:X} a2=0x{a2:X} a3=0x{a3:X} a4=0x{a4:X} h2={HexOf(a2, 0x20)}");
                ScanObjectForKeys("new#5", a1, 0x100);
            }
        } catch (Exception e) {
            LogException("OnUnk5:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnUnk6(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _unk6;
        try {
            if (original != null) {
                original(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnUnk6:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cUnk) <= 12) {
                Goshujin.Report($"DIAG new#6 a1=0x{a1:X} a2=0x{a2:X} a3=0x{a3:X} a4=0x{a4:X} h2={HexOf(a2, 0x20)}");
                ScanObjectForKeys("new#6", a1, 0x100);
            }
        } catch (Exception e) {
            LogException("OnUnk6:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnDecInit(nint cfg, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        // v14：CRI 初始化阶段就尝试钩 bcrypt（密钥可能在这一步生成）
        AttachBcrypt("DecInit");
        var original = _decInit;
        try {
            if (original != null) {
                original(cfg, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnDecInit:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cDecInit) <= 6) {
                // Config+0x10 = 参与 key 派生的字符串（key = default ^ hash(str)）
                nint str = 0;
                if (cfg != 0) {
                    Native.TryReadPtr(cfg + 0x10, out str);
                }
                Goshujin.Report($"DIAG Decrypter.Initialize(Config) cfg=0x{cfg:X} str={ReadIl2CppString(str)}");
                if (cfg != 0) {
                    Goshujin.Report($"DIAG CFGDUMP {HexOf(cfg, 0x40)}");
                }
            }
            // 关键：Initialize 会把 key 写进全局 RVA 0x5785430 —— 直接读结果
            ReportDecoderKey("DecInit");
        } catch (Exception e) {
            LogException("OnDecInit:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnDecInit2(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _decInit2;
        try {
            if (original != null) {
                original(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnDecInit2:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cDecInit) <= 6) {
                Goshujin.Report($"DIAG Decrypter.Initialize2 str={ReadIl2CppString(a1)} b2=0x{a2:X} b3=0x{a3:X}");
            }
            ReportDecoderKey("DecInit2");
        } catch (Exception e) {
            LogException("OnDecInit2:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnDecNative(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _decNative;
        try {
            if (original != null) {
                original(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnDecNative:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cDecNative) <= 8) {
                Goshujin.Report($"DIAG Decrypter.native a1=0x{a1:X} a2=0x{a2:X} a3=0x{a3:X} a4=0x{a4:X} h3={HexOf(a3, 0x20)}");
            }
        } catch (Exception e) {
            LogException("OnDecNative:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnPlgParams(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        AttachBcrypt("PlgParams");
        var original = _plgParams;
        try {
            if (original != null) {
                original(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnPlgParams:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cPlg) <= 8) {
                Goshujin.Report($"DIAG Plugin.SetConfigParameters a1=0x{a1:X} a2=0x{a2:X} a3=0x{a3:X} a4=0x{a4:X} a5=0x{a5:X}");
                ScanObjectForKeys("PluginCfg", a5, 0x100);
            }
        } catch (Exception e) {
            LogException("OnPlgParams:report", e);
        }
    }

    /// <summary>
    /// key 管理器小方法（0x6C4EA80）：this=manager，this+0x30=Player，this+0x50=binder（解密器）。
    /// 方法入口时 binder 已创建（方法内部才会把它绑到 Player+0x78）——在这里 dump 正合适。
    /// </summary>
    [UnmanagedCallersOnly]
    private static void OnKeyFeed(nint mgr, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _keyFeed;
        try {
            if (original != null) {
                original(mgr, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnKeyFeed:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cKeyFeed) > 3) {
                return;
            }
            nint binder = 0;
            if (mgr != 0) {
                Native.TryReadPtr(mgr + 0x50, out binder);
            }
            nint player = 0;
            if (mgr != 0) {
                Native.TryReadPtr(mgr + 0x30, out player);
            }
            Goshujin.Report($"KEYFEED mgr=0x{mgr:X} player=0x{player:X} binder=0x{binder:X}");
            ReportDecCallback("KeyFeed");
            ReportCriCipherKey("KeyFeed");      // 纯内存读取，不改 CRI DLL
            AttachBcrypt("KeyFeed");            // 系统库
            if (binder != 0) {
                ScanObjectForKeys("VBinder", binder, 0x200);
                DumpClassMethods("VBINDER_", binder);
                Goshujin.Report($"VBINDERP {HexOf(binder, 0x100)}");
            }
            // holder（Player+0x78 的对象，BinderSet 的另一端）
            if (player != 0 && Native.TryReadPtr(player + 0x78, out var holder) && holder != 0) {
                Goshujin.Report($"HOLDERP {HexOf(holder, 0x80)}");
                DumpClassMethods("HOLDER_", holder);
            }
        } catch (Exception e) {
            LogException("OnKeyFeed:report", e);
        }
    }

    [UnmanagedCallersOnly]
    private static void OnPlgAdditional(nint a1, nint a2, nint a3, nint a4, nint a5, nint a6, nint a7, nint a8) {
        var original = _plgAdditional;
        try {
            if (original != null) {
                original(a1, a2, a3, a4, a5, a6, a7, a8);
            }
        } catch (Exception e) {
            LogException("OnPlgAdditional:call", e);
        }
        try {
            if (Interlocked.Increment(ref _cPlg) <= 8) {
                Goshujin.Report($"DIAG Plugin.SetConfigAdditional a1=0x{a1:X} a2=0x{a2:X} a3=0x{a3:X}");
            }
        } catch (Exception e) {
            LogException("OnPlgAdditional:report", e);
        }
    }

    /// <summary>
    /// 纯内存读取 CRI 的 CriCipher AES 密钥（**不挂钩、不修改 cri_ware_unity.dll 的任何字节**）。
    ///
    /// 依据（Ghidra 反编译 + 字符串实证）：
    ///   · cri_ware_unity.dll 内含 "Microsoft Primitive Provider" / "AES" / "ChainingModeECB"
    ///     → CRI 用 BCrypt AES-ECB 自行构造 CTR 密钥流（只有 BCryptEncrypt，无 Decrypt，正是流模式特征）；
    ///   · CriCipher_Create 把密钥写入 context：*(ctx+0x20) = 16 字节 AES key；
    ///   · 全局单例 context 指针位于 Offsets.CriCipherSingleton。
    ///
    /// 只读内存，不在 CRI 模块内写任何钩子 —— v4 挂钩 CRI DLL 导致视频无法播放，是已知教训。
    /// </summary>
    private static void ReportCriCipherKey(string tag) {
        try {
            if (Interlocked.Increment(ref _cCriKey) > 8) {
                return;   // 会话内密钥基本不变，重复读只是刷屏
            }
            if (_criBase == 0) {
                _criBase = Native.FindModuleBase("cri_ware_unity.dll");
            }
            if (_criBase == 0) {
                Goshujin.Report($"CRICIPHER [{tag}] cri_ware_unity.dll 未加载");
                return;
            }
            Goshujin.Report($"CRICIPHER [{tag}] cri=@0x{_criBase:X}");

            // 1) 单例 cipher context（RVA 见 Offsets.CriCipherSingleton，随该 DLL 版本变化）
            nint ctx = 0;
            Native.TryReadPtr(_criBase + (int) Offsets.CriCipherSingleton, out ctx);
            if (ctx != 0 && Native.IsReadable(ctx, Offsets.CriCipherCtxSize)) {
                Goshujin.Report($"CRICTX ctx=0x{ctx:X} {HexOf(ctx, Offsets.CriCipherCtxSize)}");
                Goshujin.Report($"CRIKEY [{tag}] {HexOf(ctx + Offsets.CriCipherKeyOffset, 16)}");
            } else {
                Goshujin.Report($"CRICTX 单例指针不可读 raw=0x{ctx:X}");
            }

            // 2) 兜底：扫 .data 区间，跟随所有可读指针，dump 目标并单独报 +0x20 的 16 字节
            var found = 0;
            for (var off = (int) Offsets.CriDataScanStart; off < (int) Offsets.CriDataScanEnd && found < 14; off += 8) {
                if (!Native.TryReadPtr(_criBase + off, out var p) || p == 0) {
                    continue;
                }
                if (p < 0x10000 || p > 0x7FFFFFFFFFFF) {
                    continue;
                }
                if (!Native.IsReadable(p, Offsets.CriDataDumpSize)) {
                    continue;
                }
                found++;
                Goshujin.Report($"CRIDATA +0x{off:X} -> 0x{p:X} {HexOf(p, Offsets.CriDataDumpSize)}");
                Goshujin.Report($"CRIDATAKEY +0x{off:X} {HexOf(p + Offsets.CriCipherKeyOffset, 16)}");
            }
            if (found == 0) {
                Goshujin.Report("CRIDATA (无可读指针)");
            }
        } catch (Exception e) {
            LogException("ReportCriCipherKey", e);
        }
    }

    /// <summary>读解密器派生 key 的全局位（Offsets.DecoderKeyGlobal）。</summary>
    private static void ReportDecoderKey(string tag) {
        try {
            if (Native.TryReadPtr(_base + (int) Offsets.DecoderKeyGlobal, out var key) && key != 0) {
                Goshujin.Report($"DECKEY [{tag}] {(ulong) key:X16}");
            }
        } catch (Exception e) {
            LogException("ReportDecoderKey", e);
        }
    }

    /// <summary>
    /// 读 CRI 解密回调（Decrypter 注册给 CRIWARE8F9AABA8 的委托目标）。
    /// 全局槽 → 结构体；+0x8 = 原生回调。回调代码前 0x40 字节足够离线反推出托管方法地址。
    /// </summary>
    private static void ReportDecCallback(string tag) {
        try {
            if (!Native.TryReadPtr(_base + (int) Offsets.DecCallbackGlobal, out var obj) || obj == 0
                || !Native.IsReadable(obj, 0x28)) {
                return;
            }
            Goshujin.Report($"DECCALLBACK [{tag}] obj=0x{obj:X} dump={HexOf(obj, 0x28)}");
            if (Native.TryReadPtr(obj + 8, out var cb) && cb != 0) {
                var where = IsInExe(cb) ? $"exe+0x{cb - _base:X}" : "non-exe";
                Goshujin.Report($"DECCB [{tag}] cb=0x{cb:X} ({where}) code={HexOf(cb, 0x40)}");
            }
        } catch (Exception e) {
            LogException("ReportDecCallback", e);
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
    ///     OnManagedSetFile/OnDecInit/OnPlgParams/OnKeyFeed 在游戏任意线程并发调用；
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
            // 让后续 SetFile / DecInit 等冷路径继续重试；绝不能停在"正在安装"把重试永久堵死。
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
