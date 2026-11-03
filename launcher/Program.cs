using System.ComponentModel;
using System.IO.Pipes;
using System.Text;
using GenshinSniffer;
using GenshinSniffer.Utilities;

internal static class Program {

    private const string PipeName = "GenshinManaKeyPipe";
    private const string LibFileName = "ManaKeyDumper.dll";

    private static GameProcess? _proc;
    private static readonly HashSet<string> Lines = new(StringComparer.Ordinal);
    private static readonly object Lock = new();

    // ---- 配对状态机 ----
    // 协议（字节语义与 DLL 端约定，不能改）：0xFC 文本 / 0xFD blob / 0xFE 恢复主线程。
    // 「文件名 ↔ 密钥」的补齐逻辑全部收在 KeyPairing 里（纯逻辑，可单测），这里只负责
    // 收管道消息 → 让状态机吐条目 → 写盘 → 打日志。
    private static readonly KeyPairing Pairing = new();

    /// <summary>游戏退出信号：退出时置位，让 Main 的等待循环自然收尾（不再用 Environment.Exit 掐掉管道线程）。</summary>
    private static readonly ManualResetEventSlim GameExited = new(false);

    /// <summary>本次会话真正写盘的配对数 —— 用来区分"有产出/无产出"，而不是看文件是否碰巧存在。</summary>
    private static int _pairedCount;

    private static int Main(string[] args) {
        // 排障开关：只有 GMK_CONSOLE=1 才分配控制台。
        // 默认是 GUI 子系统，双击时**不会出现任何控制台/命令行窗口**。
        Log.AttachConsoleIfRequested();
        Log.Write("========================================");
        // 标题不写死游戏版本：RVA 由注入 DLL 的 RvaSet.Fingerprint + update_rva.cmd 维护，
        // 写死版本号只会让日志在下次更新后先自相矛盾。具体版本看下一行的"版本指纹"日志。
        Log.Write("GenshinManaKey - 原神过场动画密钥截获 (CRI Mana / AES_HCA)");
        Log.Write("  hook: bcrypt.dll!BCryptGenerateSymmetricKey（视频 AES-128）");
        Log.Write("        bcrypt.dll!BCryptEncrypt（密钥流验证）");
        Log.Write("        NativeMethods_SetFile（文件名来源）");
        Log.Write("        CriwareMediaPlayer 设钥函数（音频 key + 旧 videoKey）");
        Log.Write("  输出: mana_keys.log(原始) + paired_keys.json(aes/audio/videoKey, 可直接并入 key 库)");
        Log.Write("========================================");
        try {
            return Run(args);
        } finally {
            // AutoFlush=false，所以退出前必须显式冲刷，否则最后一段日志留在缓冲区里
            Log.Shutdown();
        }
    }

    private static int Run(string[] args) {
        // 遮罩自检：不启动游戏、不注入，只在左下角画 20 秒，用来看位置/穿透/Alt+Tab/字体
        if (Environment.GetEnvironmentVariable("GMK_OVERLAY_SELFTEST") == "1") {
            return OverlaySelfTest();
        }
        var exePath = AppConfig.GetGamePath(args.ElementAtOrDefault(0), out var pathSource);
        if (exePath == null) {
            // 运行中的实例只当作"你大概是这个路径"的提示：本启动器必须以挂起方式自己创建进程，
            // 游戏已在运行就是错误状态，拿它的路径直接注入是做不到的
            var running = AppConfig.GetRunningGamePath();
            var hint = $"请把游戏目录（或 YuanShen.exe / GenshinImpact.exe 全路径）写进 {Paths.GamePathFile}，"
                     + "双击就能用；也可以作为第一个命令行参数传入。";
            Fatal(running == null
                ? $"未找到游戏（来源：{pathSource}）。{hint}"
                : $"未找到游戏（来源：{pathSource}）。检测到正在运行的游戏：{running}，请先关闭它。{hint}");
            return -1;
        }
        Log.Write($"游戏: {exePath}（{AppConfig.ServiceLabel(exePath)}，来源：{pathSource}）");

        if (AppConfig.IsGameRunning(exePath)) {
            Fatal("游戏已在运行，请先关闭游戏。");
            return -1;
        }

        var libPath = Path.Combine(AppContext.BaseDirectory, LibFileName);
        if (!File.Exists(libPath)) {
            Fatal($"未找到注入 DLL: {libPath}");
            return -1;
        }

        // 遮罩窗口（左下角实时日志）：默认启用。GMK_OVERLAY=0 关闭、GMK_CONSOLE=1 同时保留控制台。
        // 只有遮罩**真的建起来了**才去关控制台 —— 建不起来就老老实实留在控制台，不能让用户什么都看不到。
        var overlayWanted = Environment.GetEnvironmentVariable("GMK_OVERLAY") != "0";
        if (!overlayWanted) {
            Log.Warn("GMK_OVERLAY=0：不使用遮罩；日志见 dumper.log（要看控制台请设 GMK_CONSOLE=1）。");
        } else if (!OverlayWindow.Create()) {
            Log.Warn("遮罩不可用；日志见 dumper.log（要看控制台请设 GMK_CONSOLE=1）。");
        }

        // 管道服务必须先起：DLL 注入后立刻连接，起晚了会漏掉最早几条上报
        var pipeTask = Task.Run(PipeLoop);

        var proc = new GameProcess(exePath);
        _proc = proc;
        // 遮罩要知道跟谁走：拿到游戏 PID 后它每 500ms 校正一次左下角位置
        OverlayWindow.SetTargetProcess(proc.Id);
        // 退出订阅必须早于注入：注入（远程线程 + 模块枚举）要花时间，
        // 这段窗口里游戏崩掉的话，晚订阅就永远收不到退出事件
        proc.OnExit += OnGameExit;
        AppDomain.CurrentDomain.ProcessExit += (_, _) => {
            // 兜底：中途退出（参数错、注入失败、用户关窗口）别留下一个挂起的游戏进程；
            // _proc 可能还没创建，用空条件访问而不是非空断言
            _proc?.Terminate(0);
            Log.Shutdown();
        };

        Log.Write($"游戏进程已创建 (PID {proc.Id})，等待注入 DLL 连接...");
        if (!proc.LoadLibrary(libPath)) {
            Fatal($"注入失败（{DescribeInjectionError(proc.LastInjectionError)}），已终止游戏进程。");
            proc.Terminate(0);
            return -1;
        }
        var injectedBase = GameProcess.FindModuleBase(proc, LibFileName);
        if (injectedBase != 0) {
            Log.Write($"注入复核: {LibFileName} 已在目标进程 @ 0x{injectedBase:X}");
        } else {
            Log.Warn($"注入复核失败: 目标进程里找不到 {LibFileName}，后续可能收不到上报。");
        }

        Log.Write("进入游戏并播放加密过场动画（如 300317-300321 对应的剧情），配对密钥将实时写入 paired_keys.json");

        // 优雅退出：等游戏退出信号，再给管道读取线程最多 2 秒把管道里剩余的上报读完
        // （以前这里直接 Environment.Exit(0)，会掐掉读取线程，最后几条上报就没了）
        if (OverlayWindow.Available) {
            // 遮罩在的时候由主线程跑消息循环（Win32 窗口必须单线程）；游戏退出时 OnGameExit 发消息结束它
            OverlayWindow.RunMessageLoop();
        } else {
            GameExited.Wait();
        }
        try {
            if (!pipeTask.Wait(TimeSpan.FromSeconds(2))) {
                Log.Warn("管道读取线程 2 秒内未结束，放弃剩余上报。");
            }
        } catch (AggregateException e) {
            // 读取线程异常退出也要走完收尾（否则连"共截获多少条"都不打了）
            Log.Error($"管道读取线程异常退出: {e.GetBaseException().Message}");
        }

        var events = EventCount;
        var paired = Volatile.Read(ref _pairedCount);
        if (paired > 0) {
            Log.Write($"共截获 {events} 条事件，已配对 {paired} 条密钥，结果见 {Paths.PairedKeys}");
        } else if (events > 0) {
            Log.Warn($"共截获 {events} 条事件，但本次没有配对出任何密钥，未生成/未更新 {Paths.PairedKeys}");
        } else {
            Log.Warn("未截获任何密钥（游戏内播放加密视频时才会触发）。");
        }
        Log.Flush();
        return 0;
    }

    /// <summary>游戏退出回调（在监视线程上执行）：只打日志 + 置信号，绝不在这里退出进程。</summary>
    private static void OnGameExit() {
        var proc = _proc;
        Log.Write(proc == null ? "游戏已退出。" : $"游戏已退出 (exit code 0x{proc.ExitCode:X8})。");
        GameExited.Set();
        // 遮罩模式：主线程正阻塞在消息循环里，发一条消息让它收尾（跨线程只能 PostMessage）
        OverlayWindow.RequestExit();
    }

    /// <summary>
    /// 遮罩自检（GMK_OVERLAY_SELFTEST=1）：**不启动游戏、不注入**，只在桌面左下角把遮罩跑 30 秒。
    /// 用途是先确认"位置对不对、点击能不能穿透、Alt+Tab 里有没有它、字体好不好看" ——
    /// 完全不涉及反作弊，出问题也只影响这一个窗口。
    ///
    /// 脚本刻意把两条显示规则都演一遍：
    ///   第 1、3 秒各推一条**配对**（会上遮罩）；第 5、7 秒各推一条**普通日志**（不该上遮罩）；
    ///   距最后一条配对满 10 秒（约第 13 秒）遮罩应自动消失；
    ///   第 18 秒再推一条配对 → 遮罩重新出现，而且**只有这一行**（上一条已在隐藏时被清掉）。
    /// </summary>
    private static int OverlaySelfTest() {
        Log.Write("GMK_OVERLAY_SELFTEST=1：只跑遮罩自检（不启动游戏、不注入），30 秒后自动退出。");
        if (!OverlayWindow.Create()) {
            Fatal("遮罩创建失败（自检）。");
            return -1;
        }
        OverlayWindow.SetSelfTestTarget();
        using var pair1 = new Timer(_ => Log.Pair(
                "★★ 已配对(掩码) Cs_ZD_AQ70201201_SLT → paired_keys.json (F5AC17FFE4B4B430553AE073EB8A8A1D)"), null,
            TimeSpan.FromSeconds(1), Timeout.InfiniteTimeSpan);
        using var pair2 = new Timer(_ => Log.Pair(
                "★★ 已配对 Cs_LY_EQ4025110_ZY → paired_keys.json (aes=45872521… audio=3C9B1A44…)"), null,
            TimeSpan.FromSeconds(3), Timeout.InfiniteTimeSpan);
        using var noise1 = new Timer(_ => Log.Write("自检：这行是普通日志，只该进 dumper.log，不该出现在遮罩上"), null,
            TimeSpan.FromSeconds(5), Timeout.InfiniteTimeSpan);
        using var noise2 = new Timer(_ => Log.Warn("自检：WRN 也一样不该上遮罩"), null,
            TimeSpan.FromSeconds(7), Timeout.InfiniteTimeSpan);
        // 第 13 秒左右遮罩应自动消失（最后一条配对在 3 秒 + 10 秒）
        using var pair3 = new Timer(_ => Log.Pair(
                "★★ 已配对(视频 AES) Cs_XT_FE5021103_ZZ → paired_keys.json (aes=9E1C77B4A0D9F1E2)"), null,
            TimeSpan.FromSeconds(18), Timeout.InfiniteTimeSpan);
        using var stop = new Timer(_ => OverlayWindow.RequestExit(), null,
            TimeSpan.FromSeconds(30), Timeout.InfiniteTimeSpan);
        OverlayWindow.RunMessageLoop();
        Log.Write("遮罩自检结束。");
        return 0;
    }

    /// <summary>
    /// 致命错误：写进 dumper.log **并弹一次 MessageBox**。
    /// 为什么必须弹：双击场景下控制台可能已经被遮罩接管而隐藏（甚至一闪而过），
    /// 只在控制台里报错等于什么都没说。
    /// </summary>
    private static void Fatal(string message) {
        Log.Error(message);
        OverlayWindow.ShowFatal("GenshinManaKey", message);
    }

    private static int EventCount {
        get {
            lock (Lock) {
                return Lines.Count;
            }
        }
    }

    private static void PipeLoop() {
        try {
            using var stream = new NamedPipeServerStream(PipeName);
            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            stream.WaitForConnection();
            Log.Write("注入 DLL 已连接。");
            int type;
            while ((type = stream.ReadByte()) != -1) {
                switch (type) {
                    case 0xFC:
                        // 文本消息：BinaryWriter.Write(string)（7 位长度前缀 + UTF-8）
                        HandleMessage(reader.ReadString());
                        break;
                    case 0xFD:
                        // blob：字符串文件名 + Int32 长度 + 字节
                        DumpBlob(reader);
                        break;
                    case 0xFE: {
                        var proc = _proc; // 不能用 _proc! —— 管道线程可能比赋值先跑到这里，NRE 会直接打断读取循环
                        if (proc == null) {
                            Log.Warn("收到恢复主线程请求，但游戏进程尚未创建（已忽略）。");
                            break;
                        }
                        proc.ResumeMainThread();
                        Log.Write("主线程已恢复，游戏启动。");
                        break;
                    }
                    default:
                        Log.Warn($"未知上报类型 0x{type:X2}，已跳过（协议可能不匹配）。");
                        break;
                }
            }
        } catch (IOException e) when (e.Message.Contains("busy", StringComparison.OrdinalIgnoreCase)
                                     || e.Message.Contains("占用", StringComparison.Ordinal)) {
            Log.Error($"管道创建失败（可能有残留实例占用）：{e.Message}");
        } catch (IOException) {
            // 管道断开（游戏退出）—— 正常收尾路径
        } catch (Exception e) {
            // 兜底：上报线自己坏掉（管道参数非法、长度前缀错乱读到 OOM 等）也只是记一条，
            // 不能让异常回灌 Main —— 那时收尾统计与退出码都会乱掉
            Log.Error($"管道读取异常，已停止接收上报: {e.Message}");
        }
    }

    private static void DumpBlob(BinaryReader reader) {
        var fileName = reader.ReadString();
        var length = reader.ReadInt32();
        var buffer = reader.ReadBytes(length);
        try {
            Directory.CreateDirectory(Paths.DumpDirectory);
            var safe = string.Concat(fileName.Where(char.IsAsciiLetterOrDigit));
            if (safe.Length == 0) {
                safe = "blob";
            }
            var path = Path.Combine(Paths.DumpDirectory, safe + ".bin");
            File.WriteAllBytes(path, buffer);
            Log.Write($"[DLL] 已转储 {safe}.bin ({length}B)");
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException) {
            Log.Warn($"[DLL] 转储失败: {e.Message}");
        }
    }

    private static void HandleMessage(string message) {
        try {
            if (AddLineIfNew(message)) {
                // README 承诺 mana_keys.log 里是"MANAKEY* / MANAFILE 行"。
                // 旧实现只落 MANAKEY*，MANAFILE 永远写不进去（实测 330 条事件连 mana_keys.log 都没生成）。
                if (message.StartsWith("MANAKEY", StringComparison.Ordinal)
                    || message.StartsWith("MANAFILE", StringComparison.Ordinal)
                    || message.StartsWith("BCKEY", StringComparison.Ordinal)) {
                    AppendRawEvent(message);
                }
            }
            foreach (var entry in Pairing.Handle(message)) {
                WritePairingEntry(entry);
            }
            // 诊断日志：保留 ★ / ★★ + 中文提示的原风格
            if (message.StartsWith("MANAFILE", StringComparison.Ordinal)) {
                var rejected = Pairing.LastRejectReason;
                if (rejected != null) {
                    // 被拒时 LastFile 还是上一份有效文件名，直接打会让人以为这条被采纳了
                    Log.Warn($"★ 文件（未采纳：{rejected}）: {message}");
                } else if (Pairing.LastFile.Length > 0) {
                    Log.Write($"★ 文件 [{Pairing.LastIndex}]: {Pairing.LastFile}");
                }
                Log.Write($"[DLL] {message}");
            } else if (message.StartsWith("MANAKEY", StringComparison.Ordinal)) {
                var rejected = Pairing.LastRejectReason;
                if (rejected == null) {
                    Log.Write($"★ 密钥: {message}");
                } else {
                    Log.Warn($"★ 密钥（未配对：{rejected}）: {message}");
                }
            } else {
                Log.Write($"[DLL] {message}");
            }
        } catch (Exception e) {
            // 单条上报处理失败不能让管道读取线程死掉（否则后续密钥全丢）
            Log.Warn($"HandleMessage 异常: {e.Message}");
        }
    }

    /// <summary>
    /// 事件去重。旧实现用 List.Contains 做判重：诊断量大时是 O(n) 线性扫描，
    /// 整体退化成 O(n²)（每来一条都要扫前面所有行）。HashSet 是 O(1)，语义不变。
    /// </summary>
    private static bool AddLineIfNew(string message) {
        lock (Lock) {
            return Lines.Add(message);
        }
    }

    private static void AppendRawEvent(string message) {
        try {
            File.AppendAllText(Paths.KeysLog, message + Environment.NewLine);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            Log.Warn($"写 mana_keys.log 失败: {e.Message}");
        }
    }

    private static void WritePairingEntry(PairingEntry entry) {
        try {
            if (entry.Kind == PairingKind.Aes) {
                // BCKEY 通路（bcrypt）：视频 AES-128
                JsonStore.UpsertAes(Paths.PairedKeys, entry.File, entry.Aes);
                Log.Pair($"★★ 已配对(视频 AES) {entry.File} → paired_keys.json (aes={entry.Aes})");
                Interlocked.Increment(ref _pairedCount);
            } else if (entry.Kind == PairingKind.MediaKeys) {
                // MANAKEY4 通路（CriwareMediaPlayer）：音频 key 与/或旧 videoKey，可能还带 AES
                JsonStore.UpsertKeys(Paths.PairedKeys, entry.File, entry.Aes, entry.Audio, entry.VideoKey);
                var detail = new StringBuilder(64);
                if (entry.Aes.Length > 0) {
                    detail.Append("aes=").Append(entry.Aes);
                }
                if (entry.Audio.Length > 0) {
                    detail.Append(detail.Length > 0 ? " " : "").Append("audio=").Append(entry.Audio);
                }
                if (entry.VideoKey.Length > 0) {
                    detail.Append(detail.Length > 0 ? " " : "").Append("videoKey=").Append(entry.VideoKey);
                }
                var label = entry.VideoKey.Length > 0 ? "旧体系" : "音频";
                Log.Pair($"★★ 已配对({label}) {entry.File} → paired_keys.json ({detail})");
                Interlocked.Increment(ref _pairedCount);
            } else {
                // MANAKEY1/2/3 的旧协议解析还保留着（协议兼容），但 v20 之后没有钩子会产出它们。
                Log.Warn($"忽略旧协议密钥上报（{entry.Kind}）{entry.File}：当前只认 BCKEY 与 MANAKEY4");
            }
            // 配对行走 Log.Pair：**只有它们会上遮罩**，其余日志（含诊断）只进 dumper.log。
            // 为什么只留这一行：遮罩贴在游戏画面上，管道诊断几十行没人会看，
            // 真正要一眼确认的只有"这个视频配上密钥了没有"。
        } catch (Exception e) {
            Log.Error($"写 paired_keys.json 失败: {e.Message}");
        }
    }

    private static string DescribeInjectionError(Exception? error) {
        if (error is Win32Exception win32) {
            var api = win32.Data["api"] as string ?? "未知 API";
            return $"{api} 失败: {win32.Message}（Win32 错误码 {win32.NativeErrorCode}）";
        }
        return error?.Message ?? "未知原因";
    }

}
