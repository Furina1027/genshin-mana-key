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
        Log.Write("========================================");
        Log.Write("GenshinManaKey - 原神 7.1 过场动画密钥截获 (CRI Mana / AES_HCA)");
        Log.Write("  hook: SetVideoAudioDecryptionKeys / SetVideoAesKeyAudioDecryptionKey");
        Log.Write("        + 两个 NativeMethods_* P/Invoke 包装 + NativeMethods_SetFile(文件名)");
        Log.Write("  输出: mana_keys.log(原始) + paired_keys.json(按文件名配对, 可直接并入 key 库)");
        Log.Write("========================================");
        try {
            return Run(args);
        } finally {
            // AutoFlush=false，所以退出前必须显式冲刷，否则最后一段日志留在缓冲区里
            Log.Shutdown();
        }
    }

    private static int Run(string[] args) {
        var exePath = AppConfig.GetGamePath(args.ElementAtOrDefault(0), out var pathSource);
        if (exePath == null) {
            // 运行中的实例只当作"你大概是这个路径"的提示：本启动器必须以挂起方式自己创建进程，
            // 游戏已在运行就是错误状态，拿它的路径直接注入是做不到的
            var running = AppConfig.GetRunningGamePath();
            var hint = $"请把游戏目录（或 YuanShen.exe / GenshinImpact.exe 全路径）写进 {Paths.GamePathFile}，"
                     + "双击就能用；也可以作为第一个命令行参数传入。";
            Log.Write(running == null
                ? $"未找到游戏（来源：{pathSource}）。{hint}"
                : $"未找到游戏（来源：{pathSource}）。检测到正在运行的游戏：{running}，请先关闭它。{hint}");
            return -1;
        }
        Log.Write($"游戏: {exePath}（{AppConfig.ServiceLabel(exePath)}，来源：{pathSource}）");

        if (AppConfig.IsGameRunning(exePath)) {
            Log.Write("游戏已在运行，请先关闭游戏。");
            return -1;
        }

        var libPath = Path.Combine(AppContext.BaseDirectory, LibFileName);
        if (!File.Exists(libPath)) {
            Log.Write($"未找到注入 DLL: {libPath}");
            return -1;
        }

        // 管道服务必须先起：DLL 注入后立刻连接，起晚了会漏掉最早几条上报
        var pipeTask = Task.Run(PipeLoop);

        var proc = new GameProcess(exePath);
        _proc = proc;
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
            Log.Write($"注入失败（{DescribeInjectionError(proc.LastInjectionError)}），已终止游戏进程。");
            proc.Terminate(0);
            return -1;
        }
        var injectedBase = GameProcess.FindModuleBase(proc, LibFileName);
        Log.Write(injectedBase != 0
            ? $"注入复核: {LibFileName} 已在目标进程 @ 0x{injectedBase:X}"
            : $"注入复核失败: 目标进程里找不到 {LibFileName}，后续可能收不到上报。");

        Log.Write("进入游戏并播放加密过场动画（如 300317-300321 对应的剧情），配对密钥将实时写入 paired_keys.json");

        // 优雅退出：等游戏退出信号，再给管道读取线程最多 2 秒把管道里剩余的上报读完
        // （以前这里直接 Environment.Exit(0)，会掐掉读取线程，最后几条上报就没了）
        GameExited.Wait();
        try {
            if (!pipeTask.Wait(TimeSpan.FromSeconds(2))) {
                Log.Write("管道读取线程 2 秒内未结束，放弃剩余上报。");
            }
        } catch (AggregateException e) {
            // 读取线程异常退出也要走完收尾（否则连"共截获多少条"都不打了）
            Log.Write($"管道读取线程异常退出: {e.GetBaseException().Message}");
        }

        var events = EventCount;
        var paired = Volatile.Read(ref _pairedCount);
        if (paired > 0) {
            Log.Write($"共截获 {events} 条事件，已配对 {paired} 条密钥，结果见 {Paths.PairedKeys}");
        } else if (events > 0) {
            Log.Write($"共截获 {events} 条事件，但本次没有配对出任何密钥，未生成/未更新 {Paths.PairedKeys}");
        } else {
            Log.Write("未截获任何密钥（游戏内播放加密视频时才会触发）。");
        }
        Log.Flush();
        return 0;
    }

    /// <summary>游戏退出回调（在监视线程上执行）：只打日志 + 置信号，绝不在这里退出进程。</summary>
    private static void OnGameExit() {
        var proc = _proc;
        Log.Write(proc == null ? "游戏已退出。" : $"游戏已退出 (exit code 0x{proc.ExitCode:X8})。");
        GameExited.Set();
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
                            Log.Write("收到恢复主线程请求，但游戏进程尚未创建（已忽略）。");
                            break;
                        }
                        proc.ResumeMainThread();
                        Log.Write("主线程已恢复，游戏启动。");
                        break;
                    }
                    default:
                        Log.Write($"未知上报类型 0x{type:X2}，已跳过（协议可能不匹配）。");
                        break;
                }
            }
        } catch (IOException e) when (e.Message.Contains("busy", StringComparison.OrdinalIgnoreCase)
                                     || e.Message.Contains("占用", StringComparison.Ordinal)) {
            Log.Write($"管道创建失败（可能有残留实例占用）：{e.Message}");
        } catch (IOException) {
            // 管道断开（游戏退出）—— 正常收尾路径
        } catch (Exception e) {
            // 兜底：上报线自己坏掉（管道参数非法、长度前缀错乱读到 OOM 等）也只是记一条，
            // 不能让异常回灌 Main —— 那时收尾统计与退出码都会乱掉
            Log.Write($"管道读取异常，已停止接收上报: {e.Message}");
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
            Log.Write($"[DLL] 转储失败: {e.Message}");
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
                    Log.Write($"★ 文件（未采纳：{rejected}）: {message}");
                } else if (Pairing.LastFile.Length > 0) {
                    Log.Write($"★ 文件 [{Pairing.LastIndex}]: {Pairing.LastFile}");
                }
                Log.Write($"[DLL] {message}");
            } else if (message.StartsWith("MANAKEY", StringComparison.Ordinal)) {
                var rejected = Pairing.LastRejectReason;
                Log.Write(rejected == null ? $"★ 密钥: {message}" : $"★ 密钥（未配对：{rejected}）: {message}");
            } else {
                Log.Write($"[DLL] {message}");
            }
        } catch (Exception e) {
            // 单条上报处理失败不能让管道读取线程死掉（否则后续密钥全丢）
            Log.Write($"HandleMessage 异常: {e.Message}");
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
            Log.Write($"写 mana_keys.log 失败: {e.Message}");
        }
    }

    private static void WritePairingEntry(PairingEntry entry) {
        try {
            if (entry.Kind == PairingKind.Aes) {
                // BCKEY 通路（bcrypt）：只有视频 AES 密钥，音频 key 拿不到 —— 不写空字段
                JsonStore.UpsertAes(Paths.PairedKeys, entry.File, entry.Aes);
                Log.Write($"★★ 已配对(视频 AES) {entry.File} → paired_keys.json (aes={entry.Aes})");
            } else if (entry.Kind == PairingKind.Method2) {
                JsonStore.UpsertMethod2(Paths.PairedKeys, entry.File, entry.Aes, entry.Audio);
                Log.Write($"★★ 已配对 {entry.File} → paired_keys.json (aes={Head(entry.Aes)}… audio={Head(entry.Audio)}…)");
            } else {
                JsonStore.UpsertMask(Paths.PairedKeys, entry.File, entry.VideoKey);
                Log.Write($"★★ 已配对(掩码) {entry.File} → paired_keys.json ({entry.VideoKey})");
            }
            Interlocked.Increment(ref _pairedCount);
        } catch (Exception e) {
            Log.Write($"写 paired_keys.json 失败: {e.Message}");
        }
    }

    /// <summary>日志里只显示密钥前 8 个字符：足够核对，又不必把整库密钥打到屏幕上。</summary>
    private static string Head(string value) => value.Length <= 8 ? value : value[..8];

    private static string DescribeInjectionError(Exception? error) {
        if (error is Win32Exception win32) {
            var api = win32.Data["api"] as string ?? "未知 API";
            return $"{api} 失败: {win32.Message}（Win32 错误码 {win32.NativeErrorCode}）";
        }
        return error?.Message ?? "未知原因";
    }

}
