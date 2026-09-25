using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using GenshinSniffer;
using GenshinSniffer.Utilities;

/// 极简 JSON KV 存储（NativeAOT 无反射安全）:
/// { "文件名": "掩码key" , "文件名2": {"aes":"..","audio":".."} }
internal static class JsonStore {

    private static string Esc(string s) {
        var sb = new StringBuilder(s.Length + 8);
        foreach (var c in s) {
            if (c == '\\') {
                sb.Append("\\");
            } else if (c == '"') {
                sb.Append("\\\"");
            } else {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }

    /// 读取现有文件为 name -> 原始 value JSON 文本
    private static Dictionary<string, string> Load(string path) {
        var dict = new Dictionary<string, string>();
        if (!File.Exists(path)) {
            return dict;
        }
        var text = File.ReadAllText(path).Trim();
        if (text.Length < 2 || text[0] != '{') {
            return dict;
        }
        text = text.Substring(1, text.Length - 2);
        // 简单切分: 值内部不含裸引号（文件名/key 均安全）
        foreach (var part in text.Split(',')) {
            var kv = part.Split(':');
            if (kv.Length < 2) {
                continue;
            }
            var k = kv[0].Trim().Trim('"');
            var v = string.Join(':', kv.Skip(1)).Trim();
            if (k.Length > 0 && v.Length > 0) {
                dict[k] = v;
            }
        }
        return dict;
    }

    public static void UpsertMethod2(string path, string name, string aes, string audio) {
        var dict = Load(path);
        dict[name] = "{\"aes\":\"" + Esc(aes) + "\",\"audio\":\"" + Esc(audio) + "\"}";
        Write(path, dict);
    }

    public static void UpsertMask(string path, string name, string videoKey) {
        var dict = Load(path);
        dict[name] = "\"" + Esc(videoKey) + "\"";
        Write(path, dict);
    }

    private static void Write(string path, Dictionary<string, string> dict) {
        var sb = new StringBuilder("{");
        var first = true;
        foreach (var kv in dict) {
            if (!first) {
                sb.Append(',');
            }
            first = false;
            sb.Append('"').Append(Esc(kv.Key)).Append("\":").Append(kv.Value);
        }
        sb.Append('}');
        File.WriteAllText(path, sb.ToString());
    }

}

internal static class Program {

    private const string PipeName = "GenshinManaKeyPipe";
    private const string LibFileName = "ManaKeyDumper.dll";
    private const string KeysPath = "mana_keys.log";
    private const string PairedPath = "paired_keys.json";

    private static GameProcess? _proc;
    private static readonly List<string> Lines = new();
    private static readonly object Lock = new();

    // ---- 路径 ↔ 密钥 配对状态 ----
    // NF(SetFile) 带 playerIndex 报文件名; N2/N3/N1(设钥) 同样带 playerIndex。
    // 同一 player 的文件名与密钥按先后到达补齐, 补齐即写 paired_keys.json (hoyo-files 格式)。
    private static readonly Dictionary<int, string> PlayerFile = new();
    private static readonly Dictionary<int, List<string>> PendingMask = new();   // idx -> "hex" (4.4 掩码 videoKey)
    private static readonly Dictionary<int, List<(string, string)>> PendingM2 = new(); // idx -> (aesHex, audioHex)
    private static string LastFile = "";   // 无索引的 S1/S2/S3 兜底配对用
    private static string? GlobalPendingMask;              // S1/S2 先于 SetFile 到达时暂存
    private static (string aes, string audio)? GlobalPendingM2; // S3 同上
    private static readonly HashSet<string> Emitted = new();

    private static int Main(string[] args) {
        Log.Write("========================================");
        Log.Write("GenshinManaKey - 原神 7.1 过场动画密钥截获 (CRI Mana / AES_HCA)");
        Log.Write("  hook: SetVideoAudioDecryptionKeys / SetVideoAesKeyAudioDecryptionKey");
        Log.Write("        + 两个 NativeMethods_* P/Invoke 包装 + NativeMethods_SetFile(文件名)");
        Log.Write("  输出: mana_keys.log(原始) + paired_keys.json(按文件名配对, 可直接并入 key 库)");
        Log.Write("========================================");

        var exePath = AppConfig.GetGamePath(args.ElementAtOrDefault(0));
        if (exePath == null) {
            Log.Write("未找到游戏，请把 YuanShen.exe / GenshinImpact.exe 全路径作为第一个参数传入。");
            return -1;
        }
        Log.Write($"游戏: {exePath}");

        if (AppConfig.IsGameRunning()) {
            Log.Write("游戏已在运行，请先关闭游戏。");
            return -1;
        }

        var libPath = Path.Combine(AppContext.BaseDirectory, LibFileName);
        if (!File.Exists(libPath)) {
            Log.Write($"未找到注入 DLL: {libPath}");
            return -1;
        }

        Task.Run(() => {
            NamedPipeServerStream? stream = null;
            try {
                stream = new NamedPipeServerStream(PipeName);
                using var reader = new BinaryReader(stream, Encoding.UTF8, true);
                stream.WaitForConnection();
                Log.Write("注入 DLL 已连接。");
                int type;
                while ((type = stream.ReadByte()) != -1) {
                    switch (type) {
                        case 0xFC: {
                            var msg = reader.ReadString();
                            HandleMessage(msg);
                            break;
                        }
                        case 0xFD: {
                            var fn = reader.ReadString();
                            var len = reader.ReadInt32();
                            var buf = reader.ReadBytes(len);
                            try {
                                var dir = Path.Combine(AppContext.BaseDirectory, "dump");
                                Directory.CreateDirectory(dir);
                                var safe = string.Concat(fn.Where(char.IsAsciiLetterOrDigit).ToArray());
                                if (safe.Length == 0) {
                                    safe = "blob";
                                }
                                var path = Path.Combine(dir, safe + ".bin");
                                File.WriteAllBytes(path, buf);
                                Log.Write($"[DLL] 已转储 {safe}.bin ({len}B)");
                            } catch (Exception ex) {
                                Log.Write($"[DLL] 转储失败: {ex.Message}");
                            }
                            break;
                        }
                        case 0xFE:
                            _proc!.ResumeMainThread();
                            Log.Write("主线程已恢复，游戏启动。");
                            break;
                    }
                }
            } catch (IOException e) when (e.Message.Contains("busy") || e.Message.Contains("占用")) {
                Log.Write($"管道创建失败（可能有残留实例占用）：{e.Message}");
            } catch (IOException) { } // 管道断开（游戏退出）
        });

        _proc = new GameProcess(exePath);
        Log.Write($"游戏进程已创建 (PID {_proc.Id})，等待注入 DLL 连接...");
        _proc.LoadLibrary(libPath);
        _proc.OnExit += () => {
            Log.Write($"游戏已退出 (exit code 0x{_proc.ExitCode:X8})。");
            lock (Lock) {
                Log.Write(Lines.Count > 0
                    ? $"共截获 {Lines.Count} 条事件，配对结果见 {Path.GetFullPath(PairedPath)}"
                    : "未截获任何密钥（游戏内播放加密视频时才会触发）。");
            }
            Environment.Exit(0);
        };
        Log.Write("进入游戏并播放加密过场动画（如 300317-300321 对应的剧情），配对密钥将实时写入 paired_keys.json");
        AppDomain.CurrentDomain.ProcessExit += (_, _) => _proc.Terminate(0);

        while (true) {
            Thread.Sleep(1000);
        }
    }

    private static bool sp_len1(string msg) => msg.Split(' ').Length >= 2;

    private static void HandleMessage(string msg) {
        try {
            lock (Lock) {
                if (!Lines.Contains(msg)) {
                    Lines.Add(msg);
                    if (msg.StartsWith("MANAKEY")) {
                        // 原始日志照常落盘 (兼容 vk_sniff_test.py 等旧流程)
                        File.AppendAllText(KeysPath, msg + Environment.NewLine);
                    }
                }
            }
            if (msg.StartsWith("MANAFILE")) {
                // MANAFILE [idx] path —— 该 player 接下来/此前设置的密钥归属此文件
                var sp = msg.Split(' ', 3);
                if (sp.Length == 3 && int.TryParse(sp[1].Trim('[', ']'), out var idx)) {
                    var file = Path.GetFileName(sp[2]);
                    if (file.EndsWith(".usm", StringComparison.OrdinalIgnoreCase)) {
                        file = file[..^4];
                    }
                    lock (Lock) {
                        PlayerFile[idx] = file;
                        LastFile = file;
                        Flush(idx);
                        if (GlobalPendingMask != null) {
                            EmitMask(file, GlobalPendingMask);
                            GlobalPendingMask = null;
                        }
                        if (GlobalPendingM2 != null) {
                            Emit(file, GlobalPendingM2.Value.aes, GlobalPendingM2.Value.audio);
                            GlobalPendingM2 = null;
                        }
                    }
                    Log.Write($"★ 文件 [{idx}]: {file}");
                }
                Log.Write($"[DLL] {msg}");
                return;
            }
            if (msg.StartsWith("MANAKEYN3") || msg.StartsWith("MANAKEYN2") || msg.StartsWith("MANAKEYN1")) {
                // 带索引: MANAKEYN3 [i] {audio} AES={hex} / MANAKEYN2 [i] {v} {a} / MANAKEYN1 [i] {k}
                var sp = msg.Split(' ');
                if (sp.Length >= 2 && int.TryParse(sp[1].Trim('[', ']'), out var idx)) {
                    if (msg.StartsWith("MANAKEYN3") && sp.Length >= 4) {
                        var audio = sp[2];
                        var aes = sp[3].StartsWith("AES=") ? sp[3][4..] : "";
                        if (aes.Length == 32) {
                            lock (Lock) {
                                if (!PendingM2.ContainsKey(idx)) {
                                    PendingM2[idx] = new List<(string, string)>();
                                }
                                PendingM2[idx].Add((aes, audio));
                                Flush(idx);
                            }
                            Log.Write($"★ method2 密钥 [{idx}]: audio={audio} AES={aes}");
                            return;
                        }
                    }
                    if (msg.StartsWith("MANAKEYN2") && sp.Length >= 4) {
                        lock (Lock) {
                            if (!PendingMask.ContainsKey(idx)) {
                                PendingMask[idx] = new List<string>();
                            }
                            PendingMask[idx].Add(sp[2]);
                            Flush(idx);
                        }
                        Log.Write($"★ 掩码密钥 [{idx}]: {sp[2]}");
                        return;
                    }
                    if (msg.StartsWith("MANAKEYN1") && sp.Length >= 3) {
                        lock (Lock) {
                            if (!PendingMask.ContainsKey(idx)) {
                                PendingMask[idx] = new List<string>();
                            }
                            PendingMask[idx].Add(sp[2]);
                            Flush(idx);
                        }
                        Log.Write($"★ 掩码密钥 [{idx}]: {sp[2]}");
                        return;
                    }
                }
            }
            if (msg.StartsWith("MANAKEY1") && sp_len1(msg)) {
                // 旧体系 S1: MANAKEY1 {videoKey} → 掩码 key (音频同 key)
                var k = msg.Split(' ');
                if (k.Length >= 2) {
                    if (LastFile != "") {
                        EmitMask(LastFile, k[1]);
                    } else {
                        GlobalPendingMask = k[1];
                    }
                    Log.Write($"★ 掩码密钥(S1): {k[1]}" + (LastFile != "" ? $" → {LastFile}" : " (等待文件名)"));
                    return;
                }
            }
            if (msg.StartsWith("MANAKEY2")) {
                // 旧体系 S2: MANAKEY2 {videoKey} {audioKey} → 掩码 key
                var k = msg.Split(' ');
                if (k.Length >= 3) {
                    if (LastFile != "") {
                        EmitMask(LastFile, k[1]);
                    } else {
                        GlobalPendingMask = k[1];
                    }
                    Log.Write($"★ 掩码密钥(S2): {k[1]}" + (LastFile != "" ? $" → {LastFile}" : " (等待文件名)"));
                    return;
                }
            }
            if (msg.StartsWith("MANAKEY3") && msg.Contains("AES=")) {
                // 无索引 S3: MANAKEY3 {audio} AES={hex} → 配最近一次文件名
                var sp = msg.Split(' ');
                if (sp.Length >= 3 && sp[2].StartsWith("AES=") && sp[2].Length == 4 + 32) {
                    if (LastFile != "") {
                        Emit(LastFile, sp[2][4..], sp[1]);
                    } else {
                        GlobalPendingM2 = (sp[2][4..], sp[1]);
                    }
                    Log.Write($"★ method2 密钥(S3): audio={sp[1]}" + (LastFile != "" ? $" → {LastFile}" : " (等待文件名)"));
                    return;
                }
            }
            if (msg.StartsWith("MANAKEY")) {
                Log.Write($"★ 密钥事件: {msg}");
            } else {
                Log.Write($"[DLL] {msg}");
            }
        } catch (Exception e) {
            Log.Write($"HandleMessage 异常: {e.Message}");
        }
    }

    /// idx 侧文件名与密钥都齐了 → 输出
    private static void Flush(int idx) {
        if (!PlayerFile.TryGetValue(idx, out var file) || file.Length == 0) {
            return;
        }
        if (PendingM2.TryGetValue(idx, out var m2s)) {
            foreach (var (aes, audio) in m2s) {
                Emit(file, aes, audio);
            }
            PendingM2.Remove(idx);
        }
        if (PendingMask.TryGetValue(idx, out var masks)) {
            foreach (var k in masks) {
                EmitMask(file, k);
            }
            PendingMask.Remove(idx);
        }
    }

    /// 4.5 method2: { "文件名": {"aes": "...", "audio": "..."} }
    private static void Emit(string file, string aes, string audio) {
        var key = file + "|" + aes;
        lock (Lock) {
            if (!Emitted.Add(key)) {
                return;
            }
            try {
                var path = Path.Combine(AppContext.BaseDirectory, PairedPath);
                JsonStore.UpsertMethod2(path, file, aes, audio);
                Log.Write($"★★ 已配对 {file} → paired_keys.json (aes={aes[..8]}… audio={audio[..8]}…)");
            } catch (Exception e) {
                Log.Write($"写 paired_keys.json 失败: {e.Message}");
            }
        }
    }

    /// 4.4 掩码: { "文件名": "videoKeyHex" }
    private static void EmitMask(string file, string videoKey) {
        var key = file + "|mask|" + videoKey;
        lock (Lock) {
            if (!Emitted.Add(key)) {
                return;
            }
            try {
                var path = Path.Combine(AppContext.BaseDirectory, PairedPath);
                JsonStore.UpsertMask(path, file, videoKey);
                Log.Write($"★★ 已配对(掩码) {file} → paired_keys.json ({videoKey})");
            } catch (Exception e) {
                Log.Write($"写 paired_keys.json 失败: {e.Message}");
            }
        }
    }

}
