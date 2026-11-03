using System.Globalization;

namespace GenshinSniffer;

/// <summary>
/// 配对种类：Method2 = 7.1 的 AES_HCA（AES + audio），Mask = 旧体系 56 位掩码 videoKey。
/// Aes = BCKEY（只有视频 AES）；MediaKeys = MANAKEY4（CriwareMediaPlayer：aes / audio / 旧 videoKey 三选一）。
/// </summary>
internal enum PairingKind { Method2, Mask, Aes, MediaKeys }

/// <summary>一条可以写盘的结果。用不到的字段是空串（Mask 只填 VideoKey，Method2 只填 Aes/Audio）。</summary>
internal readonly record struct PairingEntry(
    string File, PairingKind Kind, string Aes, string Audio, string VideoKey);

/// <summary>
/// MANA* 上报 →（文件名, 密钥）的配对状态机，**纯逻辑**：
/// 不碰 IO、不碰进程、不起线程 —— 只有这样"密钥早于文件名 / 文件名早于密钥 / 乱序 / 重复"
/// 这些分支才能被单元测试覆盖，而不是靠跑真游戏去赌。
///
/// 协议（与 DLL 端约定，字节语义不能改）：
///   MANAFILE  [idx] &lt;路径&gt;              文件名来源（带 playerIndex）
///   MANAKEYN2 [idx] {video} {audio}       掩码 videoKey（带索引）
///   MANAKEYN1 [idx] {key}                 掩码 key（带索引）
///   MANAKEYN3 [idx] {audio} AES={hex}     method2（带索引）
///   MANAKEY1 {key} / MANAKEY2 {v} {a} / MANAKEY3 {audio} AES={hex}
///                                         无索引：配"最近一次文件名"
///   MANAKEY4 file=… mode=… [aes=…] [audio=…] [videoKey=…]
///                                         CriwareMediaPlayer 密钥结构（自带文件名）
///
/// 为什么用队列而不是单槽暂存：密钥完全可能早于 MANAFILE 到达（DLL 会把启动期
/// 一次性配置的 key 在 SetFile 之前就报上来）。旧实现的 GlobalPendingMask/GlobalPendingM2
/// 是单变量，第二把密钥一到就把第一把静默覆盖 —— 那就是丢密钥。
/// 现在同一个 idx（和无索引场景）都按到达顺序排队，文件名一到整队放出，一条都不漏。
///
/// 线程安全：非线程安全，调用方必须串行调用（启动器里只有管道读取线程会调它）。
/// </summary>
internal sealed class KeyPairing {

    /// <summary>允许的 AES 密钥长度（hex 字符数）：method2 是 AES-128，固定 32 个 hex 字符。</summary>
    private const int AesHexLength = 32;

    /// <summary>audioKey / 旧 videoKey 是 uint64，固定 16 个 hex 字符（左补零）。</summary>
    private const int Key64HexLength = 16;

    /// <summary>待配对的密钥。</summary>
    private readonly record struct PendingKey(PairingKind Kind, string Aes, string Audio, string VideoKey);

    /// <summary>无索引（S1/S2/S3）场景：文件名还没到，先排队。</summary>
    private readonly List<PendingKey> _globalPending = [];

    /// <summary>带索引场景：idx → 待配对队列（同一 idx 反复设钥时追加，不覆盖）。</summary>
    private readonly Dictionary<int, List<PendingKey>> _pendingByIndex = [];

    /// <summary>idx → 已上报的文件名（已去掉 .usm 后缀）。</summary>
    private readonly Dictionary<int, string> _fileByIndex = [];

    /// <summary>已发出的「文件+密钥」指纹：游戏可能反复设同一把 key，重复写盘没有意义。</summary>
    private readonly HashSet<string> _emitted = new(StringComparer.Ordinal);

    private string _lastFile = "";
    private int _lastIndex = -1;
    private int _pendingCount;
    private string? _lastRejectReason;

    /// <summary>最近一次上报的文件名（已去 .usm 后缀）。无索引密钥用它兜底配对。</summary>
    public string LastFile => _lastFile;

    /// <summary>最近一次 MANAFILE 的 playerIndex（-1 = 还没有）。仅用于日志，配对本身不依赖它。</summary>
    public int LastIndex => _lastIndex;

    /// <summary>还压在队列里等文件名的密钥条数（0 = 没有待配对积压）。</summary>
    public int PendingCount => _pendingCount;

    /// <summary>最近一次被丢弃密钥的原因（null = 没丢弃）。供调用方打日志 —— 纯逻辑类自己不写日志。</summary>
    public string? LastRejectReason => _lastRejectReason;

    /// <summary>输入一条 DLL 上报，返回本次需要写盘的条目（可能为空）。</summary>
    public IReadOnlyList<PairingEntry> Handle(string message) {
        _lastRejectReason = null;
        if (string.IsNullOrEmpty(message)) {
            return Array.Empty<PairingEntry>();
        }
        // 判断顺序不能改：MANAKEYN1/N2/N3 也以 MANAKEY 开头，带索引的分支必须先判，
        // 否则 "MANAKEYN1 [0] abc" 会被无索引的 MANAKEY1 分支当成 "N1" 这个 key。
        // BCKEY 自带文件名，不需要跟 MANAFILE 配对；而且实测它是**唯一**真正产出密钥的通路
        if (message.StartsWith("BCKEY", StringComparison.Ordinal)) {
            return HandleBcKey(message);
        }
        // MANAKEY4 也自带文件名（DLL 从 CriwareMediaPlayer 的 videoRuntimePath 读）。
        // 必须放在 MANAKEYN1/N2/N3 之前判：虽然 "MANAKEY4" 不会命中 "MANAKEYN3"，
        // 但保持"带索引的 N 系列先判"的既有顺序更不容易在今后的协议扩展里踩坑。
        if (message.StartsWith("MANAKEY4", StringComparison.Ordinal)) {
            return HandleMediaKeys(message);
        }
        if (message.StartsWith("MANAFILE ", StringComparison.Ordinal)) {
            return HandleSetFile(message);
        }
        if (message.StartsWith("MANAKEYN3", StringComparison.Ordinal)) {
            return HandleIndexedMethod2(message);
        }
        if (message.StartsWith("MANAKEYN2", StringComparison.Ordinal)) {
            return HandleIndexedMask(message, minParts: 4);
        }
        if (message.StartsWith("MANAKEYN1", StringComparison.Ordinal)) {
            return HandleIndexedMask(message, minParts: 3);
        }
        // 无索引：MANAKEY1 {key} / MANAKEY2 {video} {audio} 都是掩码体系（音频与视频同 key）
        if (message.StartsWith("MANAKEY1", StringComparison.Ordinal)) {
            return HandleLegacyMask(message, minParts: 2);
        }
        if (message.StartsWith("MANAKEY2", StringComparison.Ordinal)) {
            return HandleLegacyMask(message, minParts: 3);
        }
        if (message.StartsWith("MANAKEY3", StringComparison.Ordinal)
            && message.Contains("AES=", StringComparison.Ordinal)) {
            return HandleLegacyMethod2(message);
        }
        return Array.Empty<PairingEntry>();
    }

    /// <summary>
    /// `BCKEY #n file={名字} len=16 {32hex} [rep=… uni=…]` —— bcrypt 通路（实测唯一真正产出密钥的）。
    ///
    /// 为什么它不走队列：文件名就在这条消息里（DLL 用当前播放文件标好了归属），
    /// 所以拿到就能直接配对，不存在"等文件名"的场景。
    ///
    /// 为什么 `file=?` 必须拒绝：DLL 在还没收到 SetFile 时会用 `?` 占位，
    /// 把密钥挂到 `?` 上比丢掉它更糟 —— 那会往密钥库里塞一条永远对不上的脏记录。
    /// </summary>
    private PairingEntry[] HandleBcKey(string message) {
        var sp = message.Split(' ');
        string? rawFile = null;
        string? keyHex = null;
        foreach (var token in sp.Skip(1)) {
            if (token.StartsWith("file=", StringComparison.Ordinal)) {
                rawFile = token["file=".Length..];
            } else if (token.StartsWith("len=", StringComparison.Ordinal)) {
                if (!int.TryParse(token["len=".Length..], NumberStyles.Integer, CultureInfo.InvariantCulture, out var len)
                    || len != AesHexLength / 2) {
                    _lastRejectReason = $"BCKEY 的 len 不是 {AesHexLength / 2} 字节";
                    return Array.Empty<PairingEntry>();
                }
            } else if (IsAesHex(token)) {
                keyHex = token.ToUpperInvariant();
            }
        }
        if (rawFile == null || keyHex == null) {
            _lastRejectReason = "BCKEY 缺少 file= 或缺 32 位十六进制密钥";
            return Array.Empty<PairingEntry>();
        }
        // DLL 在归属未知时报 "?"；解析失败哨兵以 '(' 开头（与 MANAFILE 同一套规则）
        if (rawFile.Length == 0 || rawFile == "?" || rawFile[0] == '(') {
            _lastRejectReason = $"BCKEY 的密钥没有归属到具体视频（file={rawFile}）";
            return Array.Empty<PairingEntry>();
        }
        var file = StripUsmExtension(Path.GetFileName(rawFile));
        if (file.Length == 0) {
            _lastRejectReason = "BCKEY 的文件名为空";
            return Array.Empty<PairingEntry>();
        }
        // 同一个视频同一把密钥只写一次（DLL 会以 rep=1/2/3 重复上报同一把）
        if (!_emitted.Add($"{file}|aes|{keyHex}")) {
            return Array.Empty<PairingEntry>();
        }
        return [new PairingEntry(file, PairingKind.Aes, keyHex, "", "")];
    }

    /// <summary>
    /// `MANAKEY4 file=… mode=… [aes=…] [audio=…] [videoKey=…]` —— CriwareMediaPlayer 密钥结构。
    ///
    /// mode 1（7.1+ AES）：aes = 32 hex，audio = 16 hex（HCA keycode，只有低 56 位有效）
    /// mode 0（旧体系）：videoKey = 16 hex（旧 finalKey），audio 与它同值
    ///
    /// 为什么允许"只有 audio / 只有 videoKey"：DLL 在结构刚填好、AES 数组还没就绪时也可能读到一个字段。
    /// 这条 entry 只带它确实有的字段，JsonStore 做**字段级合并**，不会被后来的 BCKEY 整条覆盖。
    /// </summary>
    private PairingEntry[] HandleMediaKeys(string message) {
        var sp = message.Split(' ');
        string? rawFile = null;
        var aes = "";
        var audio = "";
        var videoKey = "";
        foreach (var token in sp.Skip(1)) {
            if (token.StartsWith("file=", StringComparison.Ordinal)) {
                rawFile = token["file=".Length..];
            } else if (token.StartsWith("aes=", StringComparison.Ordinal)) {
                var value = token["aes=".Length..];
                if (!IsAesHex(value)) {
                    _lastRejectReason = $"MANAKEY4 的 AES 不是 32 位十六进制（实际 {value.Length} 字符）";
                    return Array.Empty<PairingEntry>();
                }
                aes = value.ToUpperInvariant();
            } else if (token.StartsWith("audio=", StringComparison.Ordinal)) {
                var value = token["audio=".Length..];
                if (!IsKey64Hex(value)) {
                    _lastRejectReason = $"MANAKEY4 的 audio 不是 16 位十六进制（实际 {value.Length} 字符）";
                    return Array.Empty<PairingEntry>();
                }
                audio = value.ToUpperInvariant();
            } else if (token.StartsWith("videoKey=", StringComparison.Ordinal)) {
                var value = token["videoKey=".Length..];
                if (!IsKey64Hex(value)) {
                    _lastRejectReason = $"MANAKEY4 的 videoKey 不是 16 位十六进制（实际 {value.Length} 字符）";
                    return Array.Empty<PairingEntry>();
                }
                videoKey = value.ToUpperInvariant();
            }
        }
        if (rawFile == null) {
            _lastRejectReason = "MANAKEY4 缺少 file=";
            return Array.Empty<PairingEntry>();
        }
        // 与 BCKEY/MANAFILE 同一套规则：? 与解析失败哨兵都拒绝
        if (rawFile.Length == 0 || rawFile == "?" || rawFile[0] == '(') {
            _lastRejectReason = $"MANAKEY4 的密钥没有归属到具体视频（file={rawFile}）";
            return Array.Empty<PairingEntry>();
        }
        if (aes.Length == 0 && audio.Length == 0 && videoKey.Length == 0) {
            _lastRejectReason = "MANAKEY4 的三个密钥字段全为空";
            return Array.Empty<PairingEntry>();
        }
        var file = StripUsmExtension(Path.GetFileName(rawFile));
        if (file.Length == 0) {
            _lastRejectReason = "MANAKEY4 的文件名为空";
            return Array.Empty<PairingEntry>();
        }
        if (!_emitted.Add($"{file}|mk|{aes}|{audio}|{videoKey}")) {
            return Array.Empty<PairingEntry>();
        }
        return [new PairingEntry(file, PairingKind.MediaKeys, aes, audio, videoKey)];
    }

    /// <summary>MANAFILE [idx] path —— 记录该 idx 的文件名，并把该 idx（以及无索引场景）攒下的密钥全部放出。</summary>
    private IReadOnlyList<PairingEntry> HandleSetFile(string message) {
        var sp = message.Split(' ', 3);
        if (sp.Length < 3 || !TryParseIndex(sp[1], out var idx)) {
            _lastRejectReason = "MANAFILE 缺少 [idx] 或路径";
            return Array.Empty<PairingEntry>();
        }
        var file = StripUsmExtension(Path.GetFileName(sp[2]));
        if (file.Length == 0) {
            _lastRejectReason = "MANAFILE 文件名为空";
            return Array.Empty<PairingEntry>();
        }
        // DLL 侧 il2cpp 字符串解析失败时会报哨兵串（(null)/(unreadable)/(bad len N)/(read error)，
        // 全部以 '(' 开头）。这些不是文件名：一旦写进密钥库就会留下 "(null)": {...} 这种污染条目，
        // 而且实测日志里 60 条 BCKEY 全部 file=(null) 就是被它拖下水的。
        // DLL 已按同样规则忽略哨兵，这里再挡一道 —— 上报内容不可信，密钥库不接受脏键。
        if (file[0] == '(') {
            _lastRejectReason = "MANAFILE 文件名是解析失败哨兵";
            return Array.Empty<PairingEntry>();
        }
        _fileByIndex[idx] = file;
        _lastFile = file;
        _lastIndex = idx;
        var result = new List<PairingEntry>();
        // 先放本 idx 的（精确配对），再放无索引暂存的（旧体系 S1/S2/S3 兜底配对）
        if (_pendingByIndex.Remove(idx, out var queued)) {
            Drain(queued, file, result);
        }
        Drain(_globalPending, file, result);
        return result;
    }

    /// <summary>MANAKEYN3 [idx] {audio} AES={32hex} —— method2（带索引）。</summary>
    private IReadOnlyList<PairingEntry> HandleIndexedMethod2(string message) {
        var sp = message.Split(' ');
        if (sp.Length < 4 || !TryParseIndex(sp[1], out var idx)) {
            _lastRejectReason = "MANAKEYN3 参数不足或 [idx] 非法";
            return Array.Empty<PairingEntry>();
        }
        if (!sp[3].StartsWith("AES=", StringComparison.Ordinal)) {
            _lastRejectReason = "MANAKEYN3 缺少 AES= 前缀";
            return Array.Empty<PairingEntry>();
        }
        var aes = sp[3]["AES=".Length..];
        if (!IsAesHex(aes)) {
            _lastRejectReason = $"method2 的 AES 不是 32 位十六进制（实际 {aes.Length} 字符）";
            return Array.Empty<PairingEntry>();
        }
        return HandleIndexed(idx, new PendingKey(PairingKind.Method2, aes, sp[2], ""));
    }

    /// <summary>MANAKEYN2 [idx] {video} {audio} / MANAKEYN1 [idx] {key} —— 掩码体系（都取第 3 段作为 videoKey）。</summary>
    private IReadOnlyList<PairingEntry> HandleIndexedMask(string message, int minParts) {
        var sp = message.Split(' ');
        if (sp.Length < minParts || !TryParseIndex(sp[1], out var idx)) {
            _lastRejectReason = $"带索引的掩码密钥参数不足（需要 {minParts} 段）或 [idx] 非法";
            return Array.Empty<PairingEntry>();
        }
        return HandleIndexed(idx, new PendingKey(PairingKind.Mask, "", "", sp[2]));
    }

    /// <summary>无索引 MANAKEY1/MANAKEY2 —— 掩码体系，配最近一次文件名。</summary>
    private IReadOnlyList<PairingEntry> HandleLegacyMask(string message, int minParts) {
        var sp = message.Split(' ');
        if (sp.Length < minParts) {
            _lastRejectReason = $"掩码密钥参数不足（需要 {minParts} 段）";
            return Array.Empty<PairingEntry>();
        }
        return HandleLegacy(new PendingKey(PairingKind.Mask, "", "", sp[1]));
    }

    /// <summary>无索引 MANAKEY3 {audio} AES={32hex} —— method2，配最近一次文件名。</summary>
    private IReadOnlyList<PairingEntry> HandleLegacyMethod2(string message) {
        var sp = message.Split(' ');
        if (sp.Length < 3 || !sp[2].StartsWith("AES=", StringComparison.Ordinal)) {
            _lastRejectReason = "MANAKEY3 格式不是 {audio} AES={32hex}";
            return Array.Empty<PairingEntry>();
        }
        var aes = sp[2]["AES=".Length..];
        if (!IsAesHex(aes)) {
            _lastRejectReason = $"method2 的 AES 不是 32 位十六进制（实际 {aes.Length} 字符）";
            return Array.Empty<PairingEntry>();
        }
        return HandleLegacy(new PendingKey(PairingKind.Method2, aes, sp[1], ""));
    }

    /// <summary>带索引的密钥：文件名已知就直接配对，否则进该 idx 的队列等文件名。</summary>
    private IReadOnlyList<PairingEntry> HandleIndexed(int idx, PendingKey key) {
        if (_fileByIndex.TryGetValue(idx, out var file) && file.Length > 0) {
            var immediate = new List<PairingEntry>(1);
            Emit(file, key, immediate);
            return immediate;
        }
        if (!_pendingByIndex.TryGetValue(idx, out var queue)) {
            queue = [];
            _pendingByIndex[idx] = queue;
        }
        queue.Add(key);
        _pendingCount++;
        return Array.Empty<PairingEntry>();
    }

    /// <summary>无索引的密钥：有"最近一次文件名"就直接配对（可能张冠李戴，但这是旧体系的兜底语义），否则排队。</summary>
    private IReadOnlyList<PairingEntry> HandleLegacy(PendingKey key) {
        if (_lastFile.Length > 0) {
            var immediate = new List<PairingEntry>(1);
            Emit(_lastFile, key, immediate);
            return immediate;
        }
        _globalPending.Add(key);
        _pendingCount++;
        return Array.Empty<PairingEntry>();
    }

    /// <summary>整队放出：按到达顺序逐条发，然后清空队列。</summary>
    private void Drain(List<PendingKey> queue, string file, List<PairingEntry> result) {
        if (queue.Count == 0) {
            return;
        }
        foreach (var key in queue) {
            Emit(file, key, result);
        }
        _pendingCount -= queue.Count;
        queue.Clear();
    }

    /// <summary>去重后产出：同一「文件+密钥」只发一次。</summary>
    private void Emit(string file, PendingKey key, List<PairingEntry> result) {
        var fingerprint = key.Kind == PairingKind.Method2
            ? $"{file}|{key.Aes}"
            : $"{file}|mask|{key.VideoKey}";
        if (!_emitted.Add(fingerprint)) {
            return;
        }
        result.Add(new PairingEntry(file, key.Kind, key.Aes, key.Audio, key.VideoKey));
    }

    /// <summary>[idx] → idx；同时容忍 DLL 写成 "0" 或 "[0]"（Trim 掉两侧方括号）。</summary>
    private static bool TryParseIndex(string token, out int idx) =>
        int.TryParse(token.Trim('[', ']'), NumberStyles.Integer, CultureInfo.InvariantCulture, out idx);

    /// <summary>去掉 .usm 后缀（大小写不敏感：DLL 报的可能是 .USM）。</summary>
    private static string StripUsmExtension(string file) =>
        file.EndsWith(".usm", StringComparison.OrdinalIgnoreCase) ? file[..^4] : file;

    /// <summary>method2 的 AES 必须是 32 个十六进制字符，否则不当作密钥（畸形上报不该污染密钥库）。</summary>
    private static bool IsAesHex(string value) {
        if (value.Length != AesHexLength) {
            return false;
        }
        foreach (var c in value) {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex) {
                return false;
            }
        }
        return true;
    }

    /// <summary>audioKey / 旧 videoKey 是 uint64，库里固定 16 个 hex 字符（左补零）。</summary>
    private static bool IsKey64Hex(string value) {
        if (value.Length != Key64HexLength) {
            return false;
        }
        foreach (var c in value) {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex) {
                return false;
            }
        }
        return true;
    }

}
