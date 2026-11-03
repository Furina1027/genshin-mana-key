using System.Globalization;
using System.Text;
using System.Text.Json;

namespace GenshinSniffer;

/// <summary>
/// 一个视频的密钥条目。三个字段互相独立，**按字段合并**：
///   Aes      7.1+ 的视频 AES-128（32 hex）
///   Audio    7.1+ 的 HCA audioKey（16 hex；HCA ciph=56 只用低 56 位，高 8 位通常为 0）
///   VideoKey ≤7.0 旧体系的 videoKey / finalKey（16 hex；旧文件里 audio 与它同值）
///
/// 用可空/空串而不是一条 union：同一份 paired_keys.json 里可能同时存在新老两种条目，
/// 合并时必须"有则更新、无则保留" —— 否则 BCKEY 的 aes 会把 MANAKEY4 刚写进来的 audio 抹掉。
/// </summary>
internal sealed class KeyEntry {

    public string Aes = "";
    public string Audio = "";
    public string VideoKey = "";

    public bool IsEmpty => Aes.Length == 0 && Audio.Length == 0 && VideoKey.Length == 0;

    /// <summary>
    /// 旧体系条目：只有 videoKey（或 audio 与它同值）—— 写盘时还原成 hk4e_keys.json 的裸字符串形态。
    /// 旧体系 videoKey 与 audioKey 本来就是同一个值（HCA 只用低 56 位），库里只存一个就够。
    /// </summary>
    public bool IsLegacyOnly => Aes.Length == 0 && VideoKey.Length > 0
                                && (Audio.Length == 0 || Audio == VideoKey);

    public KeyEntry Clone() => new() { Aes = Aes, Audio = Audio, VideoKey = VideoKey };
}

/// <summary>
/// paired_keys.json 的存储（NativeAOT 安全的无反射用法）。
///
/// 文件形态（**缩进美化**，可直接人工查阅）：
///   {
///     "Cs_ZD_AQ70201201_SLT": {
///       "aes": "F5AC17FFE4B4B430553AE073EB8A8A1D",
///       "audio": "0004BA5069B44BD4"
///     },
///     "Video_Reunion_67": "0004CDB4745CD9EF"
///   }
///
/// 为什么旧条目保留裸字符串：hoyo-files 的 hk4e_keys.json 里 ≤7.0 就是这个形态，
/// 写回时保持一致，合并工具不需要额外转换。新条目（有 aes/audio 任一）写成对象。
///
/// 为什么不用 JsonSerializer：反射序列化在 NativeAOT 下要么需要源生成器、要么被裁剪掉，
/// 这里只保留 JsonDocument（读）+ Utf8JsonWriter（写），IL 上完全静态可达。
///
/// 为什么必须原子写：这个文件是**累积的密钥库**，一把密钥要跑一次游戏才能拿到。
/// 直接 File.WriteAllText 截断重写时，只要进程/游戏在写入中途崩掉，
/// 已经积累的全部密钥就一次性清零 —— 那是不可接受的损失。
/// 所以改成：写同目录临时文件 → File.Move(overwrite) 原子替换，任何时刻磁盘上要么是旧内容要么是新内容。
/// </summary>
internal static class JsonStore {

    private const string TempInfix = ".tmp-";
    private const int AesHexLength = 32;
    private const int Key64HexLength = 16;

    /// <summary>
    /// 读取现有文件为 文件名 → <see cref="KeyEntry"/>。
    /// 兼容三种历史形态：
    ///   · 对象 {"aes","audio","videoKey"} —— 新形态；
    ///   · 对象 {"aes","audio"} —— 7.1 的 method2 形态；
    ///   · 裸字符串（16 hex）—— ≤7.0 的旧 videoKey/finalKey。
    /// 损坏时不覆盖不丢弃：原文件改名备份成 path + ".corrupt-" + 时间戳，从空表继续。
    /// </summary>
    public static Dictionary<string, KeyEntry> Load(string path) {
        var dict = new Dictionary<string, KeyEntry>(StringComparer.Ordinal);
        if (!File.Exists(path)) {
            return dict;
        }
        string text;
        try {
            text = File.ReadAllText(path);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            Log.Warn($"读取 {Path.GetFileName(path)} 失败（按空表继续）：{e.Message}");
            return dict;
        }
        // 空文件（上一次写盘刚创建文件就被杀掉）没有数据可丢，不算损坏，也不需要备份
        if (string.IsNullOrWhiteSpace(text)) {
            return dict;
        }
        try {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) {
                throw new JsonException($"根节点是 {doc.RootElement.ValueKind}，不是 JSON 对象");
            }
            foreach (var prop in doc.RootElement.EnumerateObject()) {
                var entry = ReadEntry(prop.Value);
                if (!entry.IsEmpty) {
                    dict[prop.Name] = entry;
                }
            }
            return dict;
        } catch (JsonException e) {
            BackupCorrupt(path, e);
            return dict;
        }
    }

    /// <summary>读一个值：裸字符串按旧 videoKey 处理；对象按字段读，非法字段忽略。</summary>
    private static KeyEntry ReadEntry(JsonElement value) {
        var entry = new KeyEntry();
        if (value.ValueKind == JsonValueKind.String) {
            var s = value.GetString() ?? "";
            if (IsHex(s, Key64HexLength)) {
                entry.VideoKey = s.ToUpperInvariant();
            }
            return entry;
        }
        if (value.ValueKind != JsonValueKind.Object) {
            return entry;
        }
        if (value.TryGetProperty("aes", out var aes) && aes.ValueKind == JsonValueKind.String) {
            var s = aes.GetString() ?? "";
            if (IsHex(s, AesHexLength)) {
                entry.Aes = s.ToUpperInvariant();
            }
        }
        if (value.TryGetProperty("audio", out var audio) && audio.ValueKind == JsonValueKind.String) {
            var s = audio.GetString() ?? "";
            if (IsHex(s, Key64HexLength)) {
                entry.Audio = s.ToUpperInvariant();
            }
        }
        if (value.TryGetProperty("videoKey", out var videoKey) && videoKey.ValueKind == JsonValueKind.String) {
            var s = videoKey.GetString() ?? "";
            if (IsHex(s, Key64HexLength)) {
                entry.VideoKey = s.ToUpperInvariant();
            }
        }
        return entry;
    }

    /// <summary>入库一条视频 AES 密钥（BCKEY 通路）。同名覆盖 aes，其它字段保留。</summary>
    public static void UpsertAes(string path, string name, string aes) =>
        UpsertKeys(path, name, aes, "", "");

    /// <summary>
    /// 字段级合并写入（BCKEY / MANAKEY4 共用）。
    /// 空串表示"这次没有该字段"，**不会清掉**库里已有的值；
    /// 这样 BCKEY 的 aes 和 MANAKEY4 的 audio/videoKey 谁先谁后都能正确累积。
    /// </summary>
    public static void UpsertKeys(string path, string name, string aes, string audio, string videoKey) {
        var dict = Load(path);
        if (!dict.TryGetValue(name, out var entry)) {
            entry = new KeyEntry();
            dict[name] = entry;
        }
        if (aes.Length > 0) {
            entry.Aes = aes;
        }
        if (audio.Length > 0) {
            entry.Audio = audio;
        }
        if (videoKey.Length > 0) {
            entry.VideoKey = videoKey;
        }
        Write(path, dict);
    }

    /// <summary>
    /// 把损坏的原文件改名备份（时间戳 + 递增后缀防重名），然后从空表继续。
    /// 为什么要备份而不是直接重写：损坏文件里可能还有肉眼可救的历史密钥，
    /// 覆盖掉就真没了；改名后用户还能自己拿记事本捞回来。
    /// </summary>
    private static void BackupCorrupt(string path, Exception cause) {
        // 时间戳用固定区域性：备份文件名不该随用户区域设置变（阿拉伯语区域的日历会给出完全不同的年份）
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var backup = $"{path}.corrupt-{stamp}";
        for (var i = 1; File.Exists(backup); i++) {
            backup = $"{path}.corrupt-{stamp}-{i}";
        }
        try {
            File.Move(path, backup);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            // 备份都做不到就绝不能继续写（继续写就等于把损坏文件覆盖掉 = 丢数据），
            // 这里抛出，让调用方（写盘处）记录失败并放弃本次写入。
            throw new IOException($"{Path.GetFileName(path)} 已损坏（{cause.Message}），且备份为 {backup} 失败：{e.Message}", e);
        }
        Log.Warn($"★ {Path.GetFileName(path)} 内容损坏（{cause.Message}），原文件已备份为 {Path.GetFileName(backup)}，本次从空表继续。");
    }

    /// <summary>
    /// 原子写：同目录临时文件 → 落盘 → File.Move(overwrite: true)。
    /// 临时文件必须与目标同目录（同一卷），跨卷的 Move 会退化成"复制 + 删除"，就不是原子的了。
    /// </summary>
    private static void Write(string path, Dictionary<string, KeyEntry> dict) {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full) ?? ".";
        Directory.CreateDirectory(dir);
        var tmp = full + TempInfix + Guid.NewGuid().ToString("N")[..8];
        try {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None)) {
                using (var w = new Utf8JsonWriter(fs, new JsonWriterOptions { Indented = true })) {
                    w.WriteStartObject();
                    foreach (var kv in dict) {
                        if (kv.Value.IsEmpty) {
                            continue;
                        }
                        // 旧体系只有 videoKey 时保持裸字符串：与 hk4e_keys.json 的 ≤7.0 条目同形态
                        if (kv.Value.IsLegacyOnly) {
                            w.WriteString(kv.Key, kv.Value.VideoKey);
                            continue;
                        }
                        w.WriteStartObject(kv.Key);
                        if (kv.Value.Aes.Length > 0) {
                            w.WriteString("aes", kv.Value.Aes);
                        }
                        if (kv.Value.Audio.Length > 0) {
                            w.WriteString("audio", kv.Value.Audio);
                        }
                        if (kv.Value.VideoKey.Length > 0) {
                            w.WriteString("videoKey", kv.Value.VideoKey);
                        }
                        w.WriteEndObject();
                    }
                    w.WriteEndObject();
                }
                fs.Flush(true); // 先落盘再替换：崩溃时磁盘上要么是完整旧内容、要么是完整新内容
            }
            File.Move(tmp, full, true);
        } finally {
            try {
                if (File.Exists(tmp)) {
                    File.Delete(tmp);
                }
            } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
                Log.Warn($"清理临时文件 {Path.GetFileName(tmp)} 失败：{e.Message}");
            }
        }
    }

    private static bool IsHex(string value, int length) {
        if (value.Length != length) {
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
