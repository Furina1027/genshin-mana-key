using System.Globalization;
using System.Text;
using System.Text.Json;

namespace GenshinSniffer;

/// <summary>
/// paired_keys.json 的最小 KV 存储（NativeAOT 安全的无反射用法）。
///
/// 值保持两种形态（与 hoyo-files key 库直接兼容）：
///   { "文件名": "掩码hex" }                          ← 4.4 掩码体系
///   { "文件名": {"aes":"..","audio":".."} }          ← 4.5 method2(AES_HCA)
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

    /// <summary>
    /// 读取现有文件为 name -> 原始 JSON 值文本（字符串值**含引号**，与文件里的文本一致）。
    /// 损坏时不覆盖不丢弃：原文件改名备份成 path + ".corrupt-" + 时间戳，从空表继续。
    /// </summary>
    public static Dictionary<string, string> Load(string path) {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        if (!File.Exists(path)) {
            return dict;
        }
        string text;
        try {
            text = File.ReadAllText(path);
        } catch (Exception e) when (e is IOException or UnauthorizedAccessException) {
            Log.Write($"读取 {Path.GetFileName(path)} 失败（按空表继续）：{e.Message}");
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
                // GetRawText() 就是文件里的原始值文本 → 原样回写不会二次转义（旧实现读时不反转义，会逐次膨胀）
                dict[prop.Name] = prop.Value.GetRawText();
            }
            return dict;
        } catch (JsonException e) {
            BackupCorrupt(path, e);
            return dict;
        }
    }

    /// <summary>4.5 method2：{ "文件名": {"aes":"..","audio":".."} }。</summary>
    public static void UpsertMethod2(string path, string name, string aes, string audio) {
        var dict = Load(path);
        dict[name] = BuildValueText(w => {
            w.WriteStartObject();
            w.WriteString("aes", aes);
            w.WriteString("audio", audio);
            w.WriteEndObject();
        });
        Write(path, dict);
    }

    /// <summary>
    /// 仅视频 AES 密钥：{ "文件名": {"aes":".."} }。
    ///
    /// 为什么不像 method2 那样写空 audio：BCKEY（bcrypt 通路）只拿得到视频密钥，
    /// 音频 key 属于那 4 个 MANAKEY* 钩子（实测 0 次调用）。写 `"audio":""` 等于对下游
    /// 宣称"音频 key 是空字符串"，会把一条错记录带进 key 库；不如干脆不写这个字段。
    /// </summary>
    public static void UpsertAes(string path, string name, string aes) {
        var dict = Load(path);
        dict[name] = BuildValueText(w => {
            w.WriteStartObject();
            w.WriteString("aes", aes);
            w.WriteEndObject();
        });
        Write(path, dict);
    }

    /// <summary>4.4 掩码：{ "文件名": "videoKeyHex" }。</summary>
    public static void UpsertMask(string path, string name, string videoKey) {
        var dict = Load(path);
        dict[name] = BuildValueText(w => w.WriteStringValue(videoKey));
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
        Log.Write($"★ {Path.GetFileName(path)} 内容损坏（{cause.Message}），原文件已备份为 {Path.GetFileName(backup)}，本次从空表继续。");
    }

    /// <summary>用 Utf8JsonWriter 生成一段规范 JSON 值文本（转义/控制字符都由 writer 保证合法）。</summary>
    private static string BuildValueText(Action<Utf8JsonWriter> write) {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms)) {
            write(w);
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    /// <summary>
    /// 原子写：同目录临时文件 → 落盘 → File.Move(overwrite: true)。
    /// 临时文件必须与目标同目录（同一卷），跨卷的 Move 会退化成"复制 + 删除"，就不是原子的了。
    /// </summary>
    private static void Write(string path, Dictionary<string, string> dict) {
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full) ?? ".";
        Directory.CreateDirectory(dir);
        var tmp = full + TempInfix + Guid.NewGuid().ToString("N")[..8];
        try {
            using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None)) {
                using (var w = new Utf8JsonWriter(fs)) {
                    w.WriteStartObject();
                    foreach (var kv in dict) {
                        w.WritePropertyName(kv.Key);
                        // 值按原始 JSON 文本回写：字符串值连引号一起保留，反复读写不会逐次加转义
                        w.WriteRawValue(kv.Value);
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
                Log.Write($"清理临时文件 {Path.GetFileName(tmp)} 失败：{e.Message}");
            }
        }
    }

}
