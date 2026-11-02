namespace GenshinSniffer;

/// <summary>
/// 版本指纹：「这份 RVA 常量到底属于哪一版 exe」的自证机制。
///
/// 为什么要它：运行时那四道门（RVA≠0 → 落在可执行节 → 可读 → 序言像函数入口，见
/// Application.TryResolveTarget）**只能证明"这是个函数入口"**，证明不了"这个函数是
/// NativeMethods_SetFile"。于是最坏的情况是"上一版的 RVA 在新版里恰好仍然合法"——
/// 那会把补丁打到别的函数上，游戏行为变得无法解释，而日志里一切都"正常"。
///
/// ★ 口径的两个坑（都踩过，注释留证）：
///
///   ① **不能用"前 64KB"**：本 exe 的 FileAlignment=0x200、SectionAlignment=0x1000，
///      加载器在内存里把 `[SizeOfHeaders, 0x1000)` 填零，而文件里那一段是 `.text` 数据。
///      同一份 7.1 国服客户端：文件前 64KB → 0xE597A764，镜像前 64KB → 0xF1CC54E7。
///      所以长度取 **SizeOfHeaders**（7.1 国服 0x400 → CRC32 = 0xC66689B9）。
///
///   ② **更狠的一条：判定不能用内存镜像**。2026-11-02 实跑发现，带保护壳的客户端
///      （本 exe 有 `.tls` 段 + TLS 目录）会在注入线程启动时先跑 TLS 回调，等 DLL 读头部时
///      那 1KB **已被壳改写**：磁盘 0xC66689B9 vs 内存 0x9735915B（同长度、同算法）。
///      若拿内存值去比，就会每次都误报"游戏已更新"，`GMK_STRICT=1` 还会误杀 NF
///      （NF 一挂不上，文件名归属全丢，`BCKEY file=?` 全被拒收）。
///      ⇒ **判定一律走磁盘文件**（Application.TryHashFileHeader 读自身 exe 前 SizeOfHeaders 字节），
///        内存值只写进日志当参照。读不到文件就跳过判定，绝不猜。
///
/// 谁维护它：tools\update_rva.py 在迁移成功后把它一起写回 RvaSet.Fingerprint
/// （Python 侧用同一套判据取长度，见 update_rva.fingerprint_length）。闭环见 README。
///
/// 为什么单独成文件：CRC、长度判定与三态比较都必须是纯函数（不碰地址、不碰 Native），
/// 才能被 tests\ManaKeyDumper.Tests 直接链接同一份源码覆盖 —— 和 Prologue.cs 同理。
/// </summary>
internal static class VersionGuard {

    /// <summary>指纹长度上限（防畸形 SizeOfHeaders 把 CRC 拖成整文件扫描）。</summary>
    public const int FingerprintBytes = 0x10000;

    /// <summary>SizeOfHeaders 的合理下限（最小的合法值通常就是 0x200）。</summary>
    public const int FingerprintMinBytes = 0x200;

    /// <summary>头部读不出来 / SizeOfHeaders 不可信时的兜底长度（MSVC 链接器的常规值）。</summary>
    public const int FingerprintFallbackBytes = 0x400;

    /// <summary>
    /// 从 exe 头部字节里取"指纹应该覆盖多少字节" —— 即 SizeOfHeaders。
    ///
    /// 判据与 tools\update_rva.py 的 <c>fingerprint_length()</c> **必须逐条一致**，否则
    /// 两边算出的指纹不同，表现就是每次启动都报"⚠ 版本指纹不匹配"。任一条不过就返回兜底值
    /// （宁可指纹短一点，也不要一崩溃/误报）。
    /// </summary>
    public static int FingerprintLength(ReadOnlySpan<byte> header) {
        if (header.Length < 0x40) {
            return FingerprintFallbackBytes;
        }
        var eLfanew = ReadU32(header, 0x3C);
        if (eLfanew is < 0x40 or > 0x1000) {
            return FingerprintFallbackBytes;
        }
        var nt = (int) eLfanew;
        // PE 签名(4) + COFF(20) + 可选头里要用到的 0x40 字节（SizeOfHeaders 在可选头 +0x3C）
        if (!Fits(header, nt, 0x18 + 0x40)) {
            return FingerprintFallbackBytes;
        }
        if (ReadU32(header, nt) != 0x00004550u) {     // 'PE\0\0'
            return FingerprintFallbackBytes;
        }
        var optional = nt + 0x18;
        var sizeOfHeaders = ReadU32(header, optional + 0x3C);
        if (sizeOfHeaders < FingerprintMinBytes || sizeOfHeaders > FingerprintBytes) {
            return FingerprintFallbackBytes;
        }
        return (int) sizeOfHeaders;
    }

    /// <summary>
    /// 把一段"exe 头部字节"算成指纹：长度取 SizeOfHeaders，CRC 覆盖 `[0, SizeOfHeaders)`。
    ///
    /// 返回 false = **这段字节算不出可复现的指纹**（声明的 SizeOfHeaders 超过实有字节）。
    /// 此时调用方**必须跳过判定**，绝不能夹一段长度凑一个 CRC —— 那只会是假绿灯或永久误报。
    /// </summary>
    public static bool TryHashHeader(ReadOnlySpan<byte> head, out uint crc, out int length) {
        crc = 0;
        length = FingerprintLength(head);
        if (length <= 0 || length > head.Length) {
            length = 0;
            return false;
        }
        crc = Crc32(head[..length]);
        return true;
    }

    /// <summary>
    /// 标准 CRC-32（IEEE 802.3 / zlib 口径：反射输入输出、多项式 0xEDB88320、
    /// 初值全 1、结果取反）。刻意不用查表：只算一次、几百到几万字节，8 次移位/字节可忽略，
    /// 而省掉"静态表初始化"这条在 NativeAOT 注入 DLL 里更容易出事的路径。
    /// </summary>
    public static uint Crc32(ReadOnlySpan<byte> data) {
        var crc = 0xFFFFFFFFu;
        foreach (var b in data) {
            crc ^= b;
            for (var i = 0; i < 8; i++) {
                // (crc & 1) != 0 时异或多项式：用 -(int) 得到全 1 掩码，避免分支抖动
                crc = (crc >> 1) ^ (0xEDB88320u & (uint) -(int) (crc & 1));
            }
        }
        return ~crc;
    }

    /// <summary>指纹比对的三态（外加"还没检查"）。</summary>
    public enum State {
        /// <summary>还没算过指纹（PE 读不出来 / 还没走到那一步）。</summary>
        Unchecked = 0,

        /// <summary>实测指纹 == 源码登记值：这版 RVA 属于这个 exe。</summary>
        Match = 1,

        /// <summary>登记过但不相等：游戏大概率已更新，源码里的 RVA 是旧的。</summary>
        Mismatch = 2,

        /// <summary>源码没登记（0，例如国际服）：无从校验，只能靠四道门。</summary>
        Unregistered = 3,
    }

    /// <summary>实测值与登记值 → 三态。登记值为 0 视为"未登记"，不是"不匹配"。</summary>
    public static State Compare(uint actual, uint expected) =>
        expected == 0 ? State.Unregistered
            : actual == expected ? State.Match
            : State.Mismatch;

    /// <summary>
    /// 一行日志文案（写进 mana_keys.log / dumper.log）。
    /// 三种状态的措辞刻意不同：只有 Mismatch 是"该动手了"，Unregistered 不是错误。
    /// <paramref name="length"/> &gt; 0 时追加口径（头 N 字节）—— 就是"口径被改坏"时最直接的现场证据。
    /// </summary>
    public static string Describe(State state, uint actual, uint expected, int length = 0) {
        var text = state switch {
            State.Match => $"版本指纹匹配 0x{actual:X8}（这版 RVA 属于这个 exe）",
            State.Mismatch =>
                $"⚠ 版本指纹不匹配：实测 0x{actual:X8}，源码登记 0x{expected:X8} —— 游戏已更新？" +
                "请先跑 tools\\update_rva.cmd；残留旧 RVA 会把补丁打到别的函数上",
            State.Unregistered =>
                $"版本指纹未登记（实测 0x{actual:X8}）：无法校验 RVA 是否属于本版本，" +
                "只能靠四道门（可执行节/可读/序言）自保。跑一次 tools\\update_rva.cmd 即可登记",
            _ => "版本指纹：未检查",
        };
        return length > 0 ? $"{text}（口径：exe 头 {length} 字节）" : text;
    }

    /// <summary>小端 u32 读取（不依赖 BitConverter 的端序假设，也让越界检查写在调用点）。</summary>
    private static uint ReadU32(ReadOnlySpan<byte> b, int offset) =>
        (uint) (b[offset] | (b[offset + 1] << 8) | (b[offset + 2] << 16) | (b[offset + 3] << 24));

    /// <summary>[offset, offset+size) 是否完整落在 span 内（不允许整数溢出）。</summary>
    private static bool Fits(ReadOnlySpan<byte> b, int offset, int size) =>
        offset >= 0 && size >= 0 && offset <= b.Length - size;
}
