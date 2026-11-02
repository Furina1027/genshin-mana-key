using System.Text;
using GenshinSniffer;

namespace ManaKeyDumper.Tests;

/// <summary>
/// 版本指纹（「这版 RVA 属于哪个 exe」的自证机制）测试。
///
/// 四件事必须钉住：
///   1. CRC32 是**标准 zlib 口径** —— 不然 update_rva.py 写回的值和运行时算出来的对不上，
///      表现是每次启动都"⚠ 版本指纹不匹配"，比没有这个机制更糟；
///   2. 指纹长度 = `SizeOfHeaders`，且异常头部一律兜底 —— 这是"文件与内存镜像算得出同一个值"
///      的唯一前提（本 exe FileAlignment 0x200 ≠ SectionAlignment 0x1000，
///      镜像里 `[SizeOfHeaders, 0x1000)` 是 0 填充，**不是**文件里的 `.text` 数据）；
///   3. 三态语义："登记 0" 是**未登记**（不是不匹配），否则国际服会被 GMK_STRICT 一刀切死；
///   4. 与真实 exe 的对拍：`rva_cache\YuanShen.exe`（7.1 国服）头 `SizeOfHeaders=0x400` 字节的
///      CRC32 必须等于源码登记给国服的 `0xC66689B9`，且**不等于**"文件前 64KB"的 `0xE597A764`
///      （后者是本文件记录的那个坑）。
///   仓库里没有缓存 exe 时自动跳过（换机器/浅克隆）。
/// </summary>
public sealed class VersionGuardTests {

    /// <summary>CRC32 的公开测试向量（zlib 自检用同一串）。</summary>
    [Fact]
    public void Crc32_matches_zlib_reference_vectors() {
        Assert.Equal(0xCBF43926u, VersionGuard.Crc32(Encoding.ASCII.GetBytes("123456789")));
        Assert.Equal(0xE8B7BE43u, VersionGuard.Crc32(Encoding.ASCII.GetBytes("a")));
        Assert.Equal(0x00000000u, VersionGuard.Crc32(ReadOnlySpan<byte>.Empty));
        // 单个 0 字节不等于 0：CRC32 有初值/取反，这里钉住"别把空输入和零字节混为一谈"
        Assert.Equal(0xD202EF8Du, VersionGuard.Crc32([0x00]));
    }

    /// <summary>长度与内容都要参与：喂进去的字节数不同就不能得出同一个值。</summary>
    [Fact]
    public void Crc32_is_sensitive_to_length_and_content() {
        var a = VersionGuard.Crc32([0x01, 0x02, 0x03]);
        var b = VersionGuard.Crc32([0x01, 0x02, 0x03, 0x00]);
        var c = VersionGuard.Crc32([0x01, 0x02, 0x04]);
        Assert.NotEqual(a, b);
        Assert.NotEqual(a, c);
        Assert.NotEqual(b, c);
    }

    /// <summary>正常头部：指纹长度就是 SizeOfHeaders（各版本可能不同，不能写死 0x400）。</summary>
    [Theory]
    [InlineData(0x200)]
    [InlineData(0x400)]
    [InlineData(0x600)]
    [InlineData(0x10000)]
    public void FingerprintLength_uses_size_of_headers(int sizeOfHeaders) {
        var header = BuildFakeHeader(sizeOfHeaders: sizeOfHeaders, length: 0x11000);
        Assert.Equal(sizeOfHeaders, VersionGuard.FingerprintLength(header));
    }

    /// <summary>
    /// 头部不可信时必须兜底（宁可指纹短一点，也不要算出一个和 update_rva.py 不一致的值）。
    /// 每种情形都是"真实世界里可能出现"的畸形：截断、e_lfanew 越界、签名错、SizeOfHeaders 离谱。
    /// </summary>
    [Fact]
    public void FingerprintLength_falls_back_on_malformed_headers() {
        var fallback = VersionGuard.FingerprintFallbackBytes;

        // ① 整个头部短于 DOS header 需要的最低长度
        Assert.Equal(fallback, VersionGuard.FingerprintLength(new byte[0x20]));

        // ② SizeOfHeaders 低于下限 / 高于上限
        Assert.Equal(fallback, VersionGuard.FingerprintLength(BuildFakeHeader(sizeOfHeaders: 0, length: 0x1000)));
        Assert.Equal(fallback, VersionGuard.FingerprintLength(BuildFakeHeader(sizeOfHeaders: 0x100, length: 0x1000)));
        Assert.Equal(fallback, VersionGuard.FingerprintLength(BuildFakeHeader(sizeOfHeaders: 0x20000, length: 0x30000)));

        // ③ e_lfanew 越界（0 / 很大）
        Assert.Equal(fallback, VersionGuard.FingerprintLength(BuildFakeHeader(sizeOfHeaders: 0x400, eLfanew: 0)));
        Assert.Equal(fallback, VersionGuard.FingerprintLength(BuildFakeHeader(sizeOfHeaders: 0x400, eLfanew: 0x2000)));

        // ④ PE 签名不对
        Assert.Equal(fallback, VersionGuard.FingerprintLength(
            BuildFakeHeader(sizeOfHeaders: 0x400, signature: 0x12345678u)));

        // ⑤ e_lfanew 声称的位置超出缓冲区
        Assert.Equal(fallback, VersionGuard.FingerprintLength(
            BuildFakeHeader(sizeOfHeaders: 0x400, eLfanew: 0xF00, length: 0x1000)));
    }

    /// <summary>
    /// `TryHashHeader` 是 DLL 与 update_rva 共用的"算指纹"入口：
    /// 成功时 CRC 只覆盖 `[0, SizeOfHeaders)`；**声明长度超过实有字节时必须返回 false**
    /// （宁可不算，也不能夹一段长度凑 CRC —— 那正是"假绿灯/永久误报"的来源）。
    /// </summary>
    [Fact]
    public void TryHashHeader_hashes_only_the_declared_header_and_refuses_oversized_claims() {
        // ① 正常：只算前 SizeOfHeaders 字节，后面的内容不影响结果
        var header = BuildFakeHeader(sizeOfHeaders: 0x200, length: 0x800);
        Assert.True(VersionGuard.TryHashHeader(header, out var crc, out var length));
        Assert.Equal(0x200, length);
        Assert.Equal(VersionGuard.Crc32(header.AsSpan(0, 0x200)), crc);

        var noisy = (byte[]) header.Clone();
        noisy[0x400] = 0xAA;                       // 改到 SizeOfHeaders 之外
        Assert.True(VersionGuard.TryHashHeader(noisy, out var crc2, out _));
        Assert.Equal(crc, crc2);                   // 结果不受影响

        // ② 声明 0x2000 > 实有 0x800 → 必须拒绝，且 cobble 不出值
        var oversized = BuildFakeHeader(sizeOfHeaders: 0x2000, length: 0x800);
        Assert.False(VersionGuard.TryHashHeader(oversized, out var badCrc, out var badLen));
        Assert.Equal(0u, badCrc);
        Assert.Equal(0, badLen);
    }

    /// <summary>登记 0 = 未登记（不是不匹配）：国际服当前就是 0，GMK_STRICT 不该拦它。</summary>
    [Fact]
    public void Compare_treats_zero_as_unregistered() {
        Assert.Equal(VersionGuard.State.Unregistered, VersionGuard.Compare(0x12345678u, 0));
        Assert.Equal(VersionGuard.State.Match, VersionGuard.Compare(0x12345678u, 0x12345678u));
        Assert.Equal(VersionGuard.State.Mismatch, VersionGuard.Compare(0x12345678u, 0x87654321u));
        // 实测值恰好是 0（读不到）但登记值非 0 —— 那是"不匹配"，不是"未登记"
        Assert.Equal(VersionGuard.State.Mismatch, VersionGuard.Compare(0, 0xC66689B9u));
    }

    /// <summary>日志文案：只有 Mismatch 该说"动手迁移"，其余两种不该吓人；口径后缀按需追加。</summary>
    [Fact]
    public void Describe_only_nags_on_mismatch() {
        var mismatch = VersionGuard.Describe(VersionGuard.State.Mismatch, 0x11111111u, 0xC66689B9u);
        Assert.Contains("不匹配", mismatch, StringComparison.Ordinal);
        Assert.Contains("0x11111111", mismatch, StringComparison.Ordinal);
        Assert.Contains("0xC66689B9", mismatch, StringComparison.Ordinal);
        Assert.Contains("update_rva", mismatch, StringComparison.Ordinal);
        Assert.DoesNotContain("口径", mismatch, StringComparison.Ordinal);   // length 缺省=0，不追后缀

        var unregistered = VersionGuard.Describe(VersionGuard.State.Unregistered, 0x11111111u, 0);
        Assert.Contains("未登记", unregistered, StringComparison.Ordinal);
        Assert.DoesNotContain("不匹配", unregistered, StringComparison.Ordinal);

        var match = VersionGuard.Describe(VersionGuard.State.Match, 0xC66689B9u, 0xC66689B9u);
        Assert.Contains("匹配", match, StringComparison.Ordinal);
        Assert.DoesNotContain("⚠", match, StringComparison.Ordinal);

        // 带口径：现场排"两边算法不一致"类问题时唯一的线索
        var withLength = VersionGuard.Describe(VersionGuard.State.Match, 0xC66689B9u, 0xC66689B9u, 0x400);
        Assert.Contains("口径", withLength, StringComparison.Ordinal);
        Assert.Contains("1024", withLength, StringComparison.Ordinal);
    }

    /// <summary>
    /// 与真实 7.1 国服客户端对拍：DLL 实际调用的 `TryHashHeader` 必须给出 `0xC66689B9`（长度 0x400）。
    /// 顺带留证两个"不能用的口径"：
    ///   · 文件前 64KB = `0xE597A764`（镜像里那段被 0 填充，算出来又是别的值）；
    ///   · 内存镜像头 1KB 也不可信 —— 2026-11-02 实跑得到 `0x9735915B`，因为保护壳改写了它，
    ///     所以 DLL 现在判定只读**磁盘文件**。
    /// 没有 rva_cache 时直接返回（不是失败）。
    /// </summary>
    [Fact]
    public void Cached_client_header_matches_registered_fingerprint() {
        var exe = FindCachedClient();
        if (exe == null) {
            return;     // 本机没有缓存的客户端：跳过（不是失败）
        }
        using var fs = File.OpenRead(exe);
        var probe = new byte[VersionGuard.FingerprintBytes];
        if (fs.ReadAtLeast(probe, probe.Length, throwOnEndOfStream: false) < probe.Length) {
            return;     // 文件不完整（下载中/被截断），不拿它当锚
        }
        // 走 DLL 真正用的那条路径
        Assert.True(VersionGuard.TryHashHeader(probe, out var crc, out var length));
        Assert.Equal(0x400, length);
        Assert.Equal(0xC66689B9u, crc);

        // 坑的留证：文件前 64KB 是另一个值，且**不能**当指纹用
        var sixtyFourK = VersionGuard.Crc32(probe);
        Assert.Equal(0xE597A764u, sixtyFourK);
        Assert.NotEqual(sixtyFourK, crc);
        // 实跑观察到、但**不可复现于文件**的内存镜像值（保护壳改写）——记在这里防止有人再拿它当基准
        Assert.NotEqual(0x9735915Bu, crc);
    }

    /// <summary>造一个结构合法的 PE32+ 头部（只填指纹判定需要的字段，其余留 0）。</summary>
    private static byte[] BuildFakeHeader(int sizeOfHeaders, int eLfanew = 0x80,
        uint signature = 0x00004550u, int length = 0x800) {
        var buffer = new byte[length];
        buffer[0] = (byte) 'M';
        buffer[1] = (byte) 'Z';
        WriteU32(buffer, 0x3C, (uint) eLfanew);
        var optional = eLfanew + 0x18;
        if (eLfanew >= 0x40 && optional + 0x40 <= length) {
            WriteU32(buffer, eLfanew, signature);
            WriteU32(buffer, optional + 0x3C, (uint) sizeOfHeaders);
        }
        return buffer;
    }

    private static void WriteU32(byte[] buffer, int offset, uint value) {
        if (offset < 0 || offset + 4 > buffer.Length) {
            return;
        }
        buffer[offset] = (byte) value;
        buffer[offset + 1] = (byte) (value >> 8);
        buffer[offset + 2] = (byte) (value >> 16);
        buffer[offset + 3] = (byte) (value >> 24);
    }

    /// <summary>从测试程序集目录往上找仓库根（同时有 `inject` 与 `tools` 的那层），再找缓存 exe。</summary>
    private static string? FindCachedClient() {
        try {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            for (var depth = 0; depth < 8 && dir != null; depth++, dir = dir.Parent) {
                if (!Directory.Exists(Path.Combine(dir.FullName, "inject"))) {
                    continue;
                }
                var cached = Path.Combine(dir.FullName, "rva_cache", "YuanShen.exe");
                if (File.Exists(cached)) {
                    return cached;
                }
            }
        } catch (IOException) {
            // 目录遍历本身出问题就当作"没有缓存"—— 测试不该因为环境问题红
        } catch (UnauthorizedAccessException) {
            // 同上
        }
        return null;
    }
}
