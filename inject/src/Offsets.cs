namespace GenshinSniffer;

/// <summary>
/// 魔法数字集中地（A6）。
///
/// 为什么集中：这些偏移原来散落在各个钩子/诊断函数里，游戏一更新就没人说得清
/// 哪一项还成立、哪一项是历史遗留。集中之后每一项都标注来源与"过期了怎么办"。
///
/// 两条纪律：
///   1. 能用 PE 节表派生的（模块大小）一律不写死 —— 见 FallbackModuleSize 的注释；
///   2. 只有上游遗留的全局偏移才留常量。
///
/// v20 起诊断钩子全部删除，exe 侧的 DECKEY/DecCallback 全局与 CRI DLL 内部结构偏移
/// （DecoderKeyGlobal / CriCipherSingleton 等）一并移除 —— 它们只服务于逆向调查，
/// 且都需要每个版本手工维护。历史值见 git（v19 及之前）。
/// </summary>
internal static class Offsets {

    // ==================== exe 兜底范围（仅当 PE 节表不可用时使用）====================

    /// <summary>
    /// 兜底的 exe 映像大小上限（原来是硬编码的"模块范围"）。
    /// 实测 7.1 国服 YuanShen.exe 的 SizeOfImage = 0x1B0AD000（离线读节表），比这个经验值更大；
    /// 所以它只在 PE 解析失败时使用，且使用时会在日志里说明。
    /// </summary>
    public const uint FallbackModuleSize = 0x1A880000;

    // ==================== il2cpp 元数据结构字段偏移 ====================
    // Il2CppString 的布局，跨版本相对稳定（7.0↔7.1 未变）。

    /// <summary>Il2CppString：+0x10 长度（字符数），+0x14 起 UTF-16 数据。</summary>
    public const int StringLengthOffset = 0x10;
    public const int StringCharsOffset = 0x14;

    /// <summary>
    /// Il2CppArray（byte[]）：+0x18 元素个数，+0x20 起数据。
    /// 依据：<c>Player.SetVideoAesKeyAudioDecryptionKey</c> 里就是
    /// <c>cmp dword ptr [aesArray+0x18], 0x10</c> 校验 16 字节，再把 <c>array+0x20</c> 传给原生层。
    /// </summary>
    public const int ArrayLengthOffset = 0x18;
    public const int ArrayDataOffset = 0x20;

    // ==================== CriwareMediaPlayer（MoleMole）密钥结构 ====================
    // 7.1 与 7.2 **同布局**（两版 MediaPlayerSetup 的拷贝模式逐字节一致）：
    //   [this+0x88] = config[0x00] 16B   → videoRuntimePath（get_videoRuntimePath 直接返回它）
    //   [this+0x98] = config[0x10] 16B
    //   [this+0xa8] = config[0x20] 16B
    //   [this+0xb8] = config[0x30] 16B   → mode(int) + key64(ulong)
    //   [this+0xc8] = config[0x40] 16B   → aes byte[] + hasAudio
    //   [this+0xd8] = config[0x50] 8B
    // 语义（反汇编 GAKIOOPLFAA / AABGGCLCMKA 得到）：
    //   mode==0：+0xC0 = 旧体系 videoKey（finalKey），audioKey = 同一值
    //   mode==1：+0xC8 = AES byte[16]，+0xC0 = audioKey
    //   +0xD0 为 bool：是否带 audio key
    // 这些偏移是版本相关的；升级后先用 MediaPlayerSetup 的拷贝模式重新核对。

    public const int MediaPlayerPathOffset = 0x88;
    public const int MediaPlayerModeOffset = 0xB8;
    public const int MediaPlayerKey64Offset = 0xC0;
    public const int MediaPlayerAesArrayOffset = 0xC8;
    public const int MediaPlayerHasAudioOffset = 0xD0;

    /// <summary>从 +0x88 起需要读到的字节数（覆盖到 +0xD0 那个 bool）。</summary>
    public const int MediaPlayerStructSize = 0x50;

    // ==================== 诊断输出上限（与管道协议无关，只是可读性）====================

    /// <summary>十六进制分块 dump：每行最多 240 字节数据（480 个十六进制字符 + 前缀 ≤ 512）。</summary>
    public const int MaxHexDumpBytesPerLine = 240;

    // ==================== 捕获配额（不是协议）====================

    /// <summary>BCryptGenerateSymmetricKey 的密钥长度上限（AES-256 也就 32，留 64 足够）。</summary>
    public const int MaxSecretBytes = 64;

    /// <summary>
    /// 同一个「文件名 + 密钥」重复上报次数上限（用于确认稳定），之后只留计数（A3）。
    ///
    /// 注意口径是"文件 + 密钥"而不是"密钥"：CRI 的 cipher 单例会跨视频复用同一把钥匙
    /// （实测确认有的视频密钥确实相同），只按密钥内容去重会把第二个同钥视频整段压掉。
    /// </summary>
    public const int MaxKeyRepeatReports = 3;

    /// <summary>同一个 BCENC 内容指纹重复上报次数上限（A3）。</summary>
    public const int MaxFingerprintRepeatReports = 3;

    /// <summary>BCENC 唯一记录数上限（原来错写成"总条数 200"，A3）。</summary>
    public const int MaxEncUniqueRecords = 512;

    /// <summary>
    /// PE 解析失败时才用的 CRI 模块大小上限（LocateAddress 判定回调归属用）。
    /// 实测 7.1 的 cri_ware_unity.dll SizeOfImage = 0x551000（离线读节表得到），上游遗留值是 0x400000
    /// —— 偏小会把 CRI 里的高地址误判成"非本模块"，所以这里取略大的 0x600000。
    /// 正常路径永远走 PeImage.SizeOfImage（A4/A6）。仅 GMK_FS=1 的侦察路径使用。
    /// </summary>
    public const uint CriModuleFallbackSize = 0x600000;
}
