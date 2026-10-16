namespace GenshinSniffer;

/// <summary>
/// 魔法数字集中地（A6）。
///
/// 为什么集中：这些偏移原来散落在各个钩子/诊断函数里，游戏一更新就没人说得清
/// 哪一项还成立、哪一项是历史遗留。集中之后每一项都标注来源与"过期了怎么办"。
///
/// 两条纪律：
///   1. 能用 PE 节表派生的（模块大小、il2cpp 段范围）一律不写死 —— 见本文件里 Fallback* 的注释；
///   2. 只有 CRI DLL 内部结构（随 cri_ware_unity.dll 版本变化）和上游遗留的全局偏移才留常量。
///
/// ★ 注意：本文件里 exe 侧的全局偏移都只对国服 7.1 实测成立。
///   国际服没有实测数据，绝不照搬（见 README 的 RVA 表：只给了 5 个核心钩子）。
/// </summary>
internal static class Offsets {

    // ==================== exe（il2cpp 段）内的全局变量 ====================

    /// <summary>
    /// DECKEY：解密器派生 key 的全局槽。国服 7.1 实测（7.0↔7.1 指纹迁移，运行时命中）。
    /// 过期症状：ReportDecoderKey 打出 0 或明显不像 key 的值。
    /// </summary>
    public const uint DecoderKeyGlobal = 0x5785430;

    /// <summary>
    /// 解密回调结构体全局：+0x8 = 原生回调（v12 由内存 dump 反推）。
    /// 该结构只有国服 7.1 的实测依据，国际服未知。
    /// </summary>
    public const uint DecCallbackGlobal = 0x588D600;

    /// <summary>常量/调试区，仅用于人工核对（v2 起观测到的都是死数据，保留待复核）。</summary>
    public const uint ConstProbe5784500 = 0x5784500;

    // ==================== cri_ware_unity.dll 内部 ====================
    // ★ 全部随 cri_ware_unity.dll 版本变化，升级该 DLL 后必须重新用 Ghidra 定位。

    /// <summary>CriCipher 全局单例 context 指针（对应报错 "Only one decrypter is creatable"）。</summary>
    public const uint CriCipherSingleton = 0x26A7B0;

    /// <summary>.data 兜底扫描区间（找不到单例时跟随区间内所有可读指针）。</summary>
    public const uint CriDataScanStart = 0x26A000;
    public const uint CriDataScanEnd = 0x26B000;

    /// <summary>CriCipher_Create 把 16 字节 AES key 写进 context 的这个偏移。</summary>
    public const int CriCipherKeyOffset = 0x20;

    /// <summary>dump 单例 context 的字节数（含 +0x20 的 key）。</summary>
    public const int CriCipherCtxSize = 0x48;

    /// <summary>兜底扫描时每个候选指针 dump 的字节数。</summary>
    public const int CriDataDumpSize = 0x48;

    /// <summary>
    /// PE 解析失败时才用的 CRI 模块大小上限。
    /// 实测 7.1 的 cri_ware_unity.dll SizeOfImage = 0x551000（离线读节表得到），上游遗留值是 0x400000
    /// —— 偏小会把 CRI 里的高地址误判成"非本模块"，所以这里取略大的 0x600000。
    /// 正常路径永远走 PeImage.SizeOfImage（A4/A6）。
    /// </summary>
    public const uint CriModuleFallbackSize = 0x600000;

    // ==================== exe 兜底范围（仅当 PE 节表不可用时使用）====================
    // 这些数字是上游 YaeAchievement/旧版留下的"经验值"，正确来源应该是 PE 的 SizeOfImage
    // 与 il2cpp 节范围 —— 所以它们只在 TryCreate 失败时兜底，并且使用时会打日志。

    /// <summary>
    /// 兜底的 exe 映像大小上限（原来是硬编码的"模块范围"）。
    /// 实测 7.1 国服 YuanShen.exe 的 SizeOfImage = 0x1B0AD000（离线读节表），比这个经验值更大；
    /// 所以它只在 PE 解析失败时使用，且使用时会在日志里说明。
    /// </summary>
    public const uint FallbackModuleSize = 0x1A880000;

    /// <summary>
    /// 历史遗留的"模块范围"上限（旧版 LocateAddress 用它判断地址是否属于 exe）。
    /// 现已由 PeImage.SizeOfImage 派生（A4/A6），此值只作为对照保留，不再参与判断。
    /// </summary>
    public const uint FallbackModuleRange = 0x20000000;

    /// <summary>
    /// 兜底的 il2cpp 代码段范围（判定 klass.methods 里的方法指针是否可信）。
    /// 实测 7.1 国服 il2cpp 节 = 0x06C05000..0x19E5ABC6，落在这个兜底区间内（兜底是超集，安全）。
    /// </summary>
    public const uint FallbackIl2CppStart = 0x6000000;
    public const uint FallbackIl2CppEnd = 0x1E000000;

    /// <summary>il2cpp 代码所在节名（原神把 IL2CPP 代码编在 exe 里，没有 GameAssembly.dll）。</summary>
    public const string Il2CppSectionName = "il2cpp";

    // ==================== il2cpp 元数据结构字段偏移 ====================
    // 这些是 Il2CppClass / Il2CppString / Il2CppArray 的布局，跨版本相对稳定（7.0↔7.1 未变）。

    /// <summary>klass 结构可信读取长度（也是 KLASSDUMP 的长度上限，原为一行 3072 字符）。</summary>
    public const int KlassMaxOffset = 0x600;

    /// <summary>扫 klass.methods 的字段范围（0x40 起，因为前几个槽是 vtable/接口等）。</summary>
    public const int KlassMethodsScanStart = 0x40;
    public const int KlassMethodsScanEnd = 0x5F0;

    /// <summary>Il2CppString：+0x10 长度（字符数），+0x14 起 UTF-16 数据。</summary>
    public const int StringLengthOffset = 0x10;
    public const int StringCharsOffset = 0x14;

    /// <summary>Il2CppArray：+0x18 元素个数，+0x20 起元素数据。</summary>
    public const int ArrayLengthOffset = 0x18;
    public const int ArrayDataOffset = 0x20;

    /// <summary>对象字段扫描的最大偏移（默认值；密钥字段都在对象前 0x400 字节内）。</summary>
    public const int ObjectMaxScanOffset = 0x400;

    // ==================== 诊断输出上限（与管道协议无关，只是可读性）====================

    /// <summary>单行上限 512 字符：原来一行 3072/1800 字符会被启动器的行缓冲截断（A11）。</summary>
    public const int MaxDiagLineChars = 512;

    /// <summary>十六进制分块 dump：每行最多 240 字节数据（480 个十六进制字符 + 前缀 ≤ 512）。</summary>
    public const int MaxHexDumpBytesPerLine = 240;

    /// <summary>方法列表分块：每行最多 448 个字符（加上 "TAGM0 " 前缀仍 ≤ 512）。</summary>
    public const int MaxMethodCharsPerLine = 448;

    // ==================== 捕获配额（不是协议）====================

    /// <summary>BCryptGenerateSymmetricKey 的密钥长度上限（AES-256 也就 32，留 64 足够）。</summary>
    public const int MaxSecretBytes = 64;

    /// <summary>同一把密钥重复上报次数上限（用于确认稳定），之后只留计数（A3）。</summary>
    public const int MaxKeyRepeatReports = 3;

    /// <summary>同一个 BCENC 内容指纹重复上报次数上限（A3）。</summary>
    public const int MaxFingerprintRepeatReports = 3;

    /// <summary>BCENC 唯一记录数上限（原来错写成"总条数 200"，A3）。</summary>
    public const int MaxEncUniqueRecords = 512;
}
