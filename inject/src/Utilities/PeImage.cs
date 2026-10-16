namespace GenshinSniffer.Utilities;

/// <summary>
/// 只读的 PE 映像视图：从模块基址解析 DOS 头 / NT 头 / 节表，用来回答"这个 RVA 到底能不能碰"。
///
/// 为什么必须要有它（A4）：RVA 是相对模块基址的偏移，游戏一更新就整体位移。
/// 旧实现只靠"首字节像不像函数序言"来决定要不要挂钩，而且**先解引用、后判断**——
/// RVA 一旦过期，那就是对野地址的一次读取，直接访问违例，游戏进程当场消失。
/// 正确顺序只能是：节表确认落在可执行节 → 确认可读 → 最后才做序言校验。
///
/// 本文件唯一的硬规矩：任何解引用之前都要过 Native.IsReadable。
/// 元数据都来自游戏自己的 exe（不可信输入），所以字段值也要做合理性检查，不能直接拿去做地址运算。
/// </summary>
internal sealed unsafe class PeImage {

    /// <summary>IMAGE_SECTION_HEADER 里我们真正会用到的字段子集。</summary>
    internal readonly struct Section {
        public readonly string Name;
        public readonly uint VirtualAddress;
        public readonly uint VirtualSize;
        public readonly uint SizeOfRawData;
        public readonly uint Characteristics;

        public Section(string name, uint virtualAddress, uint virtualSize, uint sizeOfRawData, uint characteristics) {
            Name = name;
            VirtualAddress = virtualAddress;
            VirtualSize = virtualSize;
            SizeOfRawData = sizeOfRawData;
            Characteristics = characteristics;
        }

        /// <summary>IMAGE_SCN_MEM_EXECUTE</summary>
        public bool IsExecutable => (Characteristics & 0x20000000) != 0;

        /// <summary>
        /// 节在内存里的跨度。正常 PE 用 VirtualSize（.data 常大于 raw size）；
        /// VirtualSize 为 0 的畸形节才退回 SizeOfRawData。
        /// </summary>
        public uint MappedSize => VirtualSize != 0 ? VirtualSize : SizeOfRawData;
    }

    private const ushort DosMagic = 0x5A4D;          // 'MZ'
    private const uint NtSignature = 0x00004550;     // 'PE\0\0'
    private const ushort OptionalMagicPe32Plus = 0x20B;
    private const ushort OptionalMagicPe32 = 0x10B;
    private const int SectionHeaderSize = 40;
    private const int MaxSectionCount = 96;

    private readonly nint _module;
    private readonly Section[] _sections;

    /// <summary>IMAGE_OPTIONAL_HEADER.SizeOfImage —— 模块在内存里的完整跨度。</summary>
    public uint SizeOfImage { get; }

    private PeImage(nint module, uint sizeOfImage, Section[] sections) {
        _module = module;
        SizeOfImage = sizeOfImage;
        _sections = sections;
    }

    /// <summary>解析模块头与节表；任何一步读不到（或根本不是 PE）都返回 false，绝不猜测。</summary>
    public static bool TryCreate(nint module, out PeImage? image) {
        image = null;
        if (module == 0 || !Native.IsReadable(module, 0x40)) {
            return false;
        }
        if (*(ushort*) module != DosMagic) {
            return false;
        }
        var eLfanew = *(int*) (module + 0x3C);
        if (eLfanew <= 0 || eLfanew > 0x1000) {
            return false;   // 合理范围之外的 e_lfanew 一定是脏数据
        }
        var nt = module + eLfanew;
        // 签名 + COFF 头(0x14) + 可选头(PE32+ 恒为 0xF0) —— 先确认整段可读再逐个字段读
        if (!Native.IsReadable(nt, 0x18 + 0xF0)) {
            return false;
        }
        if (*(uint*) nt != NtSignature) {
            return false;
        }
        var sectionCount = *(ushort*) (nt + 0x06);
        var optionalHeaderSize = *(ushort*) (nt + 0x14);
        if (sectionCount is 0 or > MaxSectionCount || optionalHeaderSize < 0x70) {
            return false;
        }
        var optional = nt + 0x18;
        var magic = *(ushort*) optional;
        if (magic is not (OptionalMagicPe32Plus or OptionalMagicPe32)) {
            return false;
        }
        var sizeOfImage = *(uint*) (optional + 0x38);
        if (sizeOfImage == 0) {
            return false;
        }
        var table = optional + optionalHeaderSize;
        if (!Native.IsReadable(table, sectionCount * SectionHeaderSize)) {
            return false;
        }
        var sections = new Section[sectionCount];
        for (var i = 0; i < sectionCount; i++) {
            var s = table + i * SectionHeaderSize;
            sections[i] = new Section(
                ReadSectionName(s),
                *(uint*) (s + 0x0C),   // VirtualAddress
                *(uint*) (s + 0x08),   // Misc.VirtualSize
                *(uint*) (s + 0x10),   // SizeOfRawData
                *(uint*) (s + 0x24));  // Characteristics
        }
        image = new PeImage(module, sizeOfImage, sections);
        return true;
    }

    private static string ReadSectionName(nint header) {
        Span<byte> name = stackalloc byte[8];
        for (var i = 0; i < 8; i++) {
            name[i] = *(byte*) (header + i);
        }
        var len = 0;
        while (len < 8 && name[len] != 0) {
            len++;
        }
        return System.Text.Encoding.ASCII.GetString(name[..len]);
    }

    /// <summary>按名查节（例如 "il2cpp"）；节名区分大小写。</summary>
    public bool TryGetSection(string name, out Section section) {
        foreach (var s in _sections) {
            if (s.Name == name) {
                section = s;
                return true;
            }
        }
        section = default;
        return false;
    }

    /// <summary>该 RVA 落在哪个节；落在节表之外返回 false（= 这个地址不该碰）。</summary>
    public bool TryGetSectionByRva(uint rva, out Section section) {
        foreach (var s in _sections) {
            var start = s.VirtualAddress;
            var end = start + s.MappedSize;
            if (end < start) {
                continue;   // 溢出回绕 → 畸形节，直接不信
            }
            if (rva >= start && rva < end) {
                section = s;
                return true;
            }
        }
        section = default;
        return false;
    }

    /// <summary>RVA → 虚拟地址，仅当它确实落在某个节内。</summary>
    public bool TryRvaToVa(uint rva, out nint va) {
        va = 0;
        if (!TryGetSectionByRva(rva, out _)) {
            return false;
        }
        va = _module + (int) rva;
        return true;
    }

    /// <summary>RVA 是否落在可执行节内 —— 挂钩前的第一道门（A4 的核心）。</summary>
    public bool IsExecutableRva(uint rva) => TryGetSectionByRva(rva, out var s) && s.IsExecutable;

    /// <summary>地址是否落在本模块的映像范围内（SizeOfImage 由 PE 派生，不再写死"模块大小"）。</summary>
    public bool Contains(nint addr) => addr >= _module && addr < _module + (nint) SizeOfImage;

    /// <summary>节的内存跨度（由节表派生，用来替代写死的 il2cpp 段范围）。</summary>
    public bool TryGetSectionRange(string name, out nint low, out nint high) {
        low = 0;
        high = 0;
        if (!TryGetSection(name, out var s)) {
            return false;
        }
        var size = s.MappedSize;
        if (size == 0) {
            return false;
        }
        low = _module + (int) s.VirtualAddress;
        high = low + (int) size;
        return high > low;
    }
}
