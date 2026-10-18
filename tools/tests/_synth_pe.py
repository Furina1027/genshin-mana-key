#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合成 PE 构造器（只给 tools/tests/ 用，不参与正式工具链）。

为什么需要它：仓库里没有任何真实 exe，`pe_utils.rva_to_off` 的越界行为、
「虚拟尾部没有文件字节就不许映射」这条硬性判据都必须有可执行的证据，
所以这里手写一个最小但**结构合法**的 PE32+（pefile 能正常解析）。

段规格：``dict(name='.text', va=0x1000, data=b'...', vsize=None, chars=0x60000020)``
"""
from __future__ import annotations

import struct

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020

SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

CHARS_CODE = SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
CHARS_DATA = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE
CHARS_RODATA = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ

OPTIONAL_HEADER_SIZE = 112 + 16 * 8     # PE32+ 固定部分 + 16 个数据目录


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError('alignment 必须为正')
    return (value + alignment - 1) // alignment * alignment


def build_pe(sections, *, image_base: int = 0x140000000, file_align: int = 0x200,
             sect_align: int = 0x1000, entry_rva: int = 0,
             data_directories: dict | None = None) -> bytes:
    """按规格拼一个最小 PE32+ 文件（返回完整字节）。

    sections 里每个元素：
      name  段名（<= 8 字符）
      va    虚拟地址（RVA）
      data  原始数据
      vsize 可选，Misc_VirtualSize（默认 == len(data)；显式给大于 raw 的值可以
            构造出「只有内存里有、文件里没有字节」的虚拟尾部，这正是要测的越界场景）
      chars 段特征位
      data_directories 可选，{目录索引: (RVA, 字节大小)}；例如 {3: (0x2000, 24)} 指定
            异常目录指向的函数边界表。不传则 16 个目录全 0（旧行为）。
    """
    if not sections:
        raise ValueError('至少要一个段')

    header_size = 0x40 + 4 + 20 + OPTIONAL_HEADER_SIZE
    header_size = _align(header_size + 40 * len(sections), file_align)

    raw_ptr = header_size
    raw_info = []
    for spec in sections:
        data = bytes(spec.get('data', b''))
        raw_size = _align(len(data), file_align) if data else 0
        raw_info.append((raw_ptr, raw_size, data))
        raw_ptr += raw_size
    total_size = raw_ptr

    size_of_code = sum(rsz for (spec, (_, rsz, _)) in zip(sections, raw_info)
                       if spec.get('chars', CHARS_DATA) & SCN_CNT_CODE)
    size_of_init = sum(rsz for (spec, (_, rsz, _)) in zip(sections, raw_info)
                       if not spec.get('chars', CHARS_DATA) & SCN_CNT_CODE)
    end_of_image = 0
    for spec, (_, rsz, data) in zip(sections, raw_info):
        vsize = spec.get('vsize')
        if vsize is None:
            vsize = len(data)
        end_of_image = max(end_of_image, int(spec['va']) + max(int(vsize), rsz))
    size_of_image = _align(end_of_image, sect_align)

    out = bytearray(total_size)
    # ---- DOS header ----
    out[0:2] = b'MZ'
    struct.pack_into('<I', out, 0x3C, 0x40)
    # ---- NT headers ----
    off = 0x40
    out[off:off + 4] = b'PE\x00\x00'
    off += 4
    struct.pack_into('<HHIIIHH', out, off,
                     IMAGE_FILE_MACHINE_AMD64, len(sections), 0, 0, 0,
                     OPTIONAL_HEADER_SIZE,
                     IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE)
    off += 20
    # ---- Optional header (PE32+) ----
    fields = [
        ('<H', 0x20B),                      # Magic
        ('<B', 14), ('<B', 0),              # linker version
        ('<I', size_of_code), ('<I', size_of_init), ('<I', 0),
        ('<I', entry_rva),                  # AddressOfEntryPoint
        ('<I', 0x1000),                     # BaseOfCode
        ('<Q', image_base),
        ('<I', sect_align), ('<I', file_align),
        ('<H', 6), ('<H', 0),               # OS version
        ('<H', 0), ('<H', 0),               # image version
        ('<H', 6), ('<H', 0),               # subsystem version
        ('<I', 0),                          # Win32VersionValue
        ('<I', size_of_image),
        ('<I', header_size),                # SizeOfHeaders
        ('<I', 0),                          # CheckSum
        ('<H', 3),                          # Subsystem = console
        ('<H', 0),                          # DllCharacteristics
        ('<Q', 0x100000), ('<Q', 0x1000),   # stack
        ('<Q', 0x100000), ('<Q', 0x1000),   # heap
        ('<I', 0),                          # LoaderFlags
        ('<I', 16),                         # NumberOfRvaAndSizes
    ]
    for fmt, value in fields:
        out[off:off + struct.calcsize(fmt)] = struct.pack(fmt, value)
        off += struct.calcsize(fmt)
    if off != 0x40 + 4 + 20 + 112:
        raise AssertionError(f'optional header 长度异常: {off:#x}')
    off += 16 * 8                            # 数据目录（默认全 0，随后按需覆盖）
    for idx, (dd_rva, dd_size) in (data_directories or {}).items():
        if not 0 <= int(idx) < 16:
            raise ValueError(f'数据目录索引越界: {idx}')
        struct.pack_into('<II', out, off - 16 * 8 + int(idx) * 8, int(dd_rva), int(dd_size))
    assert off == 0x40 + 4 + 20 + OPTIONAL_HEADER_SIZE

    # ---- Section headers ----
    for spec, (ptr, rsz, data) in zip(sections, raw_info):
        name = spec['name'].encode('ascii')
        if len(name) > 8:
            raise ValueError(f'段名过长: {spec["name"]}')
        vsize = spec.get('vsize')
        if vsize is None:
            vsize = len(data)
        struct.pack_into('<8sIIIIIIHHI', out, off,
                         name.ljust(8, b'\x00'), int(vsize), int(spec['va']),
                         rsz, ptr, 0, 0, 0, 0,
                         int(spec.get('chars', CHARS_DATA)))
        off += 40
        if data:
            out[ptr:ptr + len(data)] = data
    return bytes(out)


def write_pe(path, sections, **kwargs) -> str:
    blob = build_pe(sections, **kwargs)
    with open(path, 'wb') as fh:
        fh.write(blob)
    return str(path)
