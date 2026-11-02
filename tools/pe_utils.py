#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pe_utils.py — tools/ 下所有 PE 相关脚本共用的「只读一次 + 可靠地址映射」实现。

为什么需要这个模块
------------------
这些脚本原先各自复制了一份 PE 加载与 RVA→文件偏移映射，副本之间语义还不一致：

  · 有的把段**虚拟大小**与**文件大小**的较大值当成段范围 —— 这会把「只在内存里存在、
    文件里没有对应字节」的尾部也算成合法映射，读出来是全 0 的假数据而不报错；
  · 有的把**文件偏移**当成 RVA 传进映射函数，算出来的「RVA」其实是文件偏移；
  · 有的先 ``open().read()`` 再 ``pefile.PE(path)``，把几百 MB 的 exe 读两遍。

本模块统一成三条互不混淆的语义：

  · :meth:`PEFile.rva_to_off` —— RVA → 文件偏移。要求
    ``rva - VirtualAddress + size <= SizeOfRawData``（**不把虚拟大小与文件大小混用**），
    越界抛 :class:`RvaError`。因为「文件里真有这段字节」才是可以反汇编/读字符串的前提。
  · :meth:`PEFile.off_to_rva` —— 文件偏移 → RVA，判据是原始范围
    ``PointerToRawData .. +SizeOfRawData``（文件偏移天然属于文件）。
  · :meth:`PEFile.section_of_rva` —— 地址归属查询，判据是虚拟范围
    ``VirtualAddress .. +VirtualSize``（``VirtualSize`` 为 0 的少见段退回
    ``SizeOfRawData``，这只是补零，不是把两者取大）。

另外提供 ``parse_int`` / ``hexfmt`` / ``emit_json`` 等 CLI 小工具，供各脚本统一输出。
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

import pefile

__all__ = [
    'PEFormatError', 'RvaError', 'NumpyMissing', 'Section', 'PEFile', 'load_pe',
    'image_base', 'parse_int', 'hexfmt', 'emit_json', 'json_aware_main',
]

# 段特征位
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_CNT_CODE = 0x00000020

# 找不到 il2cpp 段时给出的提示（原神把 IL2CPP 代码放在 exe 的 il2cpp 段里）
IL2CPP_SECTION = 'il2cpp'


class PEFormatError(RuntimeError):
    """PE 结构层面的错误（不是 PE、缺段、头损坏等）。"""


class RvaError(ValueError):
    """RVA 无法可靠映射到文件偏移（越界，或落在文件里没有字节的虚拟尾部）。"""


class NumpyMissing(RuntimeError):
    """可选依赖 numpy 缺失（只影响 find_direct_calls，不影响 RVA 迁移链路）。"""


@dataclass(frozen=True)
class Section:
    """一个 PE 段的只读视图。"""

    name: str
    index: int
    virtual_address: int
    virtual_size: int          # Misc_VirtualSize（内存中的大小）
    raw_size: int              # SizeOfRawData（文件里的大小）
    raw_ptr: int               # PointerToRawData
    characteristics: int

    # —— 范围 ——
    @property
    def virtual_end(self) -> int:
        size = self.virtual_size if self.virtual_size else self.raw_size
        return self.virtual_address + size

    @property
    def raw_end(self) -> int:
        return self.raw_ptr + self.raw_size

    # —— 属性 ——
    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_READ)

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_CNT_CODE)

    # —— 归属 ——
    def contains_rva(self, rva: int) -> bool:
        """虚拟范围归属（回答「这个地址在哪个段」）。"""
        return self.virtual_address <= rva < self.virtual_end

    def contains_off(self, off: int) -> bool:
        """文件范围归属。"""
        return self.raw_ptr <= off < self.raw_end

    def file_backed(self, rva: int, size: int = 1) -> bool:
        """该 RVA 起始的 size 字节是否真的存在于文件的这个段里。"""
        delta = rva - self.virtual_address
        return 0 <= delta and delta + size <= self.raw_size

    def __str__(self) -> str:  # pragma: no cover - 仅用于打印
        return (f'{self.name} RVA 0x{self.virtual_address:08X} '
                f'VSize 0x{self.virtual_size:08X} Raw 0x{self.raw_size:08X} '
                f'@0x{self.raw_ptr:X}')


class PEFile:
    """一次性读入的 PE 文件。

    用法::

        pe = load_pe(r'...\\YuanShen.exe')
        off = pe.rva_to_off(0x70538C0)          # 越界会抛 RvaError
        data = pe.read_rva(0x70538C0, 16)
        sec = pe.section_of_rva(0x70538C0)      # 越界会抛 RvaError
    """

    def __init__(self, path: str):
        self.path = os.fspath(path)
        # ★ 只读一次：这些 exe 有几百 MB，不能再 pefile.PE(path) 读第二遍
        with open(self.path, 'rb') as fh:
            self.data = fh.read()
        try:
            self.pe = pefile.PE(data=self.data, fast_load=True)
        except pefile.PEFormatError as exc:
            raise PEFormatError(f'{self.path}: 不是有效的 PE 文件（{exc}）') from exc
        except Exception as exc:  # pefile 偶尔抛别的异常类型
            raise PEFormatError(f'{self.path}: 解析 PE 失败（{exc}）') from exc

        self.image_base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.sections: list[Section] = []
        for i, s in enumerate(self.pe.sections):
            name = s.Name.rstrip(b'\x00').decode('latin1', 'replace')
            self.sections.append(Section(
                name=name,
                index=i,
                virtual_address=int(s.VirtualAddress),
                virtual_size=int(s.Misc_VirtualSize),
                raw_size=int(s.SizeOfRawData),
                raw_ptr=int(s.PointerToRawData),
                characteristics=int(s.Characteristics),
            ))
        self._by_name: dict[str, Section] = {}
        for sec in self.sections:
            self._by_name.setdefault(sec.name, sec)

    # ------------------------------------------------------------------ 基本信息
    def __repr__(self) -> str:  # pragma: no cover
        return f'<PEFile {self.path!r} base=0x{self.image_base:X} sections={len(self.sections)}>'

    @property
    def section_names(self) -> list[str]:
        return [s.name for s in self.sections]

    def size(self) -> int:
        return len(self.data)

    def describe(self) -> str:
        lines = [f'{self.path}  ({len(self.data):,} B)  ImageBase=0x{self.image_base:X}']
        for sec in self.sections:
            lines.append(f'   {sec.name:10} VA 0x{sec.virtual_address:08X}  '
                         f'VSize 0x{sec.virtual_size:08X}  Raw 0x{sec.raw_size:08X} '
                         f'@0x{sec.raw_ptr:X}')
        return '\n'.join(lines)

    # ------------------------------------------------------------------ 按名找节
    def find_section(self, name: str) -> Optional[Section]:
        return self._by_name.get(name)

    def section_by_name(self, name: str, *, required: bool = True) -> Optional[Section]:
        """按名取节；找不到时 required=True 抛 PEFormatError（**显式报错，不返回 None**）。"""
        sec = self._by_name.get(name)
        if sec is None and required:
            raise PEFormatError(
                f'{self.path}: 找不到段 {name!r}；现有段: {", ".join(self.section_names) or "(无)"}')
        return sec

    def il2cpp(self, *, required: bool = True) -> Optional[Section]:
        return self.section_by_name(IL2CPP_SECTION, required=required)

    # ------------------------------------------------------------------ RVA → 文件偏移
    def section_of_rva(self, rva: int, *, required: bool = True) -> Optional[Section]:
        """按**虚拟范围**找 RVA 所属的段。"""
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec
        if required:
            raise RvaError(self._rva_hint(rva, '不属于任何段'))
        return None

    def section_of_off(self, off: int, *, required: bool = True) -> Optional[Section]:
        """按**原始范围**找文件偏移所属的段。"""
        for sec in self.sections:
            if sec.contains_off(off):
                return sec
        if required:
            raise RvaError(f'文件偏移 0x{off:X} 不属于任何段（文件大小 0x{len(self.data):X}）')
        return None

    def rva_to_off(self, rva: int, size: int = 1) -> int:
        """RVA → 文件偏移。

        硬性判据：段虚拟范围内，且 ``rva - VirtualAddress + size <= SizeOfRawData``。
        越界（含「只在内存里、文件里没有字节」的虚拟尾部）抛 :class:`RvaError`。
        """
        if size < 1:
            raise ValueError(f'size 必须 >= 1，收到 {size}')
        sec = self.section_of_rva(rva)  # 越界在这里抛
        delta = rva - sec.virtual_address
        if delta + size > sec.raw_size:
            raise RvaError(
                f'RVA 0x{rva:X}（段 {sec.name}）越出文件支撑范围：'
                f'段内偏移 0x{delta:X} + {size} B > SizeOfRawData 0x{sec.raw_size:X}'
                f'（该地址只存在于内存，文件里没有对应字节）')
        return sec.raw_ptr + delta

    def off_to_rva(self, off: int, size: int = 1) -> int:
        """文件偏移 → RVA（判据是原始范围）。"""
        if size < 1:
            raise ValueError(f'size 必须 >= 1，收到 {size}')
        if off < 0 or off + size > len(self.data):
            raise RvaError(f'文件偏移 0x{off:X}+{size}B 越出文件大小 0x{len(self.data):X}')
        sec = self.section_of_off(off)  # 不属于任何段在这里抛
        delta = off - sec.raw_ptr
        if delta + size > sec.raw_size:
            raise RvaError(f'文件偏移 0x{off:X}+{size}B 越出段 {sec.name} 的原始范围')
        return sec.virtual_address + delta

    # ------------------------------------------------------------------ 读字节
    def read_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_off(rva, size)
        return self.data[off:off + size]

    def read_off(self, off: int, size: int) -> bytes:
        if off < 0 or size < 0 or off + size > len(self.data):
            raise RvaError(
                f'读取越界：文件偏移 0x{off:X} + {size} B 超出文件大小 0x{len(self.data):X}'
                f'（该处多半是段的虚拟尾部，文件里没有字节）')
        return self.data[off:off + size]

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    # ------------------------------------------------------------------ 错误提示
    def _rva_hint(self, rva: int, why: str) -> str:
        hint = ''
        if rva >= self.image_base:
            hint = (f'；注意 0x{rva:X} 看起来像 VA 而不是 RVA，'
                    f'减掉 ImageBase 0x{self.image_base:X} 得 0x{rva - self.image_base:X}')
        return f'RVA 0x{rva:X} {why}（ImageBase=0x{self.image_base:X}{hint}）'


# ---------------------------------------------------------------------- 便捷函数
def load_pe(path: str) -> PEFile:
    """加载 PE（只读一次文件）。失败抛 PEFormatError。"""
    return PEFile(path)


def image_base(path: str) -> int:
    """只取 ImageBase（会完整加载一次；需要多次查询请直接持有 PEFile）。"""
    return load_pe(path).image_base


# ---------------------------------------------------------------------- CLI 小工具
def parse_int(tok: str) -> int:
    """解析 0x 前缀/十进制/八进制/二进制字面量，也允许纯十六进制（无 0x）。"""
    s = str(tok).strip().replace('_', '')
    try:
        return int(s, 0)
    except ValueError:
        pass
    # 形如 70538C0 这种没写 0x 的 RVA（含 a-f 时 int(,16) 才成立）
    try:
        return int(s, 16)
    except ValueError as exc:
        raise ValueError(f'无法解析整数: {tok!r}') from exc


def hexfmt(value: Optional[int], width: int = 8) -> str:
    """统一十六进制格式化；负数写成 -0x...（原先 f'0x{v:X}' 会打成 '0x-8'）。"""
    if value is None:
        return '—'
    if value < 0:
        return f'-0x{-value:0{width}X}'
    return f'0x{value:0{width}X}'


def emit_json(obj, *, stream=None) -> None:
    """统一的 --json 输出（UTF-8 中文不转义）。

    ``--json`` 生效时普通打印会被 :func:`json_aware_main` 挪到 stderr，
    这里把 JSON 写回**真正的 stdout**，保证 ``python x.py --json | jq`` 可用。
    """
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False),
          file=stream or _JSON_STREAM[0] or sys.stdout)


#: --json 模式下「真正 stdout」的暂存位（见 json_aware_main）
_JSON_STREAM = [None]


def json_aware_main(fn):
    """装饰 ``main()``：命令行带 ``--json`` 时把普通打印改道到 stderr。

    用法::

        @pe_utils.json_aware_main
        def main() -> int:
            ...
    """
    def wrapper(*args, **kwargs):
        as_json = '--json' in sys.argv[1:]
        if not as_json:
            return fn(*args, **kwargs)
        saved = sys.stdout
        sys.stdout = sys.stderr
        _JSON_STREAM[0] = saved
        try:
            return fn(*args, **kwargs)
        finally:
            sys.stdout = saved
            _JSON_STREAM[0] = None
    wrapper.__name__ = getattr(fn, '__name__', 'main')
    wrapper.__doc__ = fn.__doc__
    return wrapper


# ---------------------------------------------------------------------- 直接调用扫描
def find_direct_calls(pe: PEFile, section: Section, targets, *,
                      chunk_size: int = 8 << 20, overlap: int = 4):
    """在某个段里分块扫「直接 ``E8 rel32`` 调用」，返回 (命中表, 统计)。

    命中表: ``{target_rva: [call_rva, ...]}``（按 RVA 升序、去重）
    统计:   ``{'e8_total': int, 'chunks': int}``

    ★ 只认直接 ``E8 rel32``。间接调用（``FF /2``）、跳板/thunk、IAT 与重定位表、
    跳转表、以及 ``lea rax,[rip+...]`` + ``call rax`` 这类调用点**都扫不到** ——
    所以「0 处调用」绝不等于「确认无调用者」。

    分块是为了避免一次性 materialize 上千万条滑动窗口（原实现会吃掉几百 MB 临时内存）。

    ★ numpy 是**可选**依赖（只给这个函数用，不在 RVA 迁移主链路上）。缺了它时抛带安装
      提示的 :class:`NumpyMissing`，而**不是**返回空表 —— 空表会被读成"0 处调用"，
      而本函数恰恰扫不到间接调用，这个误读会直接把人带沟里。
    """
    try:
        import numpy as np
    except ImportError as exc:
        raise NumpyMissing(
            'find_direct_calls 需要 numpy（可选依赖）：pip install numpy。'
            '它不在 RVA 迁移链路上，update_rva / migrate_masked / pdata 不受影响。') from exc

    targets = list(dict.fromkeys(int(t) for t in targets))
    hits = {t: set() for t in targets}
    base_va = pe.image_base + section.virtual_address
    raw = section.raw_size
    e8_total = 0
    chunks = 0
    pos = 0
    while pos < raw:
        span = min(chunk_size + overlap, raw - pos)
        blob = np.frombuffer(pe.data, dtype=np.uint8, count=span,
                             offset=section.raw_ptr + pos)
        if blob.size >= 5:
            w = np.lib.stride_tricks.sliding_window_view(blob, 5)
            idx = np.flatnonzero(w[:, 0] == 0xE8)
            # 只保留窗口起点落在本块「本体」（不含 overlap 区）里的命中
            idx = idx[idx < min(chunk_size, raw - pos)]
            if idx.size:
                b = (blob[idx + 1].astype(np.uint32)
                     | (blob[idx + 2].astype(np.uint32) << 8)
                     | (blob[idx + 3].astype(np.uint32) << 16)
                     | (blob[idx + 4].astype(np.uint32) << 24))
                rel = b.astype(np.int32).astype(np.int64)
                tgt = np.int64(base_va + pos) + idx.astype(np.int64) + 5 + rel
                e8_total += int(idx.size)
                for t in targets:
                    hit = idx[tgt == np.int64(pe.image_base + t)]
                    for i in hit:
                        hits[t].add(section.virtual_address + pos + int(i))
            del w
        del blob
        chunks += 1
        pos += min(chunk_size, raw - pos)
    return ({t: sorted(v) for t, v in hits.items()},
            {'e8_total': e8_total, 'chunks': chunks})
