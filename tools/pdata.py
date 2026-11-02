#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pdata.py — 解析 PE 的函数边界表（RUNTIME_FUNCTION 数组）得到全部函数边界。

★ **读的是异常目录（数据目录[3]），不是按名字找 `.pdata` 段。**
  这版原神 exe 的 `.pdata` 段是**诱饵**：1,177,301 条里 588,950 条 end<=start，
  连一个真实函数起点都找不到；真正的表被搬进 `.upx0`，只有异常目录指向它
  （实测 RVA 0x19F73B00 / 0xD796B8 B / 1,177,402 条，全部合法、单调有序）。
  读错表的后果很隐蔽：函数边界全错 → 指纹截断错 → 跨版本迁移匹配不到或误匹配。
  现在两个来源都解析、按「合法条目占比」选可信的那个，另一个的分数写进 warnings。

用途：在 il2cpp 段里做「精确定点」——已知若干锚点函数的 RVA 后，
      可以直接列出它们附近的全部函数（新版本新增的函数就在其中）；
      也可以给指纹匹配（migrate_masked）提供**函数边界**，
      避免指纹跨越到下一个函数里去。

本模块同时是一个可复用的边界表接口：``load_function_bounds(pe)`` 返回
:class:`FunctionBounds`，提供 ``containing()/end_of()/slice_limit()/in_range()``，
供 update_rva.py 与 migrate_masked.py 直接调用。（历史上的"整类对齐"脚本 align_class.py
已随 2026-10-25 瘦身删除 —— ede0c7f，历史见 git。）

修掉的老问题：
  · ``data[ro:ro + min(rsz, vsz)]`` 会在 VirtualSize < SizeOfRawData 时**静默丢掉
    尾部条目** → 现在按原始大小全量解析，并把两者不一致的情况写进 warnings；
  · ``len(blob) // 12`` 会把不足一个条目的尾部字节**静默丢弃** → 现在显式报告残余字节数；
  · ``UnwindInfoAddress`` 解包后从未使用 → 现在会校验它是否落在映像内并参与展示。

用法：
  python pdata.py --exe <exe> [--near 0x6DAB600,0x6DAB540] [--span 0x2000] [--count]
  python pdata.py --exe <exe> --list 0x6DA8000 0x6DAE000 [--unwind] [--json]

退出码：0=正常；1=没有解析到任何有效函数条目；2=参数/PE/缺 .pdata 段。
"""
from __future__ import annotations

import argparse
import bisect
import struct
import sys
from dataclasses import dataclass
from typing import Iterable, Optional

import pe_utils

RUNTIME_FUNCTION_SIZE = 12
EXIT_OK = 0
EXIT_EMPTY = 1
EXIT_PARAM = 2


@dataclass(frozen=True)
class FunctionBound:
    """一条 RUNTIME_FUNCTION：函数起始 RVA、结束 RVA、异常处理信息 RVA。"""

    start: int
    end: int
    unwind: int
    unwind_in_image: bool = True

    @property
    def size(self) -> int:
        return self.end - self.start


class FunctionBounds:
    """按起始 RVA 排序的函数边界表（bisect 查询）。"""

    def __init__(self, bounds: Iterable[FunctionBound], *, info: Optional[dict] = None):
        self.bounds = sorted(bounds, key=lambda b: b.start)
        self._starts = [b.start for b in self.bounds]
        self.info = info or {}
        self.warnings = list(self.info.get('warnings', []))

    def __len__(self) -> int:
        return len(self.bounds)

    def __iter__(self):
        return iter(self.bounds)

    def starts(self) -> list:
        return list(self._starts)

    def containing(self, rva: int) -> Optional[FunctionBound]:
        """返回包含该 RVA 的函数边界（RVA 落在 [start, end) 内）；没有则 None。"""
        i = bisect.bisect_right(self._starts, rva) - 1
        if i >= 0:
            b = self.bounds[i]
            if b.start <= rva < b.end:
                return b
        return None

    def end_of(self, rva: int) -> Optional[int]:
        """该 RVA 所在函数的结束 RVA；查不到返回 None（调用方需自行决定回退策略）。"""
        b = self.containing(rva)
        return b.end if b else None

    def slice_limit(self, rva: int, want: int) -> int:
        """指纹/反汇编缓冲的长度上限：不越过函数末尾。

        查不到边界时返回 want（并在 warnings 里体现缺失），调用方可以据此决定
        是否要额外裁剪。
        """
        end = self.end_of(rva)
        if end is None:
            return want
        return max(1, min(want, end - rva))

    def in_range(self, lo: int, hi: int) -> list:
        i = bisect.bisect_left(self._starts, lo)
        out = []
        while i < len(self.bounds) and self.bounds[i].start < hi:
            out.append(self.bounds[i])
            i += 1
        return out


EXCEPTION_DIRECTORY_INDEX = 3     # IMAGE_DIRECTORY_ENTRY_EXCEPTION


def _scan_table(pe: pe_utils.PEFile, raw_ptr: int, raw_size: int, *,
                label: str) -> tuple[list, dict]:
    """按 RUNTIME_FUNCTION 数组解析一段原始字节，返回 (bounds, info)。"""
    warnings: list = []
    blob = pe.read_off(raw_ptr, raw_size)
    image_size = max([s.virtual_address + (s.virtual_size or s.raw_size)
                      for s in pe.sections] or [0])
    n, rem = divmod(len(blob), RUNTIME_FUNCTION_SIZE)
    if rem:
        warnings.append(
            f'{label}: 大小 0x{raw_size:X} 不是 {RUNTIME_FUNCTION_SIZE} 的整数倍，'
            f'尾部 {rem} B 是残缺条目（已显式报告，不再静默丢弃）')

    bounds, zero, malformed, unwind_bad = [], 0, 0, 0
    for i in range(n):
        start, end, unwind = struct.unpack_from('<III', blob, i * RUNTIME_FUNCTION_SIZE)
        if start == 0:
            zero += 1
            continue
        if end <= start:
            malformed += 1
            continue
        in_image = unwind == 0 or 0 < unwind < image_size
        if not in_image:
            unwind_bad += 1
        bounds.append(FunctionBound(start, end, unwind, in_image))

    if zero:
        warnings.append(f'{label}: 跳过 {zero} 条 start==0 的空条目')
    if malformed:
        warnings.append(f'{label}: 跳过 {malformed} 条 end<=start 的非法条目')
    if unwind_bad:
        warnings.append(f'{label}: {unwind_bad} 条条目的 UnwindInfoAddress 不在映像范围内（可疑）')

    info = dict(source=label, raw_ptr=raw_ptr, raw_size=raw_size, slots=n,
                entries=len(bounds), skipped_zero=zero, skipped_malformed=malformed,
                unwind_out_of_image=unwind_bad, remainder_bytes=rem,
                score=(len(bounds) / n) if n else 0.0, warnings=warnings)
    return bounds, info


def parse_pdata(pe: pe_utils.PEFile, *, section_name: str = '.pdata') -> FunctionBounds:
    """解析函数边界表（RUNTIME_FUNCTION 数组）。

    ★ 必须优先读**异常目录**（数据目录[3]），而不是按名字找 `.pdata` 段：
    这版原神 exe 的 `.pdata` 段是**诱饵**（1,177,301 条里 588,950 条 end<=start，
    且找不到任何真实函数起点），真正的表被搬到了 `.upx0` 里，只有异常目录指向它
    （实测 RVA 0x19F73B00 / 0xD796B8 字节 / 1,177,402 条，全部合法且单调有序）。
    读错表的后果很隐蔽：函数边界全错 → 指纹截断错 → 跨版本迁移匹配不到或误匹配。
    所以这里两个来源都解析，按「合法条目占比」选可信的那个，并把另一个的分数写进 warnings。
    """
    candidates = []

    # ① 异常目录（正道）
    try:
        dd = pe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[EXCEPTION_DIRECTORY_INDEX]
        dd_rva, dd_size = int(dd.VirtualAddress), int(dd.Size)
    except (AttributeError, IndexError):          # pragma: no cover - 没有数据目录的畸形 PE
        dd_rva, dd_size = 0, 0
    if dd_rva and dd_size >= RUNTIME_FUNCTION_SIZE:
        try:
            off = pe.rva_to_off(dd_rva, dd_size)
            bounds, info = _scan_table(pe, off, dd_size, label='异常目录')
            info['rva'] = dd_rva
            candidates.append((bounds, info))
        except (pe_utils.RvaError, pe_utils.PEFormatError) as exc:
            candidates.append(([], dict(source='异常目录', score=0.0, slots=0, entries=0,
                                        rva=dd_rva,
                                        warnings=[f'异常目录不可用：{exc}'])))

    # ② .pdata 段（★ 可能是诱饵，只在分数更高时才采信）
    sec = pe.find_section(section_name)
    if sec is not None and sec.raw_size:
        bounds, info = _scan_table(pe, sec.raw_ptr, sec.raw_size, label=sec.name)
        info['rva'] = sec.virtual_address
        info['virtual_size'] = sec.virtual_size
        if sec.virtual_size and sec.virtual_size < sec.raw_size:
            info['warnings'].append(
                f'{sec.name}: VirtualSize 0x{sec.virtual_size:X} < SizeOfRawData 0x{sec.raw_size:X}，'
                f'本次按**原始大小**全量解析（旧实现用 min() 会静默丢掉尾部条目）')
        candidates.append((bounds, info))

    if not candidates:
        raise pe_utils.PEFormatError(
            f'{pe.path}: 既没有异常目录也没有 {section_name} 段，无法得到函数边界')

    candidates.sort(key=lambda c: c[1]['score'], reverse=True)
    bounds, info = candidates[0]
    if not bounds:
        raise pe_utils.PEFormatError(
            f'{pe.path}: 两个来源都解析不出合法函数条目（'
            + '；'.join(f'{c[1]["source"]} score={c[1]["score"]:.2f}' for c in candidates) + '）')

    warnings = list(info['warnings'])
    for other_bounds, other in candidates[1:]:
        if other['source'] != info['source']:
            warnings.append(
                f'{other["source"]} 只有 {other["entries"]:,} 条合法条目（合法率 '
                f'{other["score"]:.0%}，共 {other["slots"]:,} 槽位）→ 未采用'
                + ('（这版 exe 的该来源是诱饵）' if other['score'] < 0.5 else ''))
            # 只有「这个来源彻底用不了」（0 条合法条目，例如异常目录指向段外）才把它的
            # 逐条警告带出来；诱饵那种"能解析但分数低"的情况只留上面一行摘要，免得刷屏。
            if not other['entries']:
                warnings.extend(w for w in other.get('warnings', []) if w not in warnings)
    info['warnings'] = warnings
    info['source_rva'] = info.get('rva', 0)
    return FunctionBounds(bounds, info=info)


def load_function_bounds(pe: pe_utils.PEFile, *, required: bool = False) -> Optional[FunctionBounds]:
    """给 align_class / migrate_masked 用的入口。

    ★ 有**异常目录**就算有边界（这版 exe 真正的表在那里，`.pdata` 段是诱饵）。
    required=False（默认）时，两者都没有就返回 None 并让调用方自己决定降级策略
    （降级必须在输出里写清楚）。required=True 时直接抛 PEFormatError。
    """
    try:
        dd = pe.pe.OPTIONAL_HEADER.DATA_DIRECTORY[EXCEPTION_DIRECTORY_INDEX]
        has_exc = int(dd.VirtualAddress) != 0 and int(dd.Size) >= RUNTIME_FUNCTION_SIZE
    except (AttributeError, IndexError):          # pragma: no cover
        has_exc = False
    if not has_exc and pe.find_section('.pdata') is None:
        if required:
            raise pe_utils.PEFormatError(
                f'{pe.path}: 既没有异常目录也没有 .pdata 段，无法得到函数边界；'
                f'现有段: {", ".join(pe.section_names)}')
        return None
    return parse_pdata(pe)


def main() -> int:
    ap = argparse.ArgumentParser(
        description='解析函数边界表（优先异常目录；.pdata 段可能是诱饵）')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--near', default='', help='锚点 RVA，逗号分隔')
    ap.add_argument('--span', type=pe_utils.parse_int, default=0x1800)
    ap.add_argument('--list', nargs=2, default=None, metavar=('LO', 'HI'))
    ap.add_argument('--count', action='store_true', help='只统计不列函数')
    ap.add_argument('--unwind', action='store_true', help='多打印 UnwindInfoAddress')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM
    try:
        fb = load_function_bounds(pe, required=True)
    except pe_utils.PEFormatError as exc:
        print(f'错误：{exc}', file=sys.stderr)
        return EXIT_PARAM

    out = dict(exe=a.exe, image_base=pe.image_base, pdata=fb.info, functions=[])
    if not a.json:
        src, srv = fb.info.get('source', '?'), fb.info.get('rva', 0)
        print(f'{a.exe}\n  边界表来源: {src}（RVA 0x{srv:X}）')
        print(f'  函数条目: {len(fb):,} / 槽位 {fb.info["slots"]:,}')
        for w in fb.warnings:
            print(f'  ⚠ {w}')

    if len(fb) == 0:
        print('错误：边界表里没有任何有效函数条目', file=sys.stderr)
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_EMPTY

    def fmt(b: FunctionBound) -> str:
        s = f'     RVA 0x{b.start:08X} .. 0x{b.end:08X}   size {b.size:>5}'
        if a.unwind:
            s += f'   unwind 0x{b.unwind:08X}{"" if b.unwind_in_image else " ⚠不在映像内"}'
        return s

    if a.count:
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_OK

    if a.list:
        lo, hi = (pe_utils.parse_int(a.list[0]), pe_utils.parse_int(a.list[1]))
        if hi <= lo:
            print('错误：--list 的 HI 必须大于 LO', file=sys.stderr)
            return EXIT_PARAM
        sel = fb.in_range(lo, hi)
        out['range'] = dict(lo=lo, hi=hi, count=len(sel))
        out['functions'] = [dict(start=b.start, end=b.end, size=b.size, unwind=b.unwind)
                            for b in sel]
        if not a.json:
            print(f'\n  RVA 0x{lo:X}..0x{hi:X} 内 {len(sel)} 个函数')
            prev = None
            for b in sel:
                gap = '' if prev is None or b.start == prev else f'  (gap {b.start - prev} B)'
                print(fmt(b) + gap)
                prev = b.end
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_OK

    if not a.near:
        print('\n（未给 --near / --list / --count：只打印了统计。'
              '用 --list 或 --near 查看具体函数）')
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_OK

    for tok in a.near.split(','):
        tok = tok.strip()
        if not tok:
            continue
        try:
            rva = pe_utils.parse_int(tok)
        except ValueError as exc:
            print(f'错误：{exc}', file=sys.stderr)
            return EXIT_PARAM
        sel = fb.in_range(max(0, rva - a.span), rva + a.span + 1)
        if not a.json:
            print(f'\n=== 锚点 RVA 0x{rva:X} 附近（±0x{a.span:X}）===')
            print(f'  共 {len(sel)} 个函数')
        for b in sel:
            out['functions'].append(dict(start=b.start, end=b.end, size=b.size,
                                         unwind=b.unwind, anchor=b.start == rva))
            if not a.json:
                mark = '   <<<<<< 锚点' if b.start == rva else ''
                print(fmt(b) + mark)
    if a.json:
        pe_utils.emit_json(out)
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
