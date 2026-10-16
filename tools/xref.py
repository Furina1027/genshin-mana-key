#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xref.py — 一次扫描解析多个 target RVA 的**直接** call 引用（原神 exe 的代码在 il2cpp 段）。

用法:
  python xref.py --exe <exe> --only il2cpp \
      --rva name=0x7054B80 --rva name2=0x70547F0 [--ctx 3] [--json]

⚠ 扫描范围的诚实说明（很重要）：
  这里只找**直接 ``E8 rel32`` 调用**。下面这些一律扫不到：
    · 间接调用 ``FF /2``（call r/m64）        · thunk / 跳板函数
    · IAT、导入表、重定位表                   · 跳转表/switch
    · ``lea rax,[rip+...]`` + ``call rax``   · 虚调用（vtable）
  所以「0 处调用」**不等于**「确认无调用者」，只能说「没有直接调用」。
  输出里每次都会带上这句提示。

内存：整段扫描是**分块**做的（默认 8 MiB + 4 字节重叠），不会像旧实现那样
一次性 materialize 上千万条滑窗（几百 MB 临时内存）。

退出码：0=正常；1=有 target RVA 不在任何被扫描的段内（多半是 RVA 给错了）；
        2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import os
import sys

try:
    import numpy as np
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError as exc:                       # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。安装：pip install -r tools/requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

import pe_utils

EXIT_OK = 0
EXIT_BAD_TARGET = 1
EXIT_PARAM = 2

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

CAVEAT = ('只找直接 E8 rel32 调用；间接调用（FF /2）、thunk/跳板、IAT、跳转表、'
          'lea rip + call reg、虚调用都不可见 —— 「0 处」不等于「确认无调用者」')


@pe_utils.json_aware_main
def main() -> int:
    ap = argparse.ArgumentParser(
        description='扫描直接 call 引用（只认 E8 rel32；分块扫描，内存可控）')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--rva', action='append', required=True, help='name=0xRVA')
    ap.add_argument('--only', default='', help='只扫这些段（逗号分隔），默认 .text,il2cpp')
    ap.add_argument('--ctx', type=int, default=4, help='调用点上下文打印的函数数')
    ap.add_argument('--pre', type=pe_utils.parse_int, default=0x40,
                    help='调用点向前回看的字节数（会夹取到段首）')
    ap.add_argument('--max-show', type=int, default=6, help='每个 target 最多打印几处')
    ap.add_argument('--chunk', type=pe_utils.parse_int, default=8 << 20,
                    help='分块扫描的块大小（字节，默认 8 MiB）')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.ctx < 0 or a.max_show < 0 or a.pre < 0 or a.chunk < 5:
        print('错误：--ctx/--max-show/--pre 不能为负，--chunk 必须 >= 5', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    want = [s.strip() for s in a.only.split(',') if s.strip()] if a.only else ['.text', 'il2cpp']
    secs = []
    for nm in want:
        sec = pe.section_by_name(nm, required=False)
        if sec is None:
            print(f'  ⚠ 段 {nm!r} 不存在（现有段: {", ".join(pe.section_names)}）')
            continue
        if not sec.raw_size:
            print(f'  ⚠ 段 {nm!r} 的 SizeOfRawData 为 0，跳过')
            continue
        secs.append(sec)
    if not secs:
        print(f'错误：没有可扫描的段（--only {",".join(want)}）', file=sys.stderr)
        return EXIT_PARAM

    targets = {}
    for spec in a.rva:
        if '=' not in spec:
            print(f'错误：--rva 需要 name=0xRVA 形式，收到 {spec!r}', file=sys.stderr)
            return EXIT_PARAM
        nm, hs = spec.split('=', 1)
        try:
            rva = pe_utils.parse_int(hs)
        except ValueError as exc:
            print(f'错误：{exc}', file=sys.stderr)
            return EXIT_PARAM
        targets[rva] = nm
    if len(targets) != len(a.rva):
        print('警告：有重复的 target RVA，已按后者名字合并', file=sys.stderr)

    print(f'{a.exe}\nImageBase=0x{pe.image_base:X}  扫描段: {[s.name for s in secs]}')
    print(f'★ {CAVEAT}')

    found = {t: [] for t in targets}
    e8_total = 0
    for sec in secs:
        hits, stats = pe_utils.find_direct_calls(pe, sec, targets.keys(), chunk_size=a.chunk)
        e8_total += stats['e8_total']
        for trva in targets:
            found[trva].extend(hits.get(trva, []))
        print(f'  段 {sec.name}: 扫到 E8 调用 {stats["e8_total"]:,} 处'
              f'（分 {stats["chunks"]} 块，块大小 0x{a.chunk:X}）')
    for t in found:
        found[t] = sorted(set(found[t]))

    missing = [t for t in targets if pe.section_of_rva(t, required=False) is None]
    results = []
    print()
    for trva, nm in sorted(targets.items(), key=lambda kv: kv[1]):
        hs = found[trva]
        in_sec = pe.section_of_rva(trva, required=False)
        print(f'== {nm}  RVA 0x{trva:X}  调用点 ×{len(hs)}'
              + (f'   [该 RVA 不在任何段内！]' if in_sec is None else ''))
        entry = dict(name=nm, rva=trva, section=in_sec.name if in_sec else None,
                     hit_count=len(hs), hits=[])
        for h in hs[:a.max_show]:
            try:
                ho = pe.rva_to_off(h)
                sec = pe.section_of_rva(h)
            except pe_utils.RvaError:
                continue
            entry['hits'].append(dict(rva=h, section=sec.name))
            print(f'   ◆ 调用点 RVA 0x{h:X} (段 {sec.name})')
            if a.ctx:
                back = min(a.pre, h - sec.virtual_address, ho)
                for ins in md.disasm(pe.data[ho - back:ho + 0x20],
                                     pe.image_base + h - back):
                    mark = '   <<< call target' if ins.address == pe.image_base + h else ''
                    print(f'       0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{mark}')
        if len(hs) > a.max_show:
            print(f'   （还有 {len(hs) - a.max_show} 处未打印）')
        if not hs:
            print('   ⚠ 0 处：请结合上面的说明理解 —— 这不代表「没有调用者」')
        results.append(entry)

    if a.json:
        pe_utils.emit_json(dict(exe=a.exe, image_base=pe.image_base,
                                scanned_sections=[s.name for s in secs],
                                e8_total=e8_total, caveat=CAVEAT,
                                targets=results,
                                targets_out_of_any_section=missing))
    if missing:
        print(f'\n错误：{len(missing)} 个 target RVA 不在任何段内：'
              f'{[hex(x) for x in missing]}（RVA 给错了？）', file=sys.stderr)
        return EXIT_BAD_TARGET
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
