#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""table_scan.py — 在 methodPointer 表里按 RVA 区间反查方法索引，并列出该区间的全部方法。

用法：
  python table_scan.py --exe <exe> --base 0x2870C78 --rva-lo 0x7053000 --rva-hi 0x7055000
  python table_scan.py --exe <exe> --base-rva 0x2870C78 --find 0x7053800,0x70538C0
  python table_scan.py --exe <exe> --base 0x2870C78 --find 0x7053800 --json

语义（不再混用两套范围）：
  · ``--base``      = 表在**文件里的偏移**（原语义，保留）
  · ``--base-rva``  = 表基址 RVA（会先转成文件偏移）
  · ``--base-va``   = 表基址 VA（减去 ImageBase 再转）
  三个互斥；表项是 8 字节 VA，方法 RVA = VA - ImageBase，段名用**虚拟范围**判定。

修掉的老问题：``off2rva(None) ...`` 形式的三元死代码、把所有命中都标成 il2cpp、
``np.frombuffer(count=600000)`` 越界抛裸异常、文件偏移/虚拟范围混用。

退出码：0=正常；1=有方法指针落在段外（表基址或区间可疑）；2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import sys

try:
    import numpy as np
except ImportError as exc:                       # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。安装：pip install -r tools/requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

import pe_utils

EXIT_OK = 0
EXIT_OUT_OF_RANGE = 1
EXIT_PARAM = 2


def resolve_base(pe: pe_utils.PEFile, a) -> int:
    """把 --base / --base-rva / --base-va 统一解析成**文件偏移**。"""
    given = [x for x in ((a.base, '--base'), (a.base_rva, '--base-rva'),
                         (a.base_va, '--base-va')) if x[0]]
    if len(given) != 1:
        raise ValueError('必须且只能给 --base / --base-rva / --base-va 其中一个'
                         f'（收到 {len(given)} 个）')
    text, which = given[0]
    val = pe_utils.parse_int(text)
    if which == '--base':
        return val
    if which == '--base-va':
        val = pe.rva_to_va(val) if val < pe.image_base else val
        val -= pe.image_base
    return pe.rva_to_off(val)


def main() -> int:
    ap = argparse.ArgumentParser(
        description='按 RVA 区间反查 methodPointer 表里的方法索引')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--base', default='', help='表的**文件偏移**')
    ap.add_argument('--base-rva', default='', help='表基址 RVA（与 --base 二选一）')
    ap.add_argument('--base-va', default='', help='表基址 VA（与 --base 二选一）')
    ap.add_argument('--entries', type=int, default=0,
                    help='最多读多少项（默认 0=自动：能读多少读多少，上限 600000）')
    ap.add_argument('--allow-clamp', action='store_true',
                    help='--entries 超过文件可用范围时自动夹取（默认直接报错）')
    ap.add_argument('--rva-lo', default='')
    ap.add_argument('--rva-hi', default='')
    ap.add_argument('--find', default='', help='要反查的 RVA，逗号分隔')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.entries < 0:
        print('错误：--entries 不能为负（0 表示自动）', file=sys.stderr)
        return EXIT_PARAM
    if not a.rva_lo and not a.find:
        print('错误：至少要给 --find 或 --rva-lo', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    try:
        base_off = resolve_base(pe, a)
    except (ValueError, pe_utils.RvaError) as exc:
        print(f'错误：表基址无效：{exc}', file=sys.stderr)
        return EXIT_PARAM
    if base_off % 8:
        print(f'错误：表基址（文件偏移 0x{base_off:X}）不是 8 字节对齐的', file=sys.stderr)
        return EXIT_PARAM

    sec = pe.section_of_off(base_off, required=False)
    avail_bytes = len(pe.data) - base_off
    max_entries = max(0, avail_bytes // 8)
    n = a.entries if a.entries else min(600000, max_entries)
    if n > max_entries:
        if not a.allow_clamp:
            print(f'错误：--entries {n} 超出可用范围：从文件偏移 0x{base_off:X} 起'
                  f'只剩 {avail_bytes} B（{max_entries} 项）。'
                  f'用 --allow-clamp 才会自动夹取。', file=sys.stderr)
            return EXIT_PARAM
        print(f'警告：--entries {n} → 自动夹取到 {max_entries} 项（--allow-clamp）',
              file=sys.stderr)
        n = max_entries
    if n == 0:
        print('错误：可用项数为 0（表基址已经到文件末尾？）', file=sys.stderr)
        return EXIT_PARAM

    try:
        raw = pe.read_off(base_off, n * 8)
    except pe_utils.RvaError as exc:
        print(f'错误：读表失败：{exc}', file=sys.stderr)
        return EXIT_PARAM
    q = np.frombuffer(raw, dtype='<u8')

    base_rva = pe.off_to_rva(base_off, n * 8)
    base_sec = pe.section_of_off(base_off)
    head = (f'methodPointer 表：文件偏移 0x{base_off:X} → RVA 0x{base_rva:X} '
            f'(段 {base_sec.name})  读入 {n} 项')
    out = dict(exe=a.exe, image_base=pe.image_base, base_file_offset=base_off,
               base_rva=base_rva, base_section=base_sec.name, entries=n,
               table_bytes=n * 8, finds=[], range=None, out_of_range=0)
    if not a.json:
        print(head)

    bad = 0
    if a.find:
        for tok in a.find.split(','):
            tok = tok.strip()
            if not tok:
                continue
            try:
                rva = pe_utils.parse_int(tok)
            except ValueError as exc:
                print(f'错误：{exc}', file=sys.stderr)
                return EXIT_PARAM
            target = pe.rva_to_va(rva)
            hit = np.flatnonzero(q == np.uint64(target))
            idxs = [int(i) for i in hit]
            s = pe.section_of_rva(rva, required=False)
            entry = dict(rva=rva, va=target, indices=idxs, count=len(idxs),
                         section=s.name if s else None)
            out['finds'].append(entry)
            if not a.json:
                print(f'  RVA 0x{rva:X} (VA 0x{target:X}) → 索引 {idxs}'
                      f'   段 {entry["section"] or "不在任何段内"}')
            if s is None:
                bad += 1
        if not a.json and not out['finds']:
            print('  （没有 --find 目标）')

    if a.rva_lo:
        try:
            lo_rva = pe_utils.parse_int(a.rva_lo)
            hi_rva = pe_utils.parse_int(a.rva_hi) if a.rva_hi else lo_rva + 0x100000
        except ValueError as exc:
            print(f'错误：{exc}', file=sys.stderr)
            return EXIT_PARAM
        if hi_rva <= lo_rva:
            print('错误：--rva-hi 必须大于 --rva-lo', file=sys.stderr)
            return EXIT_PARAM
        lo, hi = pe.rva_to_va(lo_rva), pe.rva_to_va(hi_rva)
        sel = np.flatnonzero((q >= np.uint64(lo)) & (q < np.uint64(hi)))
        out['range'] = dict(lo_rva=lo_rva, hi_rva=hi_rva, count=int(sel.size))
        if not a.json:
            print(f'\nVA 0x{lo:X}..0x{hi:X}（RVA 0x{lo_rva:X}..0x{hi_rva:X}）'
                  f' 内 {sel.size} 个方法指针')
        for i in sel:
            i = int(i)
            va = int(q[i])
            rva = va - pe.image_base
            s = pe.section_of_rva(rva, required=False)
            name = s.name if s else '不在任何段内'
            if s is None:
                bad += 1
            out.setdefault('range_items', []).append(
                dict(index=i, rva=rva, va=va, section=s.name if s else None))
            if not a.json:
                print(f'   idx {i:>7}   RVA 0x{rva:08X}   [{name}]')
    out['out_of_range'] = bad

    if a.json:
        pe_utils.emit_json(out)
    if bad:
        print(f'\n错误：{bad} 个目标/指针不在任何段内 —— 表基址或 RVA 区间可疑',
              file=sys.stderr)
        return EXIT_OUT_OF_RANGE
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
