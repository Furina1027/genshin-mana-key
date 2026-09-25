#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_pdata.py — 解析 PE 的 .pdata（RUNTIME_FUNCTION）得到全部函数边界。

用途：在 il2cpp 段里做「精确定点」——已知若干锚点函数的 RVA 后，
      可以直接列出它们附近的全部函数（新版本新增的函数就在其中）。

用法：
  python gia_pdata.py --exe <exe> [--near 0x6DAB600,0x6DAB540] [--span 0x2000] [--count]
  python gia_pdata.py --exe <exe> --list 0x6DA8000 0x6DAE000
"""
from __future__ import annotations

import argparse
import struct as st

import pefile


def load(exe):
    pe = pefile.PE(exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = {}
    for s in pe.sections:
        nm = s.Name.rstrip(b'\x00').decode('latin1')
        secs[nm] = (s.VirtualAddress, s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData)
    return pe, base, secs


def get_pdata(exe):
    pe, base, secs = load(exe)
    if '.pdata' not in secs:
        raise RuntimeError('无 .pdata 段')
    va, vsz, rsz, ro = secs['.pdata']
    data = open(exe, 'rb').read()
    blob = data[ro:ro + min(rsz, vsz)]
    n = len(blob) // 12
    out = []
    for i in range(n):
        b, e, u = st.unpack_from('<III', blob, i * 12)
        if b == 0:
            continue
        out.append((b, e, u))
    out.sort()
    return out, base, secs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--near', default='')
    ap.add_argument('--span', type=lambda x: int(x, 0), default=0x1800)
    ap.add_argument('--list', nargs=2, default=None)
    ap.add_argument('--count', action='store_true')
    a = ap.parse_args()

    pd, base, secs = get_pdata(a.exe)
    print(f'{a.exe}\n  .pdata 函数条目: {len(pd):,}')
    if a.count:
        return 0
    starts = [p[0] for p in pd]

    if a.list:
        lo, hi = int(a.list[0], 0), int(a.list[1], 0)
        sel = [p for p in pd if lo <= p[0] < hi]
        print(f'\n  RVA 0x{lo:X}..0x{hi:X} 内 {len(sel)} 个函数')
        prev = None
        for b, e, u in sel:
            gap = '' if prev is None or b == prev else f'  (gap {b - prev} B)'
            print(f'     RVA 0x{b:08X} .. 0x{e:08X}   size {e - b:>5}{gap}')
            prev = e
        return 0

    for tok in a.near.split(','):
        if not tok.strip():
            continue
        rva = int(tok, 0)
        print(f'\n=== 锚点 RVA 0x{rva:X} 附近（±0x{a.span:X}）===')
        sel = [p for p in pd if rva - a.span <= p[0] <= rva + a.span]
        print(f'  共 {len(sel)} 个函数')
        for b, e, u in sel:
            mark = '   <<<<<< 锚点' if b == rva else ''
            print(f'     RVA 0x{b:08X} .. 0x{e:08X}   size {e - b:>5}{mark}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
