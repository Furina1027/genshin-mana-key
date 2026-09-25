#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_table_scan.py — 在 methodPointer 表里按 RVA 区间反查方法索引，并列出该区间的全部方法。

用法：
  python gia_table_scan.py --exe <exe> --base 0x2870C78 --rva-lo 0x7053000 --rva-hi 0x7055000
  python gia_table_scan.py --exe <exe> --base 0x2870C78 --find 0x7053800,0x70538C0
"""
from __future__ import annotations

import argparse
import struct as st

import numpy as np
import pefile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--base', required=True, help='methodPointer 表文件偏移')
    ap.add_argument('--entries', type=int, default=600000)
    ap.add_argument('--rva-lo', default='')
    ap.add_argument('--rva-hi', default='')
    ap.add_argument('--find', default='')
    a = ap.parse_args()

    data = open(a.exe, 'rb').read()
    pe = pefile.PE(a.exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
             s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]

    def off2rva(off):
        for nm, sva, vsz, rsz, ro in secs:
            if ro <= off < ro + rsz:
                return sva + (off - ro), nm
        return None, None

    b = int(a.base, 0)
    n = a.entries
    q = np.frombuffer(data, dtype='<u8', count=n, offset=b)
    print(f'methodPointer 表 文件偏移 0x{b:X} → 段 RVA 0x{off2rva(b)[0]:X}   读入 {n} 项')

    if a.find:
        for tok in a.find.split(','):
            target = base + int(tok, 0)
            hit = np.flatnonzero(q == np.uint64(target))
            print(f'  RVA 0x{int(tok, 0):X} (VA 0x{target:X}) → 索引 {hit.tolist()}')
        return 0

    if a.rva_lo:
        lo = base + int(a.rva_lo, 0)
        hi = base + int(a.rva_hi, 0) if a.rva_hi else lo + 0x100000
        sel = np.flatnonzero((q >= lo) & (q < hi))
        print(f'\nVA 0x{lo:X}..0x{hi:X} 内 {len(sel)} 个方法指针')
        for i in sel:
            v = int(q[int(i)])
            rva, sn = off2rva(None) if False else (v - base, 'il2cpp')
            print(f'   idx {int(i):>7}   RVA 0x{rva:08X}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
