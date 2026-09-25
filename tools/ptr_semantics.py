#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_ptr_semantics.py — 验证「指针数组下标 == dump 的全局方法索引」。

输入若干 (idx, rva) 对（来自 dump70.cs），在 exe 里找该函数 VA 的存放位置，
再检查 (offset - idx*8) 是否收敛到同一个基址 → 是则数组即 methodPointer 表。
"""
from __future__ import annotations

import argparse
import struct as st

import pefile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--pair', action='append', required=True, help='idx:rva')
    a = ap.parse_args()

    data = open(a.exe, 'rb').read()
    pe = pefile.PE(a.exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
             s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]
    print(f'{a.exe}  ImageBase=0x{base:X}')
    for s in secs:
        print(f'   {s[0]:10} VA 0x{s[1]:08X}  VSize 0x{s[2]:08X}  Raw 0x{s[3]:08X} @0x{s[4]:X}')

    implied = []
    for spec in a.pair:
        hs, rs = spec.split(':')
        i, rva = int(hs, 0), int(rs, 0)
        pat = (base + rva).to_bytes(8, 'little')
        occ = []
        i0 = data.find(pat)
        while i0 >= 0:
            occ.append(i0)
            i0 = data.find(pat, i0 + 1)
        print(f'\n[{i:>7}] RVA 0x{rva:X}  VA 0x{base + rva:X}  出现 {len(occ)} 次')
        for o in occ[:8]:
            print(f'      文件 0x{o:X}   隐含表基址 = 0x{o - i * 8:X}')
            implied.append(o - i * 8)
    if implied:
        from collections import Counter
        c = Counter(implied)
        print('\n== 隐含基址统计 ==')
        for k, v in c.most_common(6):
            print(f'   0x{k:X}  出现 {v} 次')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
