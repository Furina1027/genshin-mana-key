#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_find_methptr.py — 定位 7.1 exe 里真正的 methodPointer 表。

思路：methodPointer 表是一大段连续的 8 字节指针，全部指向 il2cpp 段内的函数。
      在文件里扫「连续 N 个 8 字节值都落在 il2cpp 段范围内」的密集区。
      再用官方 CDN 给的已知 RVA（to_int32 / decompress）反查它出现在表的第几项。

用法：
  python gia_find_methptr.py --exe <exe> [--known 0x195DF330=to_int32 ...] [--minrun 2000]
"""
from __future__ import annotations

import argparse

import numpy as np
import pefile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--known', action='append', default=[], help='rva=name')
    ap.add_argument('--minrun', type=int, default=2000)
    ap.add_argument('--top', type=int, default=8)
    a = ap.parse_args()

    data = open(a.exe, 'rb').read()
    pe = pefile.PE(a.exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
             s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]
    il2 = [s for s in secs if s[0] == 'il2cpp'][0]
    lo_rva, hi_rva = il2[1], il2[1] + il2[2]
    lo, hi = base + lo_rva, base + hi_rva
    print(f'{a.exe}')
    print(f'ImageBase=0x{base:X}  il2cpp 段 VA 0x{il2[1]:X}..0x{hi_rva:X}')

    # 只扫 .rdata/.data 这两类「表」所在段
    for name, sva, vsz, rsz, ro in secs:
        if name not in ('.rdata', '.data', '_RDATA'):
            continue
        blob = data[ro:ro + rsz]
        n = len(blob) // 8
        if n < a.minrun:
            continue
        q = np.frombuffer(blob[:n * 8], dtype='<u8')
        ok = (q >= lo) & (q < hi)
        # 找最长连续 True 段
        runs = []
        i = 0
        while i < n:
            if ok[i]:
                j = i
                while j < n and ok[j]:
                    j += 1
                if j - i >= a.minrun:
                    runs.append((i, j))
                i = j
            else:
                i += 1
        if not runs:
            continue
        for i, j in runs[:a.top]:
            rva = sva + i * 8
            print(f'  [{name}] 连续指针段: 文件偏移 0x{ro + i * 8:X}  RVA 0x{rva:X}  '
                  f'共 {j - i} 项  (0x{(j - i) * 8:X} B)')
            for spec in a.known:
                hs, nm = spec.split('=')
                target = base + int(hs, 0)
                for k in range(j - i):
                    if int(q[i + k]) == target:
                        print(f'      ★ 已知 {nm} (VA 0x{target:X}) 位于表内第 {k} 项 '
                              f'→ 表基址 RVA 0x{rva - k * 8:X}')
                        break
                else:
                    print(f'      -- 未在该段找到 {nm}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
