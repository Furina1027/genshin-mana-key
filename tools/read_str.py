#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_read_str.py — 读 exe 里某个 RVA 处的 C 字符串（P/Invoke 的模块名 / 入口名）。"""
from __future__ import annotations

import argparse

import pefile


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--rva', action='append', required=True)
    ap.add_argument('--len', type=int, default=0)
    a = ap.parse_args()
    pe = pefile.PE(a.exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
             s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]
    data = open(a.exe, 'rb').read()
    for tok in a.rva:
        rva = int(tok, 0)
        o = None
        for nm, sva, vsz, rsz, ro in secs:
            if sva <= rva < sva + max(vsz, rsz):
                o = ro + (rva - sva)
                break
        if o is None:
            print(f'RVA 0x{rva:X}: 不在段内')
            continue
        raw = data[o:o + (a.len or 96)]
        s = raw.split(b'\x00', 1)[0]
        try:
            txt = s.decode('utf-8')
        except Exception:
            txt = repr(s)
        print(f'RVA 0x{rva:X} : {txt!r}  (字节长度 {len(s)})')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
