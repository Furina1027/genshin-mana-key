#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_xref.py — 一次扫描解析多个 target RVA 的 call 引用（原神 exe 的代码在 il2cpp 段）。

用法:
  python gia_xref.py --exe <exe> --only il2cpp \
      --rva name=0x7054B80 --rva name2=0x70547F0 [--ctx 3]
"""
from __future__ import annotations

import argparse

import numpy as np
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--rva', action='append', required=True, help='name=0xRVA')
    ap.add_argument('--only', default='', help='只扫这些段（逗号分隔），默认 .text,il2cpp')
    ap.add_argument('--ctx', type=int, default=4, help='调用点上下文打印的函数数')
    ap.add_argument('--pre', type=int, default=0x40)
    a = ap.parse_args()

    data = open(a.exe, 'rb').read()
    pe = pefile.PE(a.exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    want = [s.strip() for s in a.only.split(',')] if a.only else ['.text', 'il2cpp']
    secs = []
    for s in pe.sections:
        nm = s.Name.rstrip(b'\x00').decode('latin1')
        if nm in want and s.SizeOfRawData:
            secs.append((nm, s.VirtualAddress, s.SizeOfRawData, s.PointerToRawData))
    print(f'{a.exe}\nImageBase=0x{base:X}  扫描段: {[s[0] for s in secs]}')

    targets = {}
    for spec in a.rva:
        nm, hs = spec.split('=')
        targets[int(hs, 0)] = nm

    found = {r: [] for r in targets}
    for nm, sva, rsz, ro in secs:
        blob = np.frombuffer(data, dtype=np.uint8, count=rsz, offset=ro)
        w = np.lib.stride_tricks.sliding_window_view(blob, 5)
        idx = np.flatnonzero(w[:, 0] == 0xE8)
        if idx.size == 0:
            continue
        b = blob[idx + 1].astype(np.uint32) \
            | (blob[idx + 2].astype(np.uint32) << 8) \
            | (blob[idx + 3].astype(np.uint32) << 16) \
            | (blob[idx + 4].astype(np.uint32) << 24)
        rel = b.astype(np.int32).astype(np.int64)
        tgt = np.int64(base + sva) + idx.astype(np.int64) + 5 + rel
        for trva in targets:
            hit = idx[tgt == np.int64(base + trva)]
            for i in hit:
                found[trva].append((int(base + sva + i), nm, int(ro + i)))
        print(f'  段 {nm}: 扫到 E8 调用 {idx.size:,} 处')

    print()
    for trva, nm in sorted(targets.items(), key=lambda kv: kv[1]):
        hs = found[trva]
        print(f'== {nm}  RVA 0x{trva:X}  调用点 ×{len(hs)}')
        for h, sn, ho in hs[:6]:
            print(f'   ◆ 调用点 RVA 0x{h - base:X} (段 {sn})')
            if a.ctx:
                back = a.pre
                if ho - back < 0:
                    back = ho
                for ins in md.disasm(data[ho - back:ho + 0x20], h - back):
                    mark = '   <<< call target' if ins.address == h else ''
                    print(f'       0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{mark}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
