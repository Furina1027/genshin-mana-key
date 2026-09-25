#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""定点反汇编：gia_dump_rva.py  --exe <exe> --rva 0x6B46620[,0x...] [--len 240] [--find-call 0x6B46620]

--find-call 会扫 .text 里所有 E8 rel32 指向该 RVA 的调用点，并列出调用现场。
"""
import argparse
import re
import sys

import numpy as np
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)


def load(exe):
    data = open(exe, 'rb').read()
    pe = pefile.PE(exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    return data, pe, base


def sect_of(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def annotate(ins, base):
    tag = ''
    m = re.search(r'\[rip ([+-]) (0x[0-9a-f]+)\]', ins.op_str)
    if m:
        d = int(m.group(2), 16) * (1 if m.group(1) == '+' else -1)
        va = ins.address + ins.size + d
        tag = f'   -> VA 0x{va:X} (RVA 0x{va - base:X})'
    if ins.mnemonic == 'movabs':
        tag += '   <<< imm64'
    return tag


def dump(exe, rva, n, back=0):
    data, pe, base = load(exe)
    s = sect_of(pe, rva)
    if s is None:
        print(f'  RVA 0x{rva:X} 不在任何段内')
        return
    nm = s.Name.rstrip(b'\x00').decode('latin1')
    off = s.PointerToRawData + (rva - s.VirtualAddress) - back
    start = base + rva - back
    print(f'\n########## {exe.split(chr(92))[-1]}  RVA 0x{rva:X}  (VA 0x{base + rva:X})  段 {nm} ##########')
    k = 0
    for ins in md.disasm(data[off:off + n * 8], start):
        print(f'   0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{annotate(ins, base)}')
        k += 1
        if k >= n:
            break


def find_call(exe, rva, context=0x90):
    data, pe, base = load(exe)
    s = [x for x in pe.sections if x.Name.rstrip(b'\x00') == b'.text'][0]
    ro, sva, rsz = s.PointerToRawData, s.VirtualAddress, s.SizeOfRawData
    blob = np.frombuffer(data[ro:ro + rsz], dtype=np.uint8)
    target = base + rva
    w = np.lib.stride_tricks.sliding_window_view(blob, 5)
    hits = []
    for i in np.flatnonzero(w[:, 0] == 0xE8):
        i = int(i)
        rel = int(np.frombuffer(blob[i + 1:i + 5], dtype='<i4')[0])
        if base + sva + i + 5 + rel == target:
            hits.append(base + sva + i)
    print(f'\n########## {exe.split(chr(92))[-1]}  call RVA 0x{rva:X} 调用点 ×{len(hits)} ##########')
    for h in hits[:8]:
        off = ro + (h - base - sva) - context
        print(f'\n  ◆ 调用点 0x{h:X}')
        for ins in md.disasm(data[off:off + context + 0x10], h - context):
            mark = '   <<< call target' if ins.address == h else ''
            print(f'     0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{annotate(ins, base)}{mark}')
    # 顺带看看这个 RVA 是否作为 8/4 字节指针出现在数据段
    pat8 = rva.to_bytes(8, 'little')
    pata8 = (base + rva).to_bytes(8, 'little')
    for sec in pe.sections:
        seg = data[sec.PointerToRawData:sec.PointerToRawData + sec.SizeOfRawData]
        c1 = seg.count(pat8)
        c2 = seg.count(pata8)
        if c1 or c2:
            sn = sec.Name.rstrip(b'\x00').decode('latin1')
            print(f'   数据段 {sn}: RVA字面 ×{c1}  VA字面 ×{c2}')
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--exe', required=True)
    ap.add_argument('--rva', default='')
    ap.add_argument('--len', type=int, default=30)
    ap.add_argument('--back', type=int, default=0)
    ap.add_argument('--find-call', default='')
    a = ap.parse_args()
    if a.rva:
        for tok in a.rva.split(','):
            dump(a.exe, int(tok, 16), a.len, a.back)
    if a.find_call:
        for tok in a.find_call.split(','):
            find_call(a.exe, int(tok, 16))


if __name__ == '__main__':
    sys.exit(main())
