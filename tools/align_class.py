#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_align_class.py — 把 7.0 某个类的每个方法与 7.1 同名方法做「掩码指纹」一一对齐，
从而找出 7.1 新增（7.0 无对应）的方法。

用法：
  python gia_align_class.py --class CriWare.CriMana.Player \
      --idx70 83127:83230 --idx71 75679:75790 [--base71 0x2870C78]
"""
from __future__ import annotations

import argparse
import re
import struct as st

import numpy as np
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

EXE70 = r'E:\米家游戏\切换器\米家三合一切换器\资源替换包\原神\原神国际服\GenshinImpact.exe'
EXE71 = r'E:\github\genshin-7.1-cn-client\YuanShen.exe'
DUMP70 = r'E:\github\test\gi_il2cpp\dump70\dump70.cs'


def parse_class(path, cls):
    out = []
    inside = False
    for line in open(path, encoding='utf-8', errors='replace'):
        s = line.rstrip('\n')
        if s.startswith('// TypeDefIndex'):
            inside = False
        elif s.startswith('class '):
            inside = (s.strip() == 'class ' + cls)
        elif inside:
            m = re.match(r'\s*([^;]+); // idx (\d+)\s+RVA 0x([0-9a-fA-F]+)', s)
            if m:
                out.append((int(m.group(2)), m.group(1).strip(), int(m.group(3), 16)))
    return out


def sections(exe):
    pe = pefile.PE(exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
             s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]
    return open(exe, 'rb').read(), base, secs


def rva2off(secs, rva):
    for nm, sva, vsz, rsz, ro in secs:
        if sva <= rva < sva + max(vsz, rsz):
            return ro + (rva - sva)
    return None


def fp(data, base, secs, rva, n=14):
    o = rva2off(secs, rva)
    if o is None:
        return None
    pat, msk = bytearray(), bytearray()
    k = 0
    for ins in md.disasm(data[o:o + 0x200], base + rva):
        b = ins.bytes
        m = bytearray(b'\x01' * len(b))
        if ins.imm_size:
            for j in range(ins.imm_size):
                m[ins.imm_offset + j] = 0
        if ins.disp_size:
            for j in range(ins.disp_size):
                m[ins.disp_offset + j] = 0
        pat += b
        msk += m
        k += 1
        if k >= n:
            break
    return bytes(pat), bytes(msk)


def sim(a, b):
    if a is None or b is None:
        return -1.0
    pa, ma = a
    pb, mb = b
    L = min(len(pa), len(pb))
    if L < 8:
        return -1.0
    both = 0
    eq = 0
    for i in range(L):
        if ma[i] and mb[i]:
            both += 1
            if pa[i] == pb[i]:
                eq += 1
    return eq / both if both else -1.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='cls', default='CriWare.CriMana.Player')
    ap.add_argument('--idx70', default='')
    ap.add_argument('--idx71', default='')
    ap.add_argument('--base71', default='0x2870C78')
    ap.add_argument('--thr', type=float, default=0.90)
    a = ap.parse_args()

    m70 = parse_class(DUMP70, a.cls)
    print(f'7.0 {a.cls}: {len(m70)} 个方法，idx {m70[0][0]}..{m70[-1][0]}')
    d70, b70, s70 = sections(EXE70)
    d71, b71, s71 = sections(EXE71)

    lo, hi = [int(x, 0) for x in (a.idx71.split(':') if a.idx71 else
                                  (str(m70[0][0] - 7448) + ':' + str(m70[-1][0] - 7446)).split(':'))]
    b = int(a.base71, 0)
    q = np.frombuffer(d71, dtype='<u8', count=hi + 4, offset=b)
    n71 = []
    for i in range(lo, hi + 1):
        v = int(q[i])
        if v == 0:
            continue
        n71.append((i, v - b71))
    print(f'7.1 idx {lo}..{hi}: {len(n71)} 个有效方法指针')

    F70 = {i: fp(d70, b70, s70, r) for i, _, r in m70}
    F71 = {i: fp(d71, b71, s71, r) for i, r in n71}

    used = set()
    pairs = []
    for i, r in n71:
        best, bi = -1.0, None
        for j, nm, rr in m70:
            if j in used:
                continue
            s = sim(F71[i], F70[j])
            if s > best:
                best, bi = s, j
        if best >= a.thr:
            used.add(bi)
            pairs.append((i, bi, best, r))
        else:
            pairs.append((i, None, best, r))

    name70 = {j: nm for j, nm, _ in m70}
    rva70 = {j: rr for j, _, rr in m70}
    print(f'\n{"7.1 idx":>9} {"RVA71":>12}  {"7.0 idx":>9} {"RVA70":>12}  相似度  名称')
    for i, bi, best, r in pairs:
        if bi is None:
            print(f'{i:>9} 0x{r:08X}  {"—":>9} {"—":>12}  {best:.2f}   ★★★ 7.1 新增')
        else:
            print(f'{i:>9} 0x{r:08X}  {bi:>9} 0x{rva70[bi]:08X}  {best:.2f}   {name70[bi]}')

    miss = [j for j, nm, rr in m70 if j not in used]
    print(f'\n7.0 未被匹配上的方法（{len(miss)} 个，可能是被删/改）:')
    for j in miss:
        print(f'   {j:>6}  {name70[j]}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
