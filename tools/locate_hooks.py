#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_gi71_hooks.py — 原神 7.1 双服：CriMana.Player 视频密钥相关方法的 RVA 定位。

方法：
  1. methodPointer 表基址 = (已知函数 VA 的存放偏移) − (该函数的全局方法索引)×8
     索引来自对 7.0 dump70.cs 的锚点推断；to_int32 的索引在 7.0/7.1 都是 1357（未平移）。
  2. 由此可直接按索引读表，得到 RVA。
"""
from __future__ import annotations

import argparse
import struct as st

import numpy as np
import pefile

SERVERS = {
    'cn': dict(exe=r'E:\github\genshin-7.1-cn-client\YuanShen.exe',
               to_int32=0x195DF330, to_int32_idx=1357),
    'gl': dict(exe=r'E:\github\genshin-7.1-global-client\GenshinImpact.exe',
               to_int32=0x1952CC20, to_int32_idx=1357),
}

# 7.1 CriMana.Player 新增方法的索引（由 7.0↔7.1 指纹序列对齐得到）
TARGETS = [
    (75719, 'SetVideoAudioDecryptionKeys(提钥匙, 托管层)'),
    (75721, 'SetVideoAesKeyAudioDecryptionKey(提钥匙, 托管层)'),
    (75762, 'NativeMethods_SetVideoAudioDecryptionKeys → CRIWARE948D1068'),
    (75763, 'NativeMethods_SetVideoAesKeyAudioDecryptionKey2 → CRIWARE1E4885A8'),
    (75786, '新增#5 ?'),
    (75787, '新增#6 ?'),
    (75745, 'NativeMethods_SetFile（文件名, 参照）'),
    (75746, 'NativeMethods_EntryFile（参照）'),
    (75712, 'SetFile（参照）'),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--server', default='cn')
    ap.add_argument('--window', type=lambda x: int(x, 0), default=0x400,
                    help='在已知偏移附近再搜窗口（容错索引平移）')
    a = ap.parse_args()
    cfg = SERVERS[a.server]
    exe = cfg['exe']
    data = open(exe, 'rb').read()
    pe = pefile.PE(exe, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress, s.Misc_VirtualSize,
             s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]

    def rva2off(rva):
        for nm, sva, vsz, rsz, ro in secs:
            if sva <= rva < sva + max(vsz, rsz):
                return ro + (rva - sva), nm
        return None, None

    va = base + cfg['to_int32']
    pat = va.to_bytes(8, 'little')
    occ = [i for i in range(len(data)) if False]
    o = data.find(pat)
    offs = []
    while o >= 0:
        offs.append(o)
        o = data.find(pat, o + 1)
    print(f'{a.server}: to_int32 RVA 0x{cfg["to_int32"]:X} 指针出现 {len(offs)} 次: '
          f'{[hex(x) for x in offs]}')
    if not offs:
        return 1
    tbl = offs[0] - cfg['to_int32_idx'] * 8
    trva, _ = rva2off(tbl)
    print(f'  → methodPointer 表基址 文件 0x{tbl:X}  RVA 0x{trva:X}\n')

    n = max(i for i, _ in TARGETS) + 8
    q = np.frombuffer(data, dtype='<u8', count=n, offset=tbl)
    print(f'{"idx":>7}  {"RVA":>12}   (段)   说明')
    for i, desc in TARGETS:
        v = int(q[i]) - base
        r, sn = rva2off(v)
        print(f'{i:>7}  0x{v:08X}   {sn or "?":<8} {desc}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
