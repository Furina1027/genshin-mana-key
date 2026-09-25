#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_usm_chunk_probe.py — 直接看 USM 各流首块的字节形态，判断视频流是否真被加密。

判据：
  · 明文 H.264/VP9 会在 chunk 开头就出现 NAL 起始码（00 00 00 01 / 00 00 01）
  · 加密（AES-CTR / XOR 掩码）后字节近似均匀随机，起始码密度极低、且首字节无结构
"""
from __future__ import annotations

import argparse
import collections
import math


def parse_chunks(buf):
    out = []
    pos = 0
    n = len(buf)
    while pos + 24 <= n:
        size = int.from_bytes(buf[pos + 4:pos + 8], 'big')
        if size == 0 or pos + size + 8 > n:
            break
        data_off = buf[pos + 9]
        padding = int.from_bytes(buf[pos + 10:pos + 12], 'big')
        chno = buf[pos + 12]
        dtype = buf[pos + 15] & 3
        dstart = pos + 8 + data_off
        dlen = size - data_off - padding
        if dlen > 0:
            out.append((pos, chno, dtype, dstart, dlen))
        pos += size + 8
    return out


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', required=True)
    ap.add_argument('--show', type=int, default=4)
    a = ap.parse_args()

    buf = open(a.file, 'rb').read()
    print(f'{a.file}   {len(buf):,} B')
    ch = parse_chunks(buf)
    print(f'chunk 数: {len(ch)}')
    by = collections.Counter()
    for _, chno, dt, ds, dl in ch:
        by[(chno, dt)] += 1
    print('按 (通道, 类型) 统计:', dict(by))
    print('  类型: 0=?,1=video?,2=audio?,3=?  (dataType = 字段 & 3)')

    for want_dt in (0, 1, 2, 3):
        sel = [(p, c, d, s, l) for p, c, d, s, l in ch if d == want_dt and l > 0x20]
        if not sel:
            continue
        print(f'\n===== 类型 {want_dt}：共 {len(sel)} 块，看前 {a.show} 块 =====')
        for p, c, d, s, l in sel[:a.show]:
            blk = buf[s:s + 0x2000]
            # NAL 起始码出现次数
            sc = blk.count(b'\x00\x00\x00\x01') + blk.count(b'\x00\x00\x01')
            print(f'  chunk@{p} ch={c} len={l}  首 32B: {blk[:32].hex()}')
            print(f'        2KB 内起始码 {sc} 处   熵 {entropy(blk[:0x1000]):.3f} / 8.0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
