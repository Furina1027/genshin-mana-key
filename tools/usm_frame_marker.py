#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_usm_frame_marker.py — 用 VP9/H.264 的「帧起始标记」统计判定视频流是否被加密。

原理：
  · 明文 VP9 帧首字节低 2 位 = 0b10（frame marker），超级帧则为 (b0 & 0xE0) == 0xC0
  · 明文 H.264 帧首几乎必然是 00 00 00 01 / 00 00 01 起始码
  · 加密后 → 低 2 位应是 25/25/25/25 均匀分布，起始码基本消失

用法: python gia_usm_frame_marker.py --file <usm>
"""
from __future__ import annotations

import argparse
import collections


def parse_chunks(buf, limit=None):
    """产出 (pos, chno, dataType, dataStart, dataLen)。USM 头：size@+4, dataOffset@+9, padding@+10, chno@+12, type@+15"""
    pos = 0
    n = len(buf)
    got = 0
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
            yield (pos, chno, dtype, dstart, dlen)
            got += 1
            if limit and got >= limit:
                return
        pos += size + 8


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', required=True)
    ap.add_argument('--sample', type=int, default=400)
    a = ap.parse_args()

    buf = open(a.file, 'rb').read()
    media = [(p, c, d, s, l) for p, c, d, s, l in parse_chunks(buf) if d == 0 and l >= 0x40]
    print(f'{a.file}\n媒体块(类型0) {len(media)} 个')

    step = max(1, len(media) // a.sample)
    picked = media[::step][:a.sample]
    low2 = collections.Counter()
    startcode = 0
    vp9_super = 0
    heads = []
    for p, c, d, s, l in picked:
        b0 = buf[s]
        low2[b0 & 3] += 1
        blob = buf[s:s + 0x200]
        if blob[:3] == b'\x00\x00\x01' or blob[:4] == b'\x00\x00\x00\x01':
            startcode += 1
        if (b0 & 0xE0) == 0xC0:
            vp9_super += 1
        if len(heads) < 6:
            heads.append((p, c, l, buf[s:s + 16].hex()))

    total = len(picked)
    print(f'抽样 {total} 块：')
    print(f'  低2位分布: ' + '  '.join(f'{k}:{low2[k]}({low2[k]/total*100:.1f}%)' for k in range(4)))
    print(f'  H.264 起始码开头: {startcode} ({startcode/total*100:.1f}%)')
    print(f'  VP9 超级帧标记(b0&0xE0==0xC0): {vp9_super} ({vp9_super/total*100:.1f}%)')
    print('\n  样例块头:')
    for p, c, l, h in heads:
        print(f'    chunk@{p} ch={c} len={l}  {h}')
    print("""
判读：
  · 低2位以 2 为主(≈100%)、或起始码占比高 → 视频流是**明文**（无需密钥）
  · 低2位四值各 ≈25%、起始码 ≈0      → 视频流**已加密**（需要密钥）
""")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
