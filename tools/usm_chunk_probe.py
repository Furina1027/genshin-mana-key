#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usm_chunk_probe.py — 直接看 USM 各流首块的字节形态，判断视频流是否真被加密。

判据：
  · 明文 H.264/VP9 会在 chunk 开头就出现 NAL 起始码（00 00 00 01 / 00 00 01）
  · 加密（AES-CTR / XOR 掩码）后字节近似均匀随机，起始码密度极低、且首字节无结构

解析与统计全部走 `usm.py`（不再自带一份 parse_chunks 副本）。

用法：
  python usm_chunk_probe.py --file <usm> [--show 4] [--json]

退出码：0=正常；2=参数/IO 错误；4=容器结构畸形（UsmFormatError）。
"""
from __future__ import annotations

import argparse
import collections
import os
import sys

import pe_utils
import usm

EXIT_OK = 0
EXIT_PARAM = 2
EXIT_FORMAT = 4


def probe(buf: bytes, show: int) -> dict:
    chunks = usm.parse_chunks(buf)
    by_key = collections.Counter()
    by_typ = collections.Counter()
    for c in chunks:
        by_typ[c.typ_str] += 1
        by_key[f'{c.typ_str}:ch{c.chno}:dt{c.dt}'] += 1

    blocks = []
    for want_dt in (0, 1, 2, 3):
        sel = [c for c in chunks if c.dt == want_dt and c.dl > 0x20]
        if not sel:
            continue
        for c in sel[:show]:
            payload = c.payload(buf)
            blk = payload[:0x2000]
            blocks.append(dict(
                type=c.typ_str, pos=c.pos, chno=c.chno, dt=c.dt, frame_time=c.frame_time,
                length=c.dl, start32=blk[:32].hex(),
                start_codes=usm.count_start_codes(blk),
                entropy=round(usm.entropy(blk[:0x1000]), 3),
                starts_with_code=usm.starts_with_start_code(blk),
            ))
    return dict(
        chunks=len(chunks),
        total_heads=chunks.total,
        skipped_empty=chunks.skipped_empty,
        tail_offset=chunks.tail_offset,
        malformed=[{'offset': p, 'reason': r} for p, r in chunks.malformed],
        by_type=dict(by_typ),
        by_type_channel_dt=dict(by_key),
        blocks=blocks,
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description='USM 各流首块字节形态抽查（判定视频流是否加密）')
    ap.add_argument('--file', required=True, help='USM 文件')
    ap.add_argument('--show', type=int, default=4, help='每种 dataType 打印几个块（默认 4）')
    ap.add_argument('--json', action='store_true', help='以 JSON 输出')
    a = ap.parse_args()

    if a.show < 1:
        print('错误：--show 必须 >= 1', file=sys.stderr)
        return EXIT_PARAM
    try:
        with open(a.file, 'rb') as fh:
            buf = fh.read()
    except OSError as exc:
        print(f'错误：无法读取 {a.file}：{exc}', file=sys.stderr)
        return EXIT_PARAM

    try:
        info = probe(buf, a.show)
    except usm.UsmFormatError as exc:
        print(f'错误：USM 容器结构畸形：{exc}', file=sys.stderr)
        return EXIT_FORMAT

    info['file'] = os.path.abspath(a.file)
    info['size'] = len(buf)
    if a.json:
        pe_utils.emit_json(info)
        return EXIT_OK

    print(f'{a.file}   {len(buf):,} B')
    print(f'chunk 数: {info["chunks"]}（头部总数 {info["total_heads"]}，'
          f'空块 {info["skipped_empty"]}，尾部起点 0x{info["tail_offset"]:X}）')
    for off, reason in info['malformed']:
        print(f'  ⚠ 畸形块 @0x{off:X}：{reason}')
    print('按类型统计:', info['by_type'])
    print('按 (类型, 通道, dataType) 统计:')
    for k in sorted(info['by_type_channel_dt']):
        print(f'   {k}: {info["by_type_channel_dt"][k]}')
    print('  dataType 说明: 0=数据 1=流头 2=#HEADER END 3=元数据（字段 & 3）')
    print('  ★ 判流必须用类型（@SFV/@SFA）：视频与音频的 chno 会撞号')
    for blk in info['blocks']:
        print(f'\n  [{blk["type"]} ch={blk["chno"]} dt={blk["dt"]} ft={blk["frame_time"]}] '
              f'chunk@{blk["pos"]} len={blk["length"]}')
        print(f'        首 32B: {blk["start32"]}')
        print(f'        2KB 内起始码 {blk["start_codes"]} 处   熵 {blk["entropy"]:.3f} / 8.0')
    if not info['blocks']:
        print('\n（没有任何 dt 类型存在 >0x20 的载荷块 —— 文件可能只有流头/元数据）')
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
