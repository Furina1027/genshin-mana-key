#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""read_str.py — 读 exe 里某个 RVA 处的 C 字符串（P/Invoke 的模块名 / 入口名）。

修掉的老问题：
  · ``--len`` 默认 0 却被 ``a.len or 96`` 悄悄当成 96 → 现在默认就是 96 且必须 > 0；
  · 字符串比 --len 长时**静默截断** → 现在会继续扫到 ``--scan-max``（默认 4096），
    找到结尾 NUL 就打印完整内容并明确标注「--len 不够，已自动扩展」；
  · 解码失败与成功打印形态一样（都是 repr）→ 现在成功打 ``[UTF-8] "..."``，
    失败打 ``[UTF-8 解码失败] <repr>``，并额外给 latin1 可读形式；
  · 单个 RVA 读不到时不再返回 0。

用法：
  python read_str.py --exe <exe> --rva 0x123456 --rva 0x234567 [--len 96] [--json]

退出码：0=全部成功；1=有 RVA 无法定位/读取；2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import sys

import pe_utils

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_PARAM = 2

DEFAULT_LEN = 96
DEFAULT_SCAN_MAX = 4096


def read_one(pe: pe_utils.PEFile, rva: int, length: int, scan_max: int) -> dict:
    """读取 RVA 处的 C 字符串。返回结构化结果（error 字段表示硬失败）。"""
    item = dict(rva=rva, offset=None, section=None, text=None, nbytes=None,
                encoding=None, truncated=False, extended=False, error=None,
                decode_error=None, note=None, latin1=None, bytes_hex=None)
    try:
        sec = pe.section_of_rva(rva)
        off = pe.rva_to_off(rva)
    except pe_utils.RvaError as exc:
        item['error'] = str(exc)
        return item
    item['offset'] = off
    item['section'] = sec.name

    avail = sec.raw_end - off
    want = min(length, avail)
    raw = pe.data[off:off + want]
    idx = raw.find(b'\x00')
    if idx < 0:
        # ★ 在 --len 内没有结尾 NUL：要么字符串更长（旧实现直接截断），要么根本没有 NUL
        limit = min(max(scan_max, length), avail)
        raw2 = pe.data[off:off + limit]
        idx2 = raw2.find(b'\x00')
        if idx2 < 0:
            s = raw2
            item['truncated'] = True
            item['extended'] = True
            item['note'] = (f'在 --len {length} 与 --scan-max {scan_max} 范围内都没有结尾 NUL'
                            f'（已读 {len(raw2)} B）')
        else:
            s = raw2[:idx2]
            item['extended'] = True
            item['note'] = f'--len {length} 不够，已自动扩展：实际长度 {idx2} B'
    else:
        s = raw[:idx]
        if idx == want and want < avail:
            item['truncated'] = True
            item['note'] = f'--len {length} 处仍是字符串内容（可能被截断）'

    item['nbytes'] = len(s)
    try:
        item['text'] = s.decode('utf-8')
        item['encoding'] = 'utf-8'
    except UnicodeDecodeError as exc:
        item['encoding'] = None
        item['decode_error'] = f'UTF-8 解码失败：{exc}'
        item['latin1'] = s.decode('latin1')
        item['bytes_hex'] = s[:64].hex()
    return item


def main() -> int:
    ap = argparse.ArgumentParser(description='读 exe 里 RVA 处的 C 字符串（模块名/入口名）')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--rva', action='append', required=True, help='RVA，可重复')
    ap.add_argument('--len', type=int, default=DEFAULT_LEN,
                    help=f'最多读多少字节找结尾 NUL（默认 {DEFAULT_LEN}，必须 > 0）')
    ap.add_argument('--scan-max', type=int, default=DEFAULT_SCAN_MAX,
                    help=f'--len 内没找到 NUL 时继续扫到多少字节（默认 {DEFAULT_SCAN_MAX}）')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.len <= 0:
        print(f'错误：--len 必须 > 0（收到 {a.len}；旧实现把 0 悄悄当成 96）', file=sys.stderr)
        return EXIT_PARAM
    if a.scan_max < a.len:
        print(f'错误：--scan-max 不能小于 --len（{a.scan_max} < {a.len}）', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    items = []
    bad = 0
    for tok in a.rva:
        try:
            rva = pe_utils.parse_int(tok)
        except ValueError as exc:
            print(f'错误：{exc}', file=sys.stderr)
            return EXIT_PARAM
        item = read_one(pe, rva, a.len, a.scan_max)
        items.append(item)
        if item['error'] or item['decode_error'] or item['truncated']:
            bad += 1

    if a.json:
        pe_utils.emit_json(dict(exe=a.exe, image_base=pe.image_base, items=items))
    else:
        for it in items:
            head = f'RVA 0x{it["rva"]:X}'
            if it['offset'] is not None:
                head += f'  文件 0x{it["offset"]:X}  段 {it["section"]}'
            if it['error']:
                print(f'{head}\n    ✗ {it["error"]}')
                continue
            if it['encoding'] == 'utf-8':
                print(f'{head}\n    [UTF-8] {it["text"]!r}  (字节长度 {it["nbytes"]})')
            else:
                print(f'{head}\n    [UTF-8 解码失败] {it.get("bytes_hex")}'
                      f'  可读(latin1): {it.get("latin1")!r}')
                print(f'    ⚠ {it["decode_error"]}')
            if it.get('note'):
                print(f'    ⚠ {it["note"]}')
    return EXIT_FAIL if bad else EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
