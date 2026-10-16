#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""usm_frame_marker.py — 统计 USM 视频块的「帧起始标记」，判定视频流是否被加密。

判据（**必须理解 method2 的明文前缀**，否则判读会反）：
  · 7.1 的加密区是每个 chunk 的 payload[0x40:]，也就是说每个视频块**前 0x40 字节永远是
    明文**（首个块还含 32 字节 IVF 头 + 12 字节帧条目，其余块含 12 字节帧条目）。
    因此「帧首字节像明文（VP9 帧标记 / 49 83 42 同步码 / H.264 起始码）」**不能**证明未加密
    —— 明文和密文样本在这一段完全一样。
  · 真正的判据在**加密区**（payload[0x40:] 起）：
      - 明文流 → 视频压缩数据里仍会周期性出现起始码 00 00 01 / 同步码 49 83 42；
      - AES-CTR 密文 → 起始码/同步码基本消失，且首字节低 2 位四值均匀（各 ≈25%）。

旧实现的三个问题（C3）：
  1. 只筛 ``dt == 0 and len >= 0x40``，没有筛 ``typ == '@SFV'``，把 @SFA 音频（HCA、高熵）
     混进「媒体块」——而 chno 在音视频之间会撞号，判读被污染；
  2. 媒体块为 0 时 ``total = 0`` 直接 ZeroDivisionError；
  3. 起始码只看前 3/4 字节，比 usm_chunk_probe 的扫描弱，且判据没有落在加密区上。

输出一个明确的 verdict（明文 / 已加密 / 样本不足）并据此设置退出码：
  0 = 明文（无需密钥）；1 = 已加密（需要密钥）；2 = 样本不足 / 畸形 / 参数错误。

用法: python usm_frame_marker.py --file <usm> [--sample 400] [--json]
"""
from __future__ import annotations

import argparse
import collections
import math
import os
import sys

import pe_utils
import usm

VERDICT_PLAIN = '明文'
VERDICT_ENCRYPTED = '已加密'
VERDICT_UNSURE = '样本不足'

EXIT_PLAIN = 0
EXIT_ENCRYPTED = 1
EXIT_UNSURE = 2

#: Genshin 明文 VP9 帧首的同步码（README「首轮实测」一节记录）
SYNC_CODE = b'\x49\x83\x42'

#: 统计所需的最小样本数（低于此值不下结论）
MIN_SAMPLES = 32

#: 加密区取样窗口
BODY_WINDOW = 0x2000


def _collect_entries(buf, chunks, summary: dict):
    """产出 (chunk, IvfEntry, payload)，只保留帧数据 >= 0x40 的条目。"""
    out = []
    vchunks = usm.video_chunks(chunks, data_only=True)
    warn = []
    for i, c in enumerate(vchunks):
        payload = c.payload(buf)
        for e in usm.iter_ivf_entries(payload, first=(i == 0), warnings=warn):
            if e.data_len >= 0x40:
                out.append((c, e, payload))
    summary['warnings'] = list(dict.fromkeys(warn))
    return out


def analyze(buf: bytes, sample: int) -> dict:
    chunks = usm.parse_chunks(buf)
    info = dict(
        chunks=len(chunks),
        video_data_chunks=len(usm.video_chunks(chunks, data_only=True)),
        audio_data_chunks=len(usm.audio_chunks(chunks, data_only=True)),
        total_heads=chunks.total,
        skipped_empty=chunks.skipped_empty,
        tail_offset=chunks.tail_offset,
        malformed=[{'offset': p, 'reason': r} for p, r in chunks.malformed],
    )
    entries = _collect_entries(buf, chunks, info)
    info['media_entries'] = len(entries)
    if not entries:
        info.update(verdict=VERDICT_UNSURE, sampled=0,
                    reason='没有可用的 @SFV 视频帧条目（没有视频数据块，或帧数据都 < 0x40 字节）')
        return info

    step = max(1, len(entries) // max(1, sample))
    picked = entries[::step][:sample]

    low2_head = collections.Counter()      # 帧首（明文前缀内）
    low2_body = collections.Counter()      # 加密区首字节
    head_struct = 0                        # 帧首是 起始码/同步码
    body_struct = 0                        # 加密区里还能找到 起始码/同步码
    body_entropy = []
    samples = []
    for c, e, payload in picked:
        fs_off = e.data_off
        body_off = max(usm.ENCRYPTED_PLAIN_PREFIX, e.data_off)
        body_end = min(e.data_off + e.data_len, len(payload))
        head_blob = payload[fs_off:min(body_off, body_end)] or payload[fs_off:fs_off + 4]
        body_blob = payload[body_off:min(body_end, body_off + BODY_WINDOW)]

        low2_head[payload[fs_off] & 3] += 1
        if usm.starts_with_start_code(payload[fs_off:]) or head_blob[:3] == SYNC_CODE:
            head_struct += 1
        if body_blob:
            low2_body[body_blob[0] & 3] += 1
            if usm.count_start_codes(body_blob) or SYNC_CODE in body_blob:
                body_struct += 1
            body_entropy.append(usm.entropy(body_blob[:0x1000]))
        if len(samples) < 6:
            samples.append(dict(
                chunk_pos=c.pos, chno=c.chno, frame_time=e.ts, entry_index=e.index,
                frame_len=e.data_len, plain_prefix=body_off - e.data_off,
                head16=payload[fs_off:fs_off + 16].hex(),
                body32_off=body_off,
                body32=body_blob[:32].hex()))

    total = len(picked)
    hr = {k: low2_head[k] / total for k in range(4)}
    br = {k: low2_body[k] / total for k in range(4)}
    head_ratio = head_struct / total
    body_ratio = body_struct / total

    info.update(
        sampled=total,
        frame_head_low2={str(k): low2_head[k] for k in range(4)},
        frame_head_low2_ratio={str(k): round(hr[k], 4) for k in range(4)},
        frame_head_structured=head_struct,
        frame_head_structured_ratio=round(head_ratio, 4),
        body_low2={str(k): low2_body[k] for k in range(4)},
        body_low2_ratio={str(k): round(br[k], 4) for k in range(4)},
        body_structured=body_struct,
        body_structured_ratio=round(body_ratio, 4),
        body_mean_entropy=round(sum(body_entropy) / len(body_entropy), 3) if body_entropy else None,
        samples=samples,
    )

    # 低 2 位是否「四值均匀」：容差随样本量放大（3.5σ，σ = sqrt(p(1-p)/n)），
    # 否则小样本会被随机波动误判成「已加密」。
    tol = max(0.08, 3.5 * math.sqrt(0.25 * 0.75 / total))
    body_uniform = all(abs(br[k] - 0.25) <= tol for k in range(4))
    info['body_low2_tolerance'] = round(tol, 4)
    info['body_low2_uniform'] = body_uniform

    if total < MIN_SAMPLES:
        info.update(verdict=VERDICT_UNSURE,
                    reason=f'有效样本只有 {total} 个（< {MIN_SAMPLES}），统计量没有意义')
    elif body_ratio >= 0.5:
        info.update(verdict=VERDICT_PLAIN,
                    reason=f'加密区（payload[0x40:] 起 {BODY_WINDOW:#x} B）里 '
                           f'{body_ratio:.1%} 的块能找到起始码/同步码 → 视频体是明文的')
    elif body_ratio <= 0.02 and body_uniform:
        info.update(verdict=VERDICT_ENCRYPTED,
                    reason=f'加密区起始码/同步码近乎消失（{body_ratio:.1%}），'
                           f'且首字节低 2 位四值各≈25%（容差 ±{tol:.1%}）→ AES-CTR 密文特征')
    else:
        info.update(verdict=VERDICT_UNSURE,
                    reason=f'统计特征不典型（加密区结构化 {body_ratio:.1%}，'
                           f'低2位最大占比 {max(br.values()):.1%}，均匀={body_uniform}）')
    return info


def main() -> int:
    ap = argparse.ArgumentParser(
        description='判定 USM 视频流是否被加密（只看 @SFV 视频数据块的加密区）')
    ap.add_argument('--file', required=True)
    ap.add_argument('--sample', type=int, default=400, help='最多抽样多少个视频帧条目（默认 400）')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.sample < 1:
        print('错误：--sample 必须 >= 1', file=sys.stderr)
        return EXIT_UNSURE
    try:
        with open(a.file, 'rb') as fh:
            buf = fh.read()
    except OSError as exc:
        print(f'错误：无法读取 {a.file}：{exc}', file=sys.stderr)
        return EXIT_UNSURE
    try:
        info = analyze(buf, a.sample)
    except usm.UsmFormatError as exc:
        print(f'错误：USM 容器结构畸形：{exc}', file=sys.stderr)
        return EXIT_UNSURE

    info['file'] = os.path.abspath(a.file)
    info['size'] = len(buf)
    if a.json:
        pe_utils.emit_json(info)
    else:
        print(f'{a.file}\n'
              f'chunk {info["chunks"]}（视频数据 {info["video_data_chunks"]} / '
              f'音频数据 {info["audio_data_chunks"]}），视频帧条目 {info["media_entries"]} 个')
        for off, reason in info['malformed']:
            print(f'  ⚠ 畸形块 @0x{off:X}：{reason}')
        for w in info.get('warnings', []):
            print(f'  ⚠ {w}')
        if info['media_entries'] == 0:
            print(f'\n判读：★★ {info["verdict"]} ★★ —— {info["reason"]}')
            return EXIT_UNSURE
        print(f'抽样 {info["sampled"]} 个 @SFV 帧条目：')
        print('  帧首(明文前缀内)低2位: ' + '  '.join(
            f'{k}:{info["frame_head_low2"][str(k)]}'
            f'({info["frame_head_low2_ratio"][str(k)] * 100:.1f}%)' for k in range(4)))
        print(f'  帧首带起始码/49 83 42 同步码: {info["frame_head_structured"]} '
              f'({info["frame_head_structured_ratio"] * 100:.1f}%)  ← 明文前缀，两种情况下都一样')
        print('  加密区(payload[0x40:])首字节低2位: ' + '  '.join(
            f'{k}:{info["body_low2"][str(k)]}'
            f'({info["body_low2_ratio"][str(k)] * 100:.1f}%)' for k in range(4)))
        print(f'  加密区内仍能找到起始码/同步码: {info["body_structured"]} '
              f'({info["body_structured_ratio"] * 100:.1f}%)'
              + (f'   平均熵 {info["body_mean_entropy"]:.3f}/8.0'
                 if info['body_mean_entropy'] is not None else ''))
        print('\n  样例条目:')
        for s in info['samples']:
            print(f'    chunk@{s["chunk_pos"]} ch={s["chno"]} ft={s["frame_time"]} '
                  f'len={s["frame_len"]} 明文前缀={s["plain_prefix"]}B')
            print(f'      帧首 16B : {s["head16"]}')
            print(f'      加密区 32B: {s["body32"]}')
        print(f'\n判读：★★ {info["verdict"]} ★★ —— {info["reason"]}')
        print("""
说明：
  · 判据落在**加密区**（payload[0x40:]）：明文视频体里仍有起始码/同步码，
    AES-CTR 密文则没有、且首字节低 2 位四值各≈25%；
  · 帧首永远在明文前缀里（method2 的设计），所以「帧首像明文」什么也证明不了；
  · 退出码：0=明文 1=已加密 2=样本不足/畸形""")

    return {VERDICT_PLAIN: EXIT_PLAIN,
            VERDICT_ENCRYPTED: EXIT_ENCRYPTED,
            VERDICT_UNSURE: EXIT_UNSURE}[info['verdict']]


if __name__ == '__main__':
    raise SystemExit(main())
