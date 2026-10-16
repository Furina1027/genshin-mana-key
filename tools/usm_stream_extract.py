#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usm_stream_extract.py — 原神 7.1 USM 容器解封装（视频→IVF/VP9，音频→HCA）

容器结构（本轮实测确认，Cs_ZD_AQ70201201_SLT.usm）：
  chunk header 24 字节：
    +0x00 char[4]  type    —— **@SFV = 视频流 / @SFA = 音频流**（判通道必须用这个！）
    +0x04 uint32   size    —— BE，从 pos+8 起算（块总长 = size + 8）
    +0x09 uint8    data_offset
    +0x0A uint16   padding —— BE
    +0x0C uint8    chno    —— 流内编号。**注意：视频和音频会撞号**（@SFV 的 chno=0
                              与 @SFA 的 chno=0 都存在），所以不能只用 chno 过滤
    +0x0F uint8    dataType —— &3: 0=数据 1=流头(@SFV/@SFA) 2=#HEADER END 3=元数据(@UTF)
    +0x10 uint32   frameTime —— BE
  payload = buf[pos + 8 + data_offset : ...], len = size - data_offset - padding

视频流（@SFV, dataType=0）：
  · 第一个块 payload = IVF 文件头(32, "DKIF"+VP90+w/h/frame_count) + [帧条目(12) + 帧数据]…
  · 其余块 payload = [帧条目(12) + 帧数据]…
  · 帧条目 = LE32 帧大小 + LE64 时间戳

加密状态（method2 / AES-128-CTR）：
  · 加密区是**每个 chunk 的 payload[0x40:]**：payload 前 0x40 字节是明文，之后是密文。
    第一个块 payload = IVF头(32)+条目(12)+数据 → 该块第 0 帧的帧数据明文前缀是
    0x40-32-12 = **0x14**；其余块 payload = 条目(12)+数据 → 前缀是 0x40-12 = **0x34**。
    旧实现对所有帧一律用 0x34，第 0 帧因此被用错 32 字节（2 个 AES 块）的计数器 →
    第 0 帧解坏。现在按 chunk/条目逐个算，与 usm_decrypt.mjs 的 payload[0x40:] 语义一致。
  · CTR counter = nonce(8B) || BE32(该 IVF 条目自己的 frameTime) || BE32(blockIndex)，
    16 字节大端递增；密钥流 = AES-128-ECB(counter)。
  · 长度 <= 0x40 的 payload 没有加密区（小帧整体明文）。

用法：
  python usm_stream_extract.py <file.usm> [-o OUTDIR] [--key HEX32] [--no-audio]
  python usm_stream_extract.py <file.usm> --info        # 只看结构
  python usm_stream_extract.py <file.usm> --key ... --json

退出码：0=成功；1=没有可抽取的流；2=参数/IO 错误；3=密钥/nonce 问题；
        4=容器结构畸形；5=缺少 pycryptodome/cryptography 依赖。
"""
from __future__ import annotations

import argparse
import os
import sys

import pe_utils
import usm

EXIT_OK = 0
EXIT_NOTHING = 1
EXIT_PARAM = 2
EXIT_KEY = 3
EXIT_FORMAT = 4
EXIT_DEP = 5


def build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='USM 解封装：视频→IVF/VP9，音频→HCA（可选 AES-128-CTR 解密）')
    ap.add_argument('usm', help='输入 .usm 文件')
    ap.add_argument('-o', '--out', default=None, help='输出目录（默认与输入文件同目录）')
    ap.add_argument('--key', default=None, help='32 位十六进制 AES-128 密钥')
    ap.add_argument('--info', action='store_true', help='只打印结构，不写文件')
    ap.add_argument('--no-audio', action='store_true', help='不导出音频')
    ap.add_argument('--allow-missing-nonce', action='store_true',
                    help='给了 --key 但文件里没有 nonce 时，明确输出**未解密**的 .ivf'
                         '（而不是报错退出）')
    ap.add_argument('--json', action='store_true', help='以 JSON 输出结果摘要')
    return ap


def main() -> int:
    a = build_argparser().parse_args()

    try:
        with open(a.usm, 'rb') as fh:
            buf = fh.read()
    except OSError as exc:
        print(f'错误：无法读取 {a.usm}：{exc}', file=sys.stderr)
        return EXIT_PARAM

    try:
        chunks = usm.parse_chunks(buf)
    except usm.UsmFormatError as exc:
        print(f'错误：USM 容器结构畸形：{exc}', file=sys.stderr)
        return EXIT_FORMAT

    nonce = usm.read_nonce(buf)
    key = None
    if a.key:
        try:
            key = usm.parse_key(a.key)
        except usm.UsmKeyError as exc:
            print(f'错误：--key 不合法：{exc}', file=sys.stderr)
            return EXIT_PARAM

    decrypt_key = key
    if key is not None and nonce is None:
        # ★ 旧实现这里照样输出 .dec.ivf 并打印「已解密」，等于骗人
        if not a.allow_missing_nonce:
            print('错误：文件里找不到 nonce（VIDEO_HDRINFO 标记），无法解密。\n'
                  '      要么确认这是 7.1 method2 加密样本，要么用 --allow-missing-nonce '
                  '明确要求输出未解密文件。', file=sys.stderr)
            return EXIT_KEY
        print('警告：--allow-missing-nonce 生效 —— 本次**不解密**，'
              '将输出未解密的 .ivf（文件名不带 .dec）', file=sys.stderr)
        decrypt_key = None

    name = os.path.splitext(os.path.basename(a.usm))[0]
    outdir = a.out or os.path.dirname(a.usm) or '.'

    try:
        res = usm.extract_video(buf, chunks, key=decrypt_key, nonce=nonce if decrypt_key else None)
    except usm.UsmKeyError as exc:
        print(f'错误：解密参数问题：{exc}', file=sys.stderr)
        return EXIT_KEY
    except usm.MissingDependency as exc:
        print(f'错误：{exc}', file=sys.stderr)
        return EXIT_DEP

    audio = {}
    if not a.no_audio:
        for c in usm.audio_chunks(chunks, data_only=True):
            audio.setdefault(c.chno, bytearray()).extend(c.payload(buf))
        audio = {k: bytes(v) for k, v in sorted(audio.items())}

    summary = dict(
        usm=os.path.abspath(a.usm), size=len(buf), chunks=len(chunks),
        video_chunks=res.chunks, frames=len(res.frames), entries=res.entries,
        video_data_chunks=len(usm.video_chunks(chunks, data_only=True)),
        audio_data_chunks=len(usm.audio_chunks(chunks, data_only=True)),
        audio_tracks={str(k): len(v) for k, v in audio.items()},
        nonce=nonce.hex() if nonce else None,
        key_provided=key is not None,
        decrypted=res.decrypted_bytes > 0,
        decrypted_bytes=res.decrypted_bytes,
        warnings=list(res.warnings),
        skipped_empty=chunks.skipped_empty, tail_offset=chunks.tail_offset,
        outputs=[],
    )
    if res.ivf_header:
        summary['ivf'] = dict(
            width=int.from_bytes(res.ivf_header[12:14], 'little'),
            height=int.from_bytes(res.ivf_header[14:16], 'little'),
            frame_count=int.from_bytes(res.ivf_header[24:28], 'little'))

    if not a.json:
        print('文件   : %s  (%.1f MB)' % (a.usm, len(buf) / 1048576))
        print('chunk  : %d（视频数据 %d / 音频数据 %d / 空块 %d）' % (
            len(chunks), summary['video_data_chunks'], summary['audio_data_chunks'],
            chunks.skipped_empty))
        print('nonce  : %s' % (nonce.hex() if nonce else '(无)'))
        print('视频帧 : %d（条目 %d）' % (len(res.frames), res.entries))
        print('音频轨 : %s' % ({k: len(v) for k, v in audio.items()} or '(无)'))
        for w in res.warnings:
            print('  ⚠ %s' % w)

    if a.info:
        if 'ivf' in summary and not a.json:
            v = summary['ivf']
            print('IVF    : %dx%d  frame_count=%d' % (v['width'], v['height'], v['frame_count']))
        if a.json:
            pe_utils.emit_json(summary)
        return EXIT_OK

    if not res.frames and not audio:
        print('错误：既没有 @SFV 视频帧也没有 @SFA 音频数据，没有可抽取的流', file=sys.stderr)
        if a.json:
            pe_utils.emit_json(summary)
        return EXIT_NOTHING

    try:
        os.makedirs(outdir, exist_ok=True)
    except OSError as exc:
        print(f'错误：无法创建输出目录 {outdir}：{exc}', file=sys.stderr)
        return EXIT_PARAM

    if res.frames and res.ivf_header:
        # ★ 只有真的解密过才允许叫 .dec.ivf
        decrypted = res.decrypted_bytes > 0
        body = bytearray()
        for ts, data in res.frames:
            body += len(data).to_bytes(4, 'little') + (ts & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little') + data
        path = os.path.join(outdir, name + ('.dec.ivf' if decrypted else '.ivf'))
        try:
            with open(path, 'wb') as fh:
                fh.write(res.ivf_header + bytes(body))
        except OSError as exc:
            print(f'错误：写 {path} 失败：{exc}', file=sys.stderr)
            return EXIT_PARAM
        summary['outputs'].append(dict(path=os.path.abspath(path), kind='ivf',
                                       bytes=len(res.ivf_header) + len(body),
                                       decrypted=decrypted))
        if not a.json:
            print('  -> 视频 %s  (%.1f MB) %s' % (
                path, (len(res.ivf_header) + len(body)) / 1048576,
                '[已解密]' if decrypted else '[未解密：未提供 --key]'))

    for k, v in audio.items():
        path = os.path.join(outdir, '%s.a%d.hca' % (name, k))
        try:
            with open(path, 'wb') as fh:
                fh.write(v)
        except OSError as exc:
            print(f'错误：写 {path} 失败：{exc}', file=sys.stderr)
            return EXIT_PARAM
        summary['outputs'].append(dict(path=os.path.abspath(path), kind='hca',
                                       track=k, bytes=len(v), decrypted=False))
        if not a.json:
            print('  -> 音频 %s  (%.2f MB)' % (path, len(v) / 1048576))

    if a.json:
        pe_utils.emit_json(summary)
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
