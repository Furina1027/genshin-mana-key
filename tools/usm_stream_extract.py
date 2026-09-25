#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usm_stream_extract.py — 原神 7.1 USM 容器解封装（视频→IVF/VP9，音频→HCA）

容器结构（本轮实测确认，Cs_ZD_AQ70201201_SLT.usm）：
  chunk header 24 字节：
    +0x00 char[4]  type    —— **@SFV = 视频流 / @SFA = 音频流**（判通道必须用这个！）
    +0x04 uint32   size    —— BE，含头
    +0x09 uint8    data_offset
    +0x0A uint16   padding —— BE
    +0x0C uint8    chno    —— 流内编号。**注意：视频和音频会撞号**（@SFV 的 chno=0
                              与 @SFA 的 chno=0 都存在），所以不能只用 chno 过滤
    +0x0F uint8    dataType —— &3: 0=数据 1=流头(@SFV/@SFA) 2=#HEADER END 3=元数据(@UTF)
    +0x10 uint32   frameTime —— BE
  payload = buf[pos + 8 + data_offset : ...], len = size - data_offset - padding

视频流（@SFV, dataType=0）：
  · 第一个块 payload 以 IVF 文件头 "DKIF" 开头（32 字节：DKIF/version/hdrlen/VP90/
    width/height/framerate/scale/frame_count）
  · 之后每块 payload = IVF 帧条目（LE32 size + LE64 timestamp）+ 帧数据
  · 3000 块 = 3000 帧（与 IVF 头里的 frame_count 一致），拼接后按帧条目解析，尾部残余 0

加密状态（重要）：
  · 7.1 为 method2：frame data 前 52 字节（= payload 0x40）为**明文 VP9 头**，
    之后为 AES-128-CTR 密文。所以直接解码会报
    "Invalid data found when processing input"（前几字节像明文，后面是乱码）。
  · 拿到 key 后用 --key 解密：CTR counter = nonce(8B) || BE32(frameTime) || 0x00000000，
    16 字节大端递增；加密区 = payload[0x40:]。

用法：
  python usm_stream_extract.py <file.usm> [-o OUTDIR] [--key HEX32] [--no-audio]
  python usm_stream_extract.py <file.usm> --info        # 只看结构
"""
import argparse
import os
import struct
import sys

NONCE_MARKER = b'<NULL>\x00VIDEO_HDRINFO'


def parse_chunks(buf):
    out = []
    pos, n = 0, len(buf)
    while pos + 24 <= n:
        size = int.from_bytes(buf[pos + 4:pos + 8], 'big')
        if size == 0 or pos + size + 8 > n:
            break
        do = buf[pos + 9]
        pad = int.from_bytes(buf[pos + 10:pos + 12], 'big')
        out.append(dict(
            pos=pos,
            typ=bytes(buf[pos:pos + 4]),
            chno=buf[pos + 12],
            dt=buf[pos + 15] & 3,
            ft=int.from_bytes(buf[pos + 16:pos + 20], 'big'),
            ds=pos + 8 + do,
            dl=size - do - pad,
        ))
        pos += size + 8
    return out


def read_nonce(buf):
    ij = buf.find(NONCE_MARKER)
    if ij < 8:
        return None
    return buf[ij - 8:ij]


def extract_video(buf, chunks):
    """返回 (ivf_header, [(frameTime, frame_bytes)])"""
    vid = [c for c in chunks if c['typ'] == b'@SFV' and c['dt'] == 0]
    if not vid:
        return None, []
    ivf, parts = None, []
    for c in vid:
        p = buf[c['ds']:c['ds'] + c['dl']]
        if ivf is None:
            if p[:4] != b'DKIF':
                return None, []
            ivf = p[:32]
            parts.append(p[32:])
        else:
            parts.append(p)
    stream = b''.join(parts)
    frames, off = [], 0
    while off + 12 <= len(stream):
        sz = int.from_bytes(stream[off:off + 4], 'little')
        ts = int.from_bytes(stream[off + 4:off + 12], 'little')
        if sz == 0 or off + 12 + sz > len(stream):
            break
        frames.append((ts, stream[off + 12:off + 12 + sz]))
        off += 12 + sz
    return ivf, frames


def extract_audio(buf, chunks):
    """返回 {chno: bytes}（HCA 原始流，可能仍带 56 位 keycode 加密）"""
    out = {}
    for c in chunks:
        if c['typ'] != b'@SFA' or c['dt'] != 0:
            continue
        out.setdefault(c['chno'], bytearray()).extend(buf[c['ds']:c['ds'] + c['dl']])
    return {k: bytes(v) for k, v in sorted(out.items())}


def aes_ctr_decrypt(data: bytes, key: bytes, counter0: bytes) -> bytes:
    """AES-128-CTR：用 ECB 加密递增的 counter 块生成密钥流再 XOR（CRI CriCipher 的做法）"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            raise SystemExit('需要 pycryptodome 或 cryptography：pip install pycryptodome')
        # cryptography 无真 ECB 流接口，这里退回手写
        raise SystemExit('请安装 pycryptodome: pip install pycryptodome')
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray(data)
    ctr = int.from_bytes(counter0, 'big')
    for i in range(0, len(out), 16):
        ks = cipher.encrypt(ctr.to_bytes(16, 'big'))
        chunk = out[i:i + 16]
        for j, b in enumerate(chunk):
            out[i + j] = b ^ ks[j]
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('usm')
    ap.add_argument('-o', '--out', default=None)
    ap.add_argument('--key', default=None, help='32 位十六进制 AES-128 密钥')
    ap.add_argument('--info', action='store_true')
    ap.add_argument('--no-audio', action='store_true')
    a = ap.parse_args()

    buf = open(a.usm, 'rb').read()
    chunks = parse_chunks(buf)
    nonce = read_nonce(buf)
    name = os.path.splitext(os.path.basename(a.usm))[0]
    outdir = a.out or os.path.dirname(a.usm) or '.'
    os.makedirs(outdir, exist_ok=True)

    ivf, frames = extract_video(buf, chunks)
    aud = extract_audio(buf, chunks)
    print('文件   : %s  (%.1f MB)' % (name, len(buf) / 1048576))
    print('chunk  : %d  (视频 %d / 音频 %s)' % (
        len(chunks), len(frames), {k: len(v) for k, v in aud.items()} if False else
        len([c for c in chunks if c['typ'] == b'@SFA' and c['dt'] == 0])))
    print('nonce  : %s' % (nonce.hex() if nonce else '(无)'))
    print('视频帧 : %d' % len(frames))
    if a.info:
        if ivf:
            w = int.from_bytes(ivf[12:14], 'little')
            h = int.from_bytes(ivf[14:16], 'little')
            fc = int.from_bytes(ivf[24:28], 'little')
            print('IVF    : %dx%d  frame_count=%d' % (w, h, fc))
        return

    if ivf and frames:
        key = bytes.fromhex(a.key) if a.key else None
        body = bytearray()
        for ts, f in frames:
            data = f
            if key and nonce:
                # 加密区 = payload[0x40:] = frame data[0x34:]
                PLAIN = 0x34
                ctr0 = nonce + ts.to_bytes(4, 'big') + b'\x00\x00\x00\x00'
                data = f[:PLAIN] + aes_ctr_decrypt(f[PLAIN:], key, ctr0)
            body += len(data).to_bytes(4, 'little') + ts.to_bytes(8, 'little') + data
        p = os.path.join(outdir, name + ('.dec.ivf' if key else '.ivf'))
        open(p, 'wb').write(ivf + bytes(body))
        print('  -> 视频 %s  (%.1f MB)%s' % (p, len(body) / 1048576,
                                            ' [已解密]' if key else ' [未解密]'))
    if not a.no_audio:
        for k, v in aud.items():
            p = os.path.join(outdir, '%s.a%d.hca' % (name, k))
            open(p, 'wb').write(v)
            print('  -> 音频 %s  (%.2f MB)' % (p, len(v) / 1048576))


if __name__ == '__main__':
    main()
