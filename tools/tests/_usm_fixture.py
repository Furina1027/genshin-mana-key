#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""合成 USM 文件构造器（只给 tools/tests/ 用）。

★ 关键：这里的加密是**独立实现**（直接用 ``Crypto.Cipher.AES`` 的 ECB 逐块加密计数器），
不是调用 ``usm.ctr_xor`` —— 否则测试就成了「自己证明自己」。它严格按 C2 记录的语义加密：

    加密区  = 每个 chunk 的 payload[0x40:]
    counter = nonce(8B) || BE32(该 IVF 条目自己的 frameTime) || BE32(blockIndex)
    blockIndex 从 0 开始，正好对准该条目落在 payload[0x40:] 之后的第一个字节

所以：首个 chunk 的帧数据明文前缀是 0x40-32-12 = **0x14**（IVF 头 32 + 帧条目 12），
其余 chunk 是 0x40-12 = **0x34**。用固定 0x34 解所有帧就是 C2 里
「第 0 帧解坏」的原始缺陷。

这个模块是**加密器**：它把明文帧 + 已知 key 造成一个「已加密的 USM」，
然后测试用 ``usm.extract_video(..., key=..., nonce=...)`` 解密，断言逐帧完整还原。
"""
from __future__ import annotations

import struct

from Crypto.Cipher import AES

AES_BLOCK = 16
ENCRYPTED_PLAIN_PREFIX = 0x40
IVF_HEADER_SIZE = 32
IVF_ENTRY_SIZE = 12
NONCE_MARKER = b'<NULL>\x00VIDEO_HDRINFO'


# ----------------------------------------------------------------- 参考加密实现
def ref_keystream(key: bytes, counter0: bytes, nbytes: int) -> bytes:
    """参考密钥流：counter0 起、16 字节大端递增、AES-ECB(counter) 拼接。"""
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    counter = int.from_bytes(counter0, 'big')
    mask = (1 << 128) - 1
    while len(out) < nbytes:
        out += cipher.encrypt(counter.to_bytes(16, 'big'))
        counter = (counter + 1) & mask
    return bytes(out[:nbytes])


def ref_counter(nonce: bytes, frame_time: int, block_index: int = 0) -> bytes:
    assert len(nonce) == 8
    return nonce + frame_time.to_bytes(4, 'big') + block_index.to_bytes(4, 'big')


def ref_encrypt(data: bytes, key: bytes, nonce: bytes, frame_time: int) -> bytes:
    ks = ref_keystream(key, ref_counter(nonce, frame_time), len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ----------------------------------------------------------------- 容器拼装
def make_ivf_header(width=1920, height=1080, frame_count=0, rate=30, scale=1) -> bytes:
    h = bytearray(IVF_HEADER_SIZE)
    h[0:4] = b'DKIF'
    struct.pack_into('<HH', h, 4, 0, IVF_HEADER_SIZE)
    h[8:12] = b'VP90'
    struct.pack_into('<HH', h, 12, width, height)
    struct.pack_into('<II', h, 16, rate, scale)
    struct.pack_into('<I', h, 24, frame_count)
    return bytes(h)


def make_entry(size: int, ts: int) -> bytes:
    return struct.pack('<IQ', size, ts)


def make_chunk(typ: bytes, frame_time: int, payload: bytes, *, chno: int = 0,
               dt: int = 0, data_offset: int = 0x10, padding: int = 0,
               frame_rate: int = 30, size_override=None) -> bytes:
    """24 字节头 + payload。size 从 pos+8 起算，所以块总长 = size + 8。"""
    if size_override is None:
        size = data_offset + len(payload) + padding
    else:
        size = size_override
    hdr = bytearray(24)
    hdr[0:4] = typ
    struct.pack_into('>I', hdr, 4, size)
    hdr[8] = 0x01
    hdr[9] = data_offset
    struct.pack_into('>H', hdr, 10, padding)
    hdr[12] = chno
    hdr[13] = 0
    hdr[14] = 0
    hdr[15] = dt
    struct.pack_into('>I', hdr, 16, frame_time)
    struct.pack_into('>I', hdr, 20, frame_rate)
    return bytes(hdr) + payload + b'\x00' * padding


def make_usm(frames, *, key=None, nonce=None, encrypt=True, width=1920, height=1080,
             entries_per_chunk=None, decoy_chunk_time=True, nonce_marker=True,
             fps=30, prefix=b'', suffix=b'') -> bytes:
    """构造一个最小 USM。

    frames          : [bytes, ...] 明文帧数据
    key/nonce       : encrypt=True 时用它们加密（nonce 必须 8 字节）
    entries_per_chunk: None=每块一帧；或 [2,1,3,...] 指定每块几个 IVF 条目
    decoy_chunk_time: True 时 chunk 头的 frameTime 故意写成与条目 ts 不同的值，
                      用来证明解密用的是**条目自己的** frameTime（C2 缺陷之一）
    """
    if not frames:
        raise ValueError('至少要一帧')
    if encrypt and (key is None or nonce is None):
        raise ValueError('encrypt=True 必须给 key 与 nonce')

    # 切成「块 → 条目索引列表」
    if entries_per_chunk is None:
        groups = [[i] for i in range(len(frames))]
    else:
        groups, idx = [], 0
        for n in entries_per_chunk:
            groups.append(list(range(idx, min(idx + n, len(frames)))))
            idx += n
        if idx < len(frames):
            groups.append(list(range(idx, len(frames))))

    out = bytearray(prefix)
    if nonce_marker:
        if nonce is None:
            raise ValueError('nonce_marker=True 必须给 nonce')
        meta = b'#CONTENTS END' + nonce + NONCE_MARKER + b'\x00' * 4
        out += make_chunk(b'@UTF', 0, meta, dt=1)

    for gi, group in enumerate(groups):
        first = (gi == 0)
        payload = bytearray()
        if first:
            payload += make_ivf_header(width, height, len(frames), fps)
        data_offs = []
        # USM 里帧条目与帧数据是**交替**的：entry, data, entry, data, ...
        for fi in group:
            data_offs.append(len(payload) + IVF_ENTRY_SIZE)
            payload += make_entry(len(frames[fi]), fi * 1000 + 1)
            payload += frames[fi]
        payload = bytes(payload)

        if encrypt:
            # ★ 逐个条目：该条目帧数据里落在 payload[0x40:] 之后的部分才加密，
            #   计数器用该条目自己的 ts；条目头本身永不加密。
            for k, fi in enumerate(group):
                data_off = data_offs[k]
                start = max(ENCRYPTED_PLAIN_PREFIX, data_off)
                end = min(data_off + len(frames[fi]), len(payload))
                if start < end:
                    enc = ref_encrypt(payload[start:end], key, nonce, fi * 1000 + 1)
                    payload = payload[:start] + enc + payload[end:]

        # chunk 头 frameTime：默认故意写一个「诱饵值」，只有用条目 ts 才能解对
        if decoy_chunk_time:
            chunk_ft = 0xDEAD0000 + gi
        else:
            chunk_ft = group[0] * 1000 + 1
        out += make_chunk(b'@SFV', chunk_ft, payload, chno=0, dt=0)

    # 音频块（HCA 头风格），用来验证「判流必须用 @SFV 而不是 chno」
    out += make_chunk(b'@SFA', 0, b'\xC8\xC3\xC1\x00' + bytes(range(64)), chno=0, dt=0)
    out += suffix
    return bytes(out)


def expected_ivf(frames, *, width=1920, height=1080, fps=30) -> bytes:
    """按 IVF 规范拼出「正确解密后」应当得到的文件字节，用于逐字节比对。"""
    body = bytearray(make_ivf_header(width, height, len(frames), fps))
    for i, f in enumerate(frames):
        body += make_entry(len(f), i * 1000 + 1)
        body += f
    return bytes(body)


def vp9_frame(n: int, marker=b'\x49\x83\x42') -> bytes:
    """造一帧「看起来像明文 VP9」的数据：VP9 同步码 + 低 2 位 = 0b10 的首字节。"""
    b0 = bytes([(2 | 0x80) & 0xFF])
    return marker + b0 + bytes((i * 7 + n) & 0xFF for i in range(n))


def random_frame(n: int, seed: int = 0) -> bytes:
    """确定性伪随机帧（高熵，模拟密文/不可解码数据）。"""
    out = bytearray()
    x = (seed * 2654435761 + 12345) & 0xFFFFFFFF
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)
