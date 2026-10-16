#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""usm.py — CRI USM 容器解析 + method2(AES-128-CTR) 解密的**唯一**实现。

tools/ 下的三个 USM 脚本（usm_chunk_probe / usm_frame_marker / usm_stream_extract）
原先各抄了一份 parse_chunks，副本之间还不一致（有的没有 dlen 保护、有的在畸形块上
静默 break、有的判通道只看 chno 不看 @SFV/@SFA）。现在全部走这里。

容器结构（本轮实测确认）
------------------------
chunk header 24 字节::

    +0x00 char[4]  type     —— @SFV=视频流 / @SFA=音频流 / @UTF=元数据 …
    +0x04 uint32   size     —— BE，**从 pos+8 起算**（所以块总长 = size + 8）
    +0x09 uint8    data_offset
    +0x0A uint16   padding  —— BE
    +0x0C uint8    chno     —— **视频和音频会撞号**，判流必须用 type 而不是 chno
    +0x0F uint8    dataType —— &3: 0=数据 1=流头 2=#HEADER END 3=元数据
    +0x10 uint32   frameTime —— BE
    +0x14 uint32   frameRate —— BE

    payload = buf[pos + 8 + data_offset : pos + 8 + size - padding]
    dlen    = size - data_offset - padding          （dlen <= 0 的块不产出）

加密语义（method2）
-------------------
加密区是**每个 chunk 的 payload[0x40:]**：

  · 首个视频数据块 payload = IVF 文件头(32) + 帧条目(12) + 帧数据
    → payload[0x40:] 落在帧数据偏移 0x40-32-12 = **0x14**
  · 其余视频数据块 payload = 帧条目(12) + 帧数据
    → payload[0x40:] 落在帧数据偏移 0x40-12 = **0x34**
  · 长度 <= 0x40 的 payload 没有加密区（整体明文）

CTR 计数器::

    counter(16B, 大端) = nonce(8B) || BE32(frameTime) || BE32(blockIndex)
    keystream          = AES-128-ECB(counter)，blockIndex 从 0 开始、随块递增

其中 frameTime 取**该 IVF 条目自己的时间戳**（一个 chunk 里可能有多个条目，
用 chunk 的 frameTime 会让第 2 个及以后的条目计数器错位）。
"""
from __future__ import annotations

import collections
import math
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

__all__ = [
    'UsmFormatError', 'MissingDependency', 'UsmKeyError',
    'Chunk', 'ChunkList', 'IvfEntry', 'VideoExtract',
    'KNOWN_CHUNK_TAGS', 'VIDEO_TAG', 'AUDIO_TAG', 'META_TAG',
    'ENCRYPTED_PLAIN_PREFIX', 'IVF_HEADER_SIZE', 'IVF_ENTRY_SIZE',
    'parse_chunks', 'video_chunks', 'audio_chunks', 'read_nonce',
    'parse_key', 'check_key', 'check_nonce',
    'ctr_keystream_manual', 'ctr_xor', 'aes_ctr_decrypt',
    'iter_ivf_entries', 'decrypt_payload_entries', 'extract_video',
    'entropy', 'count_start_codes', 'starts_with_start_code',
]

# ---------------------------------------------------------------------- 常量
VIDEO_TAG = b'@SFV'
AUDIO_TAG = b'@SFA'
META_TAG = b'@UTF'

#: 已知的 USM chunk 类型标签。不在此列 = 容器尾部（MKV 头等），不是畸形块。
KNOWN_CHUNK_TAGS = frozenset((
    b'@SFV', b'@SFA', b'@UTF', b'@CMS', b'@CUE', b'@ALP', b'@SBT',
    b'@SQV', b'@SQA', b'@SHK', b'CRID',
))

#: size 字段最小合法值：覆盖 pos+8 起的 16 字节剩余头部
MIN_CHUNK_SIZE = 0x10

#: 每个 chunk 的 payload 前 0x40 字节是明文（加密区从 payload[0x40:] 开始）
ENCRYPTED_PLAIN_PREFIX = 0x40

IVF_MAGIC = b'DKIF'
IVF_HEADER_SIZE = 32
IVF_ENTRY_SIZE = 12
AES_BLOCK = 16

NONCE_MARKER = b'<NULL>\x00VIDEO_HDRINFO'
NONCE_SIZE = 8

_HEX32_RE = re.compile(r'^[0-9a-fA-F]{32}$')


# ---------------------------------------------------------------------- 异常
class UsmFormatError(ValueError):
    """USM 容器结构错误（带偏移量，绝不静默跳过）。"""


class UsmKeyError(ValueError):
    """密钥/nonce 参数错误（长度、十六进制格式）。"""


class MissingDependency(RuntimeError):
    """缺少 pycryptodome / cryptography 这类可选依赖。"""


# ---------------------------------------------------------------------- 数据结构
@dataclass(frozen=True)
class Chunk:
    """一个 USM chunk（只记元数据，payload 由调用方按 ds/dl 从原 buffer 切）。"""

    pos: int
    typ: bytes
    size: int
    chno: int
    dt: int
    frame_time: int
    frame_rate: int
    data_offset: int
    padding: int
    ds: int          # payload 起始（文件偏移）
    dl: int          # payload 长度（已扣掉 data_offset 与 padding）
    end: int         # 下一个 chunk 的起始（pos + 8 + size）

    @property
    def is_video(self) -> bool:
        return self.typ == VIDEO_TAG

    @property
    def is_audio(self) -> bool:
        return self.typ == AUDIO_TAG

    @property
    def typ_str(self) -> str:
        return self.typ.decode('latin1', 'replace')

    def payload(self, buf) -> bytes:
        return bytes(buf[self.ds:self.ds + self.dl])

    def __str__(self) -> str:  # pragma: no cover
        return (f'{self.typ_str}@{self.pos} ch={self.chno} dt={self.dt} '
                f'ft={self.frame_time} len={self.dl}')


class ChunkList(list):
    """parse_chunks 的返回值：既是 chunk 列表，也带回解析过程中的旁证。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args)
        self.tail_offset: int = kwargs.pop('tail_offset', 0)
        self.skipped_empty: int = kwargs.pop('skipped_empty', 0)
        self.total: int = kwargs.pop('total', 0)
        self.malformed: list = kwargs.pop('malformed', [])


@dataclass(frozen=True)
class IvfEntry:
    """IVF 帧条目（一个 chunk 里可能有多个）。"""

    index: int
    entry_off: int   # 12 字节条目头在 payload 内的偏移
    ts: int          # 时间戳（== chunk frameTime 通常）
    size: int        # 条目声明的大小
    data_off: int    # 帧数据在 payload 内的偏移
    data_len: int    # 实际可用帧数据长度（截断时小于 size）
    truncated: bool = False


@dataclass
class VideoExtract:
    """extract_video 的结果。"""

    ivf_header: Optional[bytes] = None
    frames: list = field(default_factory=list)   # [(ts, frame_bytes)]
    chunks: int = 0
    entries: int = 0
    decrypted_bytes: int = 0
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.ivf_header is not None and bool(self.frames)


# ---------------------------------------------------------------------- chunk 解析
def parse_chunks(buf, *, strict: bool = True) -> ChunkList:
    """解析 USM chunk 链。

    · 未知的 4 字节标签 = 容器尾部（MKV 头 / 填充），正常结束，记在 ``tail_offset``；
    · 已知标签但 ``size`` 过小或越界 = **畸形块**：strict=True 抛带偏移的
      :class:`UsmFormatError`，strict=False 记进 ``malformed`` 后停止解析；
    · 只产出 ``dlen > 0`` 的块，空块计入 ``skipped_empty``。
    """
    out = ChunkList()
    pos, n = 0, len(buf)
    while pos + 24 <= n:
        typ = bytes(buf[pos:pos + 4])
        if typ not in KNOWN_CHUNK_TAGS:
            out.tail_offset = pos
            break
        size = int.from_bytes(buf[pos + 4:pos + 8], 'big')
        if size < MIN_CHUNK_SIZE:
            msg = (f'偏移 0x{pos:X} 的 {typ!r} 块 size=0x{size:X} 过小'
                   f'（< 0x{MIN_CHUNK_SIZE:X}，头部本身都不完整）')
            if strict:
                raise UsmFormatError(msg)
            out.malformed.append((pos, msg))
            break
        if pos + 8 + size > n:
            msg = (f'偏移 0x{pos:X} 的 {typ!r} 块声明 size=0x{size:X}，'
                   f'需要到 0x{pos + 8 + size:X}，超出文件大小 0x{n:X}（截断/畸形）')
            if strict:
                raise UsmFormatError(msg)
            out.malformed.append((pos, msg))
            break
        data_offset = buf[pos + 9]
        padding = int.from_bytes(buf[pos + 10:pos + 12], 'big')
        if data_offset + padding > size:
            msg = (f'偏移 0x{pos:X} 的 {typ!r} 块 data_offset={data_offset} + '
                   f'padding={padding} > size=0x{size:X}（载荷长度为负，畸形）')
            if strict:
                raise UsmFormatError(msg)
            out.malformed.append((pos, msg))
            break
        chno = buf[pos + 12]
        dt = buf[pos + 15] & 3
        ft = int.from_bytes(buf[pos + 16:pos + 20], 'big')
        fr = int.from_bytes(buf[pos + 20:pos + 24], 'big')
        ds = pos + 8 + data_offset
        dl = size - data_offset - padding
        out.total += 1
        if dl > 0:
            out.append(Chunk(pos=pos, typ=typ, size=size, chno=chno, dt=dt,
                             frame_time=ft, frame_rate=fr, data_offset=data_offset,
                             padding=padding, ds=ds, dl=dl, end=pos + 8 + size))
        else:
            out.skipped_empty += 1
        pos += size + 8
    else:
        out.tail_offset = pos
    return out


def video_chunks(chunks: Iterable[Chunk], *, data_only: bool = True) -> list:
    """视频数据块（type == @SFV，可选只要 dataType==0）。"""
    return [c for c in chunks if c.typ == VIDEO_TAG and (not data_only or c.dt == 0)]


def audio_chunks(chunks: Iterable[Chunk], *, data_only: bool = True) -> list:
    return [c for c in chunks if c.typ == AUDIO_TAG and (not data_only or c.dt == 0)]


# ---------------------------------------------------------------------- nonce
def read_nonce(buf: bytes) -> Optional[bytes]:
    """从 ``<NULL>\\x00VIDEO_HDRINFO`` 前取 8 字节 nonce；找不到返回 None。"""
    ij = buf.find(NONCE_MARKER)
    if ij < NONCE_SIZE:
        return None
    return bytes(buf[ij - NONCE_SIZE:ij])


# ---------------------------------------------------------------------- 参数校验
def check_key(key) -> bytes:
    """校验 AES 密钥：必须是 16/24/32 字节（method2 用 16 字节 AES-128）。"""
    if key is None:
        raise UsmKeyError('密钥为 None')
    if not isinstance(key, (bytes, bytearray)):
        raise UsmKeyError(f'密钥类型必须是 bytes，收到 {type(key).__name__}')
    key = bytes(key)
    if len(key) not in (16, 24, 32):
        raise UsmKeyError(
            f'AES 密钥长度必须是 16/24/32 字节，收到 {len(key)} 字节'
            f'（{key.hex() or "(空)"}）—— 十六进制字符串必须正好 32/48/64 个字符')
    return key


def parse_key(text) -> bytes:
    """把 ``--key`` 的十六进制字符串解析成密钥，长度/字符非法一律显式报错。

    注意：不能直接 ``bytes.fromhex(s)`` 就完事 —— 它会静默接受奇数长度之外的
    任意偶数长度（例如 30 个字符解出 15 字节），到 AES.new 才炸出难懂的异常。
    """
    if text is None:
        raise UsmKeyError('未提供密钥')
    if isinstance(text, (bytes, bytearray)):
        return check_key(bytes(text))
    s = str(text).strip().replace(' ', '')
    if s.lower().startswith('0x'):
        s = s[2:]
    if not s:
        raise UsmKeyError('密钥为空')
    if not re.fullmatch(r'[0-9a-fA-F]+', s):
        bad = sorted({ch for ch in s if ch not in '0123456789abcdefABCDEF'})
        raise UsmKeyError(f'密钥含非十六进制字符 {bad}：{text!r}')
    if len(s) % 2:
        raise UsmKeyError(f'密钥十六进制长度为奇数 {len(s)}：{text!r}')
    if not _HEX32_RE.match(s):
        raise UsmKeyError(
            f'密钥必须是 32 个十六进制字符（16 字节 AES-128），'
            f'收到 {len(s)} 个字符：{text!r}')
    return check_key(bytes.fromhex(s))


def check_nonce(nonce) -> bytes:
    if nonce is None:
        raise UsmKeyError('nonce 为 None（文件里找不到 VIDEO_HDRINFO）')
    if not isinstance(nonce, (bytes, bytearray)):
        raise UsmKeyError(f'nonce 类型必须是 bytes，收到 {type(nonce).__name__}')
    nonce = bytes(nonce)
    if len(nonce) != NONCE_SIZE:
        raise UsmKeyError(f'nonce 必须是 {NONCE_SIZE} 字节，收到 {len(nonce)} 字节')
    return nonce


# ---------------------------------------------------------------------- AES-CTR
def _ecb_backend():
    """返回 ('pycryptodome', AES) / ('cryptography', (Cipher, algorithms, modes))。"""
    try:
        from Crypto.Cipher import AES  # type: ignore
        return 'pycryptodome', AES
    except ImportError:
        pass
    try:
        from cryptography.hazmat.primitives.ciphers import (  # type: ignore
            Cipher, algorithms, modes)
        return 'cryptography', (Cipher, algorithms, modes)
    except ImportError:
        pass
    raise MissingDependency(
        '需要 pycryptodome 或 cryptography 才能做 AES-CTR 解密：'
        'pip install pycryptodome（推荐）或 pip install cryptography')


def _ecb_encrypt(key: bytes, blob: bytes) -> bytes:
    """对 16 字节对齐的 blob 做 AES-ECB 加密（纯计数器块，不需要 padding）。"""
    name, mod = _ecb_backend()
    if name == 'pycryptodome':
        return mod.new(key, mod.MODE_ECB).encrypt(blob)
    Cipher, algorithms, modes = mod
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(blob) + enc.finalize()


def ctr_keystream_manual(key: bytes, counter0: bytes, nbytes: int) -> bytes:
    """参考实现：从 counter0 起、16 字节大端递增，AES-ECB(counter) 拼成密钥流。

    这是「CTR = nonce(8B)||BE32(frameTime)||BE32(blockIndex) 大端递增」的直译，
    用作等价性判据（见 tools/tests/test_ctr.py），不参与正常快路径。
    """
    key = check_key(key)
    counter0 = bytes(counter0)
    if len(counter0) != AES_BLOCK:
        raise UsmKeyError(f'counter 必须是 {AES_BLOCK} 字节，收到 {len(counter0)} 字节')
    if nbytes < 0:
        raise ValueError('nbytes 不能为负')
    if nbytes == 0:
        return b''
    nblocks = (nbytes + AES_BLOCK - 1) // AES_BLOCK
    ctr = bytearray(nblocks * AES_BLOCK)
    val = int.from_bytes(counter0, 'big')
    mask = (1 << 128) - 1
    for i in range(nblocks):
        ctr[i * AES_BLOCK:(i + 1) * AES_BLOCK] = val.to_bytes(AES_BLOCK, 'big')
        val = (val + 1) & mask
    return _ecb_encrypt(key, bytes(ctr))[:nbytes]


def _counter0(nonce: bytes, frame_time: int) -> bytes:
    if not 0 <= frame_time <= 0xFFFFFFFF:
        raise UsmKeyError(f'frameTime 必须是 32 位无符号整数，收到 {frame_time}')
    return nonce + frame_time.to_bytes(4, 'big') + b'\x00\x00\x00\x00'


def ctr_xor(data: bytes, key: bytes, nonce: bytes, frame_time: int,
            *, backend: str = 'auto') -> bytes:
    """AES-128-CTR 加/解密（对称）。

    counter = nonce(8B) || BE32(frame_time) || BE32(block)，block 从 0 起递增。
    backend='auto' 用 pycryptodome 的 MODE_CTR（C 实现，几百 MB 视频也够快）；
    backend='manual' 强制走 ctr_keystream_manual（等价性测试用）。
    """
    key = check_key(key)
    nonce = check_nonce(nonce)
    data = bytes(data)
    if not 0 <= frame_time <= 0xFFFFFFFF:
        raise UsmKeyError(f'frameTime 必须是 32 位无符号整数，收到 {frame_time}')
    if not data:
        return b''
    if backend not in ('auto', 'manual', 'pycryptodome'):
        raise ValueError(f'未知 backend: {backend!r}')
    if backend in ('auto', 'pycryptodome'):
        try:
            from Crypto.Cipher import AES  # type: ignore
        except ImportError:
            if backend == 'pycryptodome':
                raise MissingDependency('需要 pycryptodome：pip install pycryptodome')
            AES = None
        if AES is not None:
            # 不使用 nonce 参数时的默认 counter 是 16 字节；这里固定 nonce=8B，
            # 剩余 8 字节大端作为计数器，initial_value 即 BE32(frameTime)||BE32(0)。
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce,
                             initial_value=(frame_time & 0xFFFFFFFF) << 32)
            return cipher.decrypt(data)
    ks = ctr_keystream_manual(key, _counter0(nonce, frame_time), len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def aes_ctr_decrypt(data: bytes, key: bytes, counter0: bytes) -> bytes:
    """兼容旧接口：给定 16 字节 counter0 的 CTR 解密（走参考实现）。"""
    ks = ctr_keystream_manual(key, counter0, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ---------------------------------------------------------------------- IVF 条目
def iter_ivf_entries(payload: bytes, *, first: bool = False,
                     warnings: Optional[list] = None) -> list:
    """把 chunk payload 切成 IVF 条目。

    first=True 时先跳过 32 字节 IVF 文件头（首个视频块）。
    """
    def warn(msg: str) -> None:
        if warnings is not None:
            warnings.append(msg)

    payload = bytes(payload)
    n = len(payload)
    out: list = []
    off = 0
    if first:
        if n < IVF_HEADER_SIZE:
            warn(f'首个视频块 payload 只有 {n} B，装不下 {IVF_HEADER_SIZE} B 的 IVF 头（截断）')
            return out
        off = IVF_HEADER_SIZE
    idx = 0
    while off + IVF_ENTRY_SIZE <= n:
        size = int.from_bytes(payload[off:off + 4], 'little')
        ts = int.from_bytes(payload[off + 4:off + 12], 'little')
        data_off = off + IVF_ENTRY_SIZE
        avail = n - data_off
        if size == 0:
            warn(f'IVF 条目 #{idx}（payload 偏移 0x{off:X}）声明 size=0，停止切分')
            break
        truncated = size > avail
        out.append(IvfEntry(index=idx, entry_off=off, ts=ts, size=size,
                            data_off=data_off, data_len=min(size, avail),
                            truncated=truncated))
        if truncated:
            warn(f'IVF 条目 #{idx}（payload 偏移 0x{off:X}）声明 {size} B，'
                 f'但 payload 只剩 {avail} B（跨块或文件截断）')
            break
        off = data_off + size
        idx += 1
    if 0 < n - off < IVF_ENTRY_SIZE and any(payload[off:]):
        warn(f'payload 尾部残余 {n - off} B 非零且不足一个 IVF 条目（偏移 0x{off:X}）')
    return out


def decrypt_payload_entries(payload: bytes, key: bytes, nonce: bytes,
                            entries: Sequence[IvfEntry]) -> tuple:
    """按 method2 语义解密一个 chunk 的 payload，返回 (新 payload, 解密字节数)。

    逐个 IVF 条目处理：条目帧数据里位于 payload[0x40:] 之后的字节才是密文，
    密钥流从该条目自己的 frameTime 起算（block 0 对准密文区的第一个字节）。
    """
    key = check_key(key)
    nonce = check_nonce(nonce)
    out = bytearray(payload)
    total = 0
    for e in entries:
        start = max(ENCRYPTED_PLAIN_PREFIX, e.data_off)
        end = min(e.data_off + e.data_len, len(out))
        if start >= end:
            continue
        out[start:end] = ctr_xor(bytes(out[start:end]), key, nonce, e.ts)
        total += end - start
    return bytes(out), total


def extract_video(buf: bytes, chunks: Iterable[Chunk], *,
                  key: Optional[bytes] = None,
                  nonce: Optional[bytes] = None) -> VideoExtract:
    """把全部 @SFV 数据块拼成 (IVF 头, [(ts, 帧数据)])，需要时顺带解密。

    key 与 nonce 必须同时给；只给一个有歧义，直接抛 UsmKeyError（不允许偷偷输出
    「已解密」但其实没解密的文件）。
    """
    if (key is None) != (nonce is None):
        raise UsmKeyError('key 与 nonce 必须同时提供（只给其中一个无法解密）')
    if key is not None:
        key = check_key(key)
        nonce = check_nonce(nonce)

    vid = video_chunks(chunks, data_only=True)
    res = VideoExtract(chunks=len(vid))
    if not vid:
        res.warnings.append('没有 @SFV 数据块（type=@SFV & dataType=0）')
        return res

    ivf: Optional[bytes] = None
    for i, c in enumerate(vid):
        payload = c.payload(buf)
        first = ivf is None
        if first:
            if len(payload) < IVF_HEADER_SIZE or payload[:4] != IVF_MAGIC:
                res.warnings.append(
                    f'首个 @SFV 数据块（文件偏移 0x{c.ds:X}）不以 DKIF 开头：'
                    f'{payload[:4]!r} —— 不是标准 USM 视频流')
                return res
            ivf = payload[:IVF_HEADER_SIZE]
        entries = iter_ivf_entries(payload, first=first, warnings=res.warnings)
        if key is not None:
            payload, n = decrypt_payload_entries(payload, key, nonce, entries)
            res.decrypted_bytes += n
        res.entries += len(entries)
        for e in entries:
            res.frames.append((e.ts, payload[e.data_off:e.data_off + e.data_len]))
    res.ivf_header = ivf
    return res


# ---------------------------------------------------------------------- 统计小工具
def entropy(data: bytes) -> float:
    """香农熵（bit/byte，0..8）。"""
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def count_start_codes(blob: bytes) -> int:
    """H.264/VP9 起始码出现次数。

    3 字节起始码 ``00 00 01`` 是 4 字节码 ``00 00 00 01`` 的子串，所以这里只数
    3 字节模式：两种写法各自的每次出现都恰好计一次（旧实现把两种模式相加，
    4 字节码被重复计数，密度虚高一倍）。
    """
    return bytes(blob).count(b'\x00\x00\x01')


def starts_with_start_code(blob: bytes) -> bool:
    """块首是否就是起始码（3 或 4 字节形式）。"""
    b = bytes(blob)
    return b[:3] == b'\x00\x00\x01' or b[:4] == b'\x00\x00\x00\x01'
