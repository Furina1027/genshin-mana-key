#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""usm.py 的端到端测试：合成 USM → 用已知 key 加密 → 解密 → 逐帧比对。

这条测试是 C2 的回归闸门：旧实现对所有帧一律用 ``PLAIN = 0x34``，
而**第 0 帧**的帧数据是从 payload 偏移 0x2C 开始的，明文前缀只有 **0x14**，
于是第 0 帧被用错 32 字节（2 个 AES 块）的计数器解开。
本文件的 ``test_frame0_regression_...`` 会同时跑「正确语义」与「旧的 PLAIN=0x34 语义」，
断言前者逐字节还原、后者必然对不上 —— 修回旧行为这条测试立刻红。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usm  # noqa: E402
from _usm_fixture import (NONCE_MARKER, expected_ivf, make_ivf_header,  # noqa: E402
                          make_usm, ref_encrypt, random_frame, vp9_frame)

KEY = bytes.fromhex('F5AC17FFE4B4B430553AE073EB8A8A1D')
NONCE = bytes.fromhex('0102030405060708')


class TestUsmFixtureRoundtrip(unittest.TestCase):
    def setUp(self):
        self.frames = [random_frame(0x400 + i * 37, seed=i + 1) for i in range(5)]
        self.blob = make_usm(self.frames, key=KEY, nonce=NONCE)

    def _chunks(self):
        return usm.parse_chunks(self.blob)

    def test_chunks_parsed(self):
        chunks = self._chunks()
        vid = usm.video_chunks(chunks)
        aud = usm.audio_chunks(chunks)
        self.assertEqual(len(vid), len(self.frames))
        self.assertEqual(len(aud), 1)
        # chno 会撞号：视频和音频都是 chno=0，必须靠 typ 区分
        self.assertEqual({c.chno for c in vid} & {c.chno for c in aud}, {0})
        # payload 起始紧跟在 24 字节头之后，长度 == size - data_offset - padding
        for c in vid:
            self.assertEqual(c.ds, c.pos + 24)
            self.assertEqual(c.dl, c.size - c.data_offset - c.padding)
            self.assertEqual(c.end, c.pos + 8 + c.size)

    def test_nonce_extracted(self):
        self.assertEqual(usm.read_nonce(self.blob), NONCE)
        self.assertEqual(usm.read_nonce(b'no marker here'), None)

    def test_without_key_is_ciphertext(self):
        res = usm.extract_video(self.blob, self._chunks())
        self.assertTrue(res.ivf_header.startswith(b'DKIF'))
        self.assertEqual(len(res.frames), len(self.frames))
        self.assertEqual(res.decrypted_bytes, 0)
        # 明文帧的头 0x14 字节是明文（VP9 头），但其余部分是密文
        self.assertNotEqual(res.frames[0][1], self.frames[0])
        # 帧数据前 0x14 字节（= payload[0x2C:0x40]）留在明文区，不受加密影响
        self.assertEqual(res.frames[0][1][:0x14], self.frames[0][:0x14])
        self.assertNotEqual(res.frames[0][1][0x14:], self.frames[0][0x14:])

    def test_decrypt_restores_every_frame(self):
        res = usm.extract_video(self.blob, self._chunks(), key=KEY, nonce=NONCE)
        self.assertEqual(len(res.frames), len(self.frames))
        for i, (ts, data) in enumerate(res.frames):
            self.assertEqual(ts, i * 1000 + 1)
            self.assertEqual(data, self.frames[i],
                             f'第 {i} 帧解密后与明文不一致（{len(data)} B）')
        # IVF 头 + 全部帧条目 + 帧数据，逐字节等于规范拼法
        rebuilt = res.ivf_header + b''.join(
            len(d).to_bytes(4, 'little') + ts.to_bytes(8, 'little') + d
            for ts, d in res.frames)
        self.assertEqual(rebuilt, expected_ivf(self.frames))

    def test_decrypted_byte_count(self):
        """解密字节数 == 每个条目落在 payload[0x40:] 之后的长度之和。"""
        chunks = usm.video_chunks(self._chunks())
        want = 0
        for i, c in enumerate(chunks):
            payload_len = c.dl
            data_off = 0x20 + 0x0C if i == 0 else 0x0C     # 首块多 32B IVF 头
            start = max(0x40, data_off)
            end = min(data_off + len(self.frames[i]), payload_len)
            want += max(0, end - start)
        res = usm.extract_video(self.blob, self._chunks(), key=KEY, nonce=NONCE)
        self.assertEqual(res.decrypted_bytes, want)
        self.assertGreater(want, 0)

    # ------------------------------------------------------------------ C2 回归闸门
    def test_frame0_regression_old_plain_0x34_is_wrong(self):
        """旧的「所有帧都用 PLAIN=0x34」一定解坏第 0 帧。"""
        chunks = usm.video_chunks(self._chunks())
        c0 = chunks[0]
        payload = c0.payload(self.blob)
        self.assertEqual(payload[:4], b'DKIF')
        # 正确语义：加密区是 payload[0x40:]，对应帧数据偏移 0x14；
        # 计数器用条目自己的 ts（不是 chunk 头那个诱饵 frameTime）
        entry_ts = int.from_bytes(payload[36:40], 'little')
        self.assertNotEqual(entry_ts, c0.frame_time, 'fixture 应当使用诱饵 chunk frameTime')
        fixed = payload[:0x40] + usm.ctr_xor(payload[0x40:], KEY, NONCE, entry_ts)
        frame0_fixed = fixed[0x2C:0x2C + len(self.frames[0])]
        self.assertEqual(frame0_fixed, self.frames[0], '按 payload[0x40:] 语义应当完整还原')

        # ★ 旧实现（usm_stream_extract.py 第 169-173 行）：对帧数据用固定 PLAIN=0x34、
        #   计数器用 chunk 的 frameTime
        frame0_old = payload[0x2C:0x2C + len(self.frames[0])]
        old = frame0_old[:0x34] + usm.ctr_xor(frame0_old[0x34:], KEY, NONCE, c0.frame_time)
        self.assertNotEqual(old, self.frames[0], '旧语义居然解对了？说明测试没抓住回归')
        # 差异集中在被错过的头 2 个 AES 块 + 计数器错位处
        self.assertNotEqual(old[0x14:0x34], self.frames[0][0x14:0x34])
        self.assertEqual(old[:0x14], self.frames[0][:0x14])

    def test_other_chunks_plain_prefix_is_0x34(self):
        chunks = usm.video_chunks(self._chunks())
        payload = chunks[1].payload(self.blob)
        self.assertNotEqual(payload[:4], b'DKIF')
        entry_ts = int.from_bytes(payload[4:12], 'little')
        fixed = payload[:0x40] + usm.ctr_xor(payload[0x40:], KEY, NONCE, entry_ts)
        self.assertEqual(fixed[0x0C:0x0C + len(self.frames[1])], self.frames[1])

    def test_counter_uses_entry_timestamp_not_chunk_time(self):
        """一条证据：用 chunk 头的 frameTime 解密必须失败（fixture 里是诱饵值）。"""
        chunks = usm.video_chunks(self._chunks())
        c = chunks[2]
        payload = c.payload(self.blob)
        wrong = payload[:0x40] + usm.ctr_xor(payload[0x40:], KEY, NONCE, c.frame_time)
        self.assertNotEqual(wrong[0x0C:0x0C + len(self.frames[2])], self.frames[2])


class TestMultiEntryChunk(unittest.TestCase):
    """一个 chunk 里塞多个 IVF 条目（C2 要求支持，且各自用自己的 ts）。"""

    def setUp(self):
        self.frames = [random_frame(0x200 + i * 11, seed=100 + i) for i in range(5)]
        self.blob = make_usm(self.frames, key=KEY, nonce=NONCE,
                             entries_per_chunk=[3, 2])

    def test_all_frames_restored(self):
        chunks = usm.parse_chunks(self.blob)
        vid = usm.video_chunks(chunks)
        self.assertEqual(len(vid), 2)
        self.assertEqual(len(usm.iter_ivf_entries(vid[0].payload(self.blob), first=True)), 3)
        self.assertEqual(len(usm.iter_ivf_entries(vid[1].payload(self.blob))), 2)
        res = usm.extract_video(self.blob, chunks, key=KEY, nonce=NONCE)
        self.assertEqual(len(res.frames), 5)
        for i, (ts, data) in enumerate(res.frames):
            self.assertEqual(data, self.frames[i], f'多条目块里第 {i} 帧没还原')


class TestSmallFrames(unittest.TestCase):
    def test_short_payload_stays_plain(self):
        """payload <= 0x40 的块没有加密区（小帧整体明文），加了 key 也不许改字节。"""
        frames = [random_frame(0x200, seed=7)] + [random_frame(10, seed=8)]
        blob = make_usm(frames, key=KEY, nonce=NONCE)
        chunks = usm.parse_chunks(blob)
        res = usm.extract_video(blob, chunks, key=KEY, nonce=NONCE)
        self.assertEqual(res.frames[1][1], frames[1])
        self.assertEqual(res.frames[0][1], frames[0])


class TestKeyAndNonceValidation(unittest.TestCase):
    def test_parse_key(self):
        self.assertEqual(usm.parse_key('F5AC17FFE4B4B430553AE073EB8A8A1D'), KEY)
        self.assertEqual(usm.parse_key('  f5ac17ffe4b4b430553ae073eb8a8a1d '), KEY)
        self.assertEqual(usm.parse_key('0xF5AC17FFE4B4B430553AE073EB8A8A1D'), KEY)
        for bad in ('F5AC17FFE4B4B430553AE073EB8A8A',      # 30 个字符（15 字节）
                    'F5AC17FFE4B4B430553AE073EB8A8A1D00',  # 34 个字符
                    'F5AC17FFE4B4B430553AE073EB8A8AG',     # 非十六进制
                    '', 'zz', None):
            with self.assertRaises(usm.UsmKeyError, msg=f'{bad!r} 应当报错'):
                usm.parse_key(bad)

    def test_check_key_length(self):
        for n in (1, 8, 15, 17, 33):
            with self.assertRaises(usm.UsmKeyError):
                usm.check_key(b'\x00' * n)
        for n in (16, 24, 32):
            self.assertEqual(len(usm.check_key(b'\x00' * n)), n)

    def test_nonce_length(self):
        with self.assertRaises(usm.UsmKeyError):
            usm.check_nonce(b'\x00' * 7)
        with self.assertRaises(usm.UsmKeyError):
            usm.check_nonce(None)

    def test_key_without_nonce_is_error(self):
        """给了 key 但 nonce 缺失 → 明确报错，绝不输出「已解密」的假文件。"""
        frames = [random_frame(0x200, seed=1)]
        blob = make_usm(frames, key=KEY, nonce=NONCE)
        chunks = usm.parse_chunks(blob)
        with self.assertRaises(usm.UsmKeyError):
            usm.extract_video(blob, chunks, key=KEY, nonce=None)
        with self.assertRaises(usm.UsmKeyError):
            usm.extract_video(blob, chunks, key=None, nonce=NONCE)

    def test_ctr_xor_validates_inputs(self):
        with self.assertRaises(usm.UsmKeyError):
            usm.ctr_xor(b'1234', b'\x00' * 15, NONCE, 0)
        with self.assertRaises(usm.UsmKeyError):
            usm.ctr_xor(b'1234', KEY, b'\x00' * 9, 0)
        with self.assertRaises(usm.UsmKeyError):
            usm.ctr_xor(b'1234', KEY, NONCE, -1)


class TestPlainVp9Detection(unittest.TestCase):
    """usm_frame_marker 用的判据小工具。"""

    def test_start_code_counting(self):
        blob = b'\x00\x00\x00\x01AAAA\x00\x00\x01BB'
        self.assertEqual(usm.count_start_codes(blob), 2)   # 4 字节码只算一次
        self.assertTrue(usm.starts_with_start_code(blob))
        self.assertTrue(usm.starts_with_start_code(b'\x00\x00\x01X'))
        self.assertFalse(usm.starts_with_start_code(vp9_frame(16)))

    def test_entropy_bounds(self):
        self.assertAlmostEqual(usm.entropy(b'\x00' * 100), 0.0)
        self.assertGreater(usm.entropy(bytes(range(256))), 7.9)


if __name__ == '__main__':
    unittest.main()
