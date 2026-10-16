#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""三个 USM 脚本的端到端（CLI main()）测试。

覆盖的缺陷：
  · C2：usm_stream_extract 解密后第 0 帧必须完整（与 usm_decrypt.mjs 的 payload[0x40:] 语义一致）；
        给了 --key 但 nonce 缺失时必须非 0 退出，不许输出假的 .dec.ivf；
        密钥长度非法必须报参数错误；
  · C3：usm_frame_marker 只统计 @SFV、媒体块为 0 时不崩、输出 verdict 并据此设置退出码；
  · usm_chunk_probe 用共享 parse_chunks，缺省能跑通 --json。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usm  # noqa: E402
import usm_chunk_probe  # noqa: E402
import usm_frame_marker  # noqa: E402
import usm_stream_extract  # noqa: E402
from _usm_fixture import expected_ivf, make_usm, random_frame  # noqa: E402

KEY = bytes.fromhex('F5AC17FFE4B4B430553AE073EB8A8A1D')
NONCE = bytes.fromhex('0102030405060708')
KEY_HEX = KEY.hex().upper()


def run_main(mod, argv):
    """以给定 argv 调 main()，返回 (退出码, stdout 文本)。"""
    buf = io.StringIO()
    old = sys.argv
    sys.argv = [mod.__name__] + list(argv)
    try:
        with contextlib.redirect_stdout(buf):
            code = mod.main()
    finally:
        sys.argv = old
    return code, buf.getvalue()


def h264_frame(n: int, seed: int) -> bytes:
    """造一帧「明文 H.264 风格」的数据：起始码周期性出现。"""
    out = bytearray(b'\x00\x00\x00\x01\x65')
    i = 0
    while len(out) < n:
        out += bytes(((seed * 31 + i * 17 + k) % 251 for k in range(60)))
        out += b'\x00\x00\x01'
        i += 1
    return bytes(out[:n])


class StreamExtractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.frames = [random_frame(0x400 + i * 97, seed=i + 1) for i in range(8)]
        cls.usm_path = os.path.join(cls.tmp, 'enc.usm')
        blob = make_usm(cls.frames, key=KEY, nonce=NONCE)
        with open(cls.usm_path, 'wb') as fh:
            fh.write(blob)
        cls.expected = expected_ivf(cls.frames)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_decrypt_writes_correct_ivf(self):
        outdir = os.path.join(self.tmp, 'out1')
        code, text = run_main(usm_stream_extract, [self.usm_path, '-o', outdir,
                                                   '--key', KEY_HEX, '--no-audio'])
        self.assertEqual(code, 0, text)
        path = os.path.join(outdir, 'enc.dec.ivf')
        self.assertTrue(os.path.exists(path), text)
        with open(path, 'rb') as fh:
            got = fh.read()
        # ★ 整份 IVF 逐字节等于「正确解密后」应当得到的内容（含第 0 帧）
        self.assertEqual(got, self.expected)
        self.assertIn('已解密', text)

    def test_decrypt_json(self):
        outdir = os.path.join(self.tmp, 'out2')
        code, text = run_main(usm_stream_extract, [self.usm_path, '-o', outdir,
                                                   '--key', KEY_HEX, '--json'])
        self.assertEqual(code, 0)
        info = json.loads(text)
        self.assertTrue(info['decrypted'])
        self.assertEqual(info['frames'], len(self.frames))
        self.assertEqual(info['nonce'], NONCE.hex())
        self.assertTrue(any(o['kind'] == 'ivf' and o['decrypted'] for o in info['outputs']))

    def test_bad_key_length_is_param_error(self):
        code, _ = run_main(usm_stream_extract, [self.usm_path, '--key', KEY_HEX[:30]])
        self.assertEqual(code, usm_stream_extract.EXIT_PARAM)

    def test_missing_nonce_with_key_fails(self):
        p = os.path.join(self.tmp, 'nononce.usm')
        with open(p, 'wb') as fh:
            fh.write(make_usm(self.frames, key=KEY, nonce=NONCE, nonce_marker=False))
        outdir = os.path.join(self.tmp, 'out3')
        code, _ = run_main(usm_stream_extract, [p, '-o', outdir, '--key', KEY_HEX])
        self.assertEqual(code, usm_stream_extract.EXIT_KEY)
        # ★ 绝不允许留下名叫 .dec.ivf 的假解密产物
        self.assertFalse(os.path.exists(os.path.join(outdir, 'nononce.dec.ivf')))

    def test_missing_nonce_allowed_outputs_plain_ivf(self):
        p = os.path.join(self.tmp, 'nononce2.usm')
        with open(p, 'wb') as fh:
            fh.write(make_usm(self.frames, key=KEY, nonce=NONCE, nonce_marker=False))
        outdir = os.path.join(self.tmp, 'out4')
        code, text = run_main(usm_stream_extract, [p, '-o', outdir, '--key', KEY_HEX,
                                                   '--allow-missing-nonce', '--no-audio'])
        self.assertEqual(code, 0, text)
        plain = os.path.join(outdir, 'nononce2.ivf')
        self.assertTrue(os.path.exists(plain))
        self.assertFalse(os.path.exists(os.path.join(outdir, 'nononce2.dec.ivf')))
        self.assertIn('未解密', text)

    def test_malformed_container_exit_code(self):
        p = os.path.join(self.tmp, 'bad.usm')
        blob = bytearray(make_usm(self.frames, key=KEY, nonce=NONCE))
        blob[4:8] = (0x7FFFFFFF).to_bytes(4, 'big')   # 第一个块 size 越界
        with open(p, 'wb') as fh:
            fh.write(bytes(blob))
        code, _ = run_main(usm_stream_extract, [p, '--info'])
        self.assertEqual(code, usm_stream_extract.EXIT_FORMAT)


class FrameMarkerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        n = 200
        enc_frames = [random_frame(0x400, seed=1000 + i) for i in range(n)]
        enc = os.path.join(cls.tmp, 'enc.usm')
        with open(enc, 'wb') as fh:
            fh.write(make_usm(enc_frames, key=KEY, nonce=NONCE))
        cls.enc = enc
        plain_frames = [h264_frame(0x400, i) for i in range(n)]
        plain = os.path.join(cls.tmp, 'plain.usm')
        with open(plain, 'wb') as fh:
            fh.write(make_usm(plain_frames, encrypt=False, nonce_marker=False))
        cls.plain = plain
        tiny = os.path.join(cls.tmp, 'tiny.usm')
        with open(tiny, 'wb') as fh:
            fh.write(make_usm([random_frame(0x400, seed=5)], encrypt=False,
                              nonce_marker=False))
        cls.tiny = tiny

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_encrypted_verdict(self):
        code, text = run_main(usm_frame_marker, ['--file', self.enc])
        self.assertEqual(code, usm_frame_marker.EXIT_ENCRYPTED, text)
        self.assertIn('已加密', text)

    def test_plaintext_verdict(self):
        code, text = run_main(usm_frame_marker, ['--file', self.plain])
        self.assertEqual(code, usm_frame_marker.EXIT_PLAIN, text)
        self.assertIn('明文', text)

    def test_too_few_samples_is_not_a_verdict(self):
        code, text = run_main(usm_frame_marker, ['--file', self.tiny])
        self.assertEqual(code, usm_frame_marker.EXIT_UNSURE, text)
        self.assertIn('样本不足', text)

    def test_json_verdict(self):
        code, text = run_main(usm_frame_marker, ['--file', self.enc, '--json'])
        self.assertEqual(code, usm_frame_marker.EXIT_ENCRYPTED)
        info = json.loads(text)
        self.assertEqual(info['verdict'], '已加密')
        self.assertIn('body_low2_ratio', info)

    def test_audio_only_file_no_crash(self):
        """只有 @SFA 音频、没有 @SFV 视频 —— 旧实现会 ZeroDivisionError。"""
        p = os.path.join(self.tmp, 'audio.usm')
        with open(p, 'wb') as fh:
            fh.write(make_usm([random_frame(0x100, seed=1)], encrypt=False,
                              nonce_marker=False).replace(b'@SFV', b'@SFA'))
        code, text = run_main(usm_frame_marker, ['--file', p])
        self.assertEqual(code, usm_frame_marker.EXIT_UNSURE, text)
        self.assertIn('样本不足', text)


class ChunkProbeTest(unittest.TestCase):
    def test_probe_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'enc.usm')
            with open(p, 'wb') as fh:
                fh.write(make_usm([random_frame(0x400, seed=3)], key=KEY, nonce=NONCE))
            code, text = run_main(usm_chunk_probe, ['--file', p, '--json'])
            self.assertEqual(code, 0, text)
            info = json.loads(text)
            self.assertEqual(info['chunks'], 3)          # @UTF 元数据 + @SFV + @SFA
            self.assertIn('@SFV', info['by_type'])

    def test_probe_malformed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'bad.usm')
            blob = bytearray(make_usm([random_frame(0x80, seed=3)], key=KEY, nonce=NONCE))
            blob[4:8] = (0x7FFFFFFF).to_bytes(4, 'big')
            with open(p, 'wb') as fh:
                fh.write(bytes(blob))
            code, _ = run_main(usm_chunk_probe, ['--file', p])
            self.assertEqual(code, usm_chunk_probe.EXIT_FORMAT)


if __name__ == '__main__':
    unittest.main()
