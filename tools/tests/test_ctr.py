#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CTR 计数器等价性测试。

C2 要求把「每 16 字节一次 Python 调用 + 逐字节 XOR」换成 pycryptodome 的
``AES.MODE_CTR``，同时**密钥流必须与下面这个语义逐字节等价**::

    counter(16B, 大端) = nonce(8B) || BE32(frameTime) || BE32(blockIndex)
    keystream          = AES-128-ECB(counter)，blockIndex 从 0 起、16 字节大端递增

本文件用三种互相独立的算法交叉验证：
  1. ``usm.ctr_keystream_manual``      —— 手写计数器 + ECB（参考实现）
  2. ``usm.ctr_xor(backend=...)``      —— pycryptodome MODE_CTR 快路径 / 参考实现退路
  3. 直接 ``AES.MODE_ECB`` 逐块加密手拼 counter（最朴素的第三方实现）

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Crypto.Cipher import AES  # noqa: E402

import usm  # noqa: E402


def has_cryptography():
    """cryptography 是**可选**依赖（只在没有 pycryptodome 时当退路用）。

    CI 只装 tools/requirements.txt 里那四个固定依赖（见该文件的「可选依赖」一节），
    所以这里必须能"查不到就跳过"，否则可选依赖缺失会被误报成功能回归。
    """
    try:
        return importlib.util.find_spec('cryptography') is not None
    except (ImportError, ValueError):     # 被 meta_path 拦截器等挡掉时 find_spec 会抛
        return False


KEY = bytes.fromhex('F5AC17FFE4B4B430553AE073EB8A8A1D')
NONCE = bytes.fromhex('DEADBEEFCAFEBABE')


def naive_keystream(key, nonce, frame_time, nbytes):
    """最朴素的第三方参考：手拼 counter + ECB。"""
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    block = 0
    while len(out) < nbytes:
        counter = nonce + frame_time.to_bytes(4, 'big') + block.to_bytes(4, 'big')
        out += cipher.encrypt(counter)
        block += 1
    return bytes(out[:nbytes])


def pycryptodome_keystream(key, nonce, frame_time, nbytes):
    """直接构造 pycryptodome 的 MODE_CTR（不走 usm.py 的封装）。"""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce,
                     initial_value=(frame_time & 0xFFFFFFFF) << 32)
    return cipher.encrypt(b'\x00' * nbytes)


class TestCounterEquivalence(unittest.TestCase):
    SIZES = (0, 1, 15, 16, 17, 31, 32, 4096)

    def test_manual_matches_naive(self):
        for n in self.SIZES:
            self.assertEqual(
                usm.ctr_keystream_manual(KEY, usm._counter0(NONCE, 0x11223344), n),
                naive_keystream(KEY, NONCE, 0x11223344, n),
                f'nbytes={n} 时手写实现与朴素实现不一致')

    def test_pycryptodome_mode_ctr_matches_manual(self):
        for ft in (0, 1, 0x11223344, 0xFFFFFFFF):
            for n in self.SIZES:
                want = usm.ctr_keystream_manual(KEY, usm._counter0(NONCE, ft), n)
                got = pycryptodome_keystream(KEY, NONCE, ft, n)
                self.assertEqual(got, want,
                                 f'frameTime=0x{ft:X} nbytes={n}：MODE_CTR 与手写不等价')

    def test_ctr_xor_backends_agree(self):
        data = bytes(range(256)) * 5
        for ft in (0, 7, 0xAABBCCDD):
            fast = usm.ctr_xor(data, KEY, NONCE, ft)
            slow = usm.ctr_xor(data, KEY, NONCE, ft, backend='manual')
            self.assertEqual(fast, slow)
            self.assertEqual(fast, bytes(a ^ b for a, b in
                                         zip(data, naive_keystream(KEY, NONCE, ft, len(data)))))

    def test_keystream_is_symmetric(self):
        data = b'hello usm world' * 7
        enc = usm.ctr_xor(data, KEY, NONCE, 42)
        self.assertNotEqual(enc, data)
        self.assertEqual(usm.ctr_xor(enc, KEY, NONCE, 42), data)
        self.assertNotEqual(usm.ctr_xor(enc, KEY, NONCE, 43), data)

    def test_block0_is_ecb_of_counter(self):
        ks = usm.ctr_keystream_manual(KEY, usm._counter0(NONCE, 0x0A0B0C0D), 16)
        self.assertEqual(ks, AES.new(KEY, AES.MODE_ECB)
                         .encrypt(NONCE + bytes.fromhex('0A0B0C0D') + b'\x00' * 4))

    def test_counter_carries_into_frame_time(self):
        """block 计数溢出 32 位时按「16 字节大端递增」进位到 frameTime 字段。"""
        ft = 0x00000010
        counter0 = NONCE + ft.to_bytes(4, 'big') + b'\xFF\xFF\xFF\xFF'
        ks = usm.ctr_keystream_manual(KEY, counter0, 32)
        ecb = AES.new(KEY, AES.MODE_ECB)
        self.assertEqual(ks[:16], ecb.encrypt(counter0))
        self.assertEqual(ks[16:32],
                         ecb.encrypt(NONCE + (ft + 1).to_bytes(4, 'big') + b'\x00' * 4))
        # pycryptodome 的 MODE_CTR 用同样的 8 字节大端计数器字段 → 同样进位
        c = AES.new(KEY, AES.MODE_CTR, nonce=NONCE,
                    initial_value=(ft << 32) | 0xFFFFFFFF)
        self.assertEqual(c.encrypt(b'\x00' * 32), ks)

    def test_backend_forced_manual_without_pycryptodome_path(self):
        """backend='manual' 不依赖 pycryptodome 的 MODE_CTR（只依赖 ECB 加密）。"""
        data = b'\xAA' * 100
        self.assertEqual(usm.ctr_xor(data, KEY, NONCE, 3, backend='manual'),
                         usm.ctr_xor(data, KEY, NONCE, 3))

    def test_unknown_backend_rejected(self):
        with self.assertRaises(ValueError):
            usm.ctr_xor(b'x' * 16, KEY, NONCE, 0, backend='nope')

    @unittest.skipUnless(has_cryptography(),
                         '没装可选的 cryptography：退路本身无从验证（CI 只装固定依赖）')
    def test_cryptography_fallback_is_real(self):
        """没有 pycryptodome 时退到 cryptography 的 ECB —— 不是「检测到就退出」的死分支。"""
        want = naive_keystream(KEY, NONCE, 5, 48)          # 先在正常环境里算参考值
        data = b'\x11' * 70
        want_xor = usm.ctr_xor(data, KEY, NONCE, 5, backend='manual')
        hidden = {'Crypto': None, 'Crypto.Cipher': None, 'Crypto.Cipher.AES': None}
        with mock.patch.dict(sys.modules, hidden):
            name, _ = usm._ecb_backend()
            self.assertEqual(name, 'cryptography')
            self.assertEqual(
                usm.ctr_keystream_manual(KEY, usm._counter0(NONCE, 5), 48), want)
            # backend='auto' 在这种情况下也应该自动退到手写计数器实现
            self.assertEqual(usm.ctr_xor(data, KEY, NONCE, 5), want_xor)
            # backend='pycryptodome' 是显式要求，缺了就该抛 MissingDependency
            with self.assertRaises(usm.MissingDependency):
                usm.ctr_xor(data, KEY, NONCE, 5, backend='pycryptodome')


if __name__ == '__main__':
    unittest.main()
