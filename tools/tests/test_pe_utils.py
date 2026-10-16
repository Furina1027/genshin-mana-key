#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pe_utils 的单元测试：合成一个最小 PE，验证 RVA→文件偏移的边界语义。

重点（对应 C1 的硬性要求）：
  · ``rva_to_off`` 必须要求 ``rva - VirtualAddress + size <= SizeOfRawData``，越界抛异常；
  · 段的**虚拟尾部**（VirtualSize > SizeOfRawData，文件里没有字节）**不许**映射成功
    —— 这正是旧代码 ``max(Misc_VirtualSize, SizeOfRawData)`` 会把假数据读出来的地方；
  · 缺段时 ``section_by_name`` 必须显式报错而不是返回 None。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pe_utils  # noqa: E402
from _synth_pe import CHARS_CODE, CHARS_RODATA, build_pe  # noqa: E402

IMAGE_BASE = 0x140000000

TEXT_VA = 0x1000
TEXT_LEN = 0x200
RDATA_VA = 0x2000
RDATA_LEN = 0x100
IL2CPP_VA = 0x3000
IL2CPP_RAW = 0x200
IL2CPP_VSIZE = 0x8000      # ★故意大于 raw：模拟「只在内存里有」的尾部


class PEFixture:
    """在临时目录里落一个合成 PE，并在整个测试类内复用。"""

    def __init__(self, tmpdir):
        self.path = os.path.join(tmpdir, 'synth.exe')
        blob = build_pe([
            dict(name='.text', va=TEXT_VA, data=bytes(range(256)) * 2,
                 chars=CHARS_CODE),
            dict(name='.rdata', va=RDATA_VA, data=b'\xAB' * RDATA_LEN,
                 chars=CHARS_RODATA),
            dict(name='il2cpp', va=IL2CPP_VA, data=b'\x90' * IL2CPP_RAW,
                 vsize=IL2CPP_VSIZE, chars=CHARS_CODE),
        ], image_base=IMAGE_BASE)
        with open(self.path, 'wb') as fh:
            fh.write(blob)
        self.pe = pe_utils.load_pe(self.path)


class TestPELoad(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.fx = PEFixture(cls._tmp.name)
        cls.pe = cls.fx.pe

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_image_base_and_sections(self):
        self.assertEqual(self.pe.image_base, IMAGE_BASE)
        self.assertEqual(self.pe.section_names, ['.text', '.rdata', 'il2cpp'])
        self.assertIsNotNone(self.pe.find_section('il2cpp'))
        self.assertIsNone(self.pe.find_section('nope'))

    def test_section_by_name_missing_raises(self):
        with self.assertRaises(pe_utils.PEFormatError) as cm:
            self.pe.section_by_name('不存在的段')
        self.assertIn('找不到段', str(cm.exception))
        self.assertIsNone(self.pe.section_by_name('不存在的段', required=False))

    def test_rva_to_off_ok(self):
        sec = self.pe.section_by_name('.text')
        self.assertEqual(self.pe.rva_to_off(TEXT_VA), sec.raw_ptr)
        # size 表示「从该 RVA 起要访问多少字节」，只要不越过段尾就合法
        self.assertEqual(self.pe.rva_to_off(TEXT_VA, TEXT_LEN), sec.raw_ptr)
        self.assertEqual(self.pe.rva_to_off(TEXT_VA + TEXT_LEN - 1, 1),
                         sec.raw_ptr + TEXT_LEN - 1)
        self.assertEqual(self.pe.rva_to_off(TEXT_VA + 4), sec.raw_ptr + 4)

    def test_rva_to_off_out_of_range_raises(self):
        # 段内偏移刚好等于 SizeOfRawData → 越界（旧代码 max() 会放过去）
        with self.assertRaises(pe_utils.RvaError):
            self.pe.rva_to_off(TEXT_VA + TEXT_LEN)
        # size 跨过段尾 → 越界
        with self.assertRaises(pe_utils.RvaError):
            self.pe.rva_to_off(TEXT_VA + TEXT_LEN - 1, 2)
        # 完全不在任何段
        with self.assertRaises(pe_utils.RvaError):
            self.pe.rva_to_off(0x9_0000)

    def test_virtual_tail_is_not_file_backed(self):
        """il2cpp 的 VirtualSize 远大于 SizeOfRawData：虚拟范围内但不许映射到文件。"""
        sec = self.pe.section_by_name('il2cpp')
        rva_in_tail = IL2CPP_VA + IL2CPP_RAW + 0x100
        self.assertTrue(sec.contains_rva(rva_in_tail))          # 虚拟范围里
        self.assertEqual(self.pe.section_of_rva(rva_in_tail), sec)
        with self.assertRaises(pe_utils.RvaError) as cm:        # 但文件里没有字节
            self.pe.rva_to_off(rva_in_tail)
        self.assertIn('SizeOfRawData', str(cm.exception))
        # 旧实现（max(vsz, rsz)）在这里会返回一个「合法」偏移 —— 那就是假数据
        old_style = sec.raw_ptr + (rva_in_tail - sec.virtual_address)
        self.assertGreater(old_style, sec.raw_ptr + sec.raw_size)
        # 虚拟范围内的**前** raw_size 字节仍然可以映射
        self.assertEqual(self.pe.rva_to_off(IL2CPP_VA + IL2CPP_RAW - 1),
                         sec.raw_ptr + IL2CPP_RAW - 1)

    def test_off_to_rva_roundtrip(self):
        for rva in (TEXT_VA, TEXT_VA + 0x123, RDATA_VA + 0x10, IL2CPP_VA + 0x1F):
            off = self.pe.rva_to_off(rva)
            self.assertEqual(self.pe.off_to_rva(off), rva)

    def test_off_to_rva_out_of_range(self):
        with self.assertRaises(pe_utils.RvaError):
            self.pe.off_to_rva(len(self.pe.data) + 10)

    def test_read_bytes(self):
        self.assertEqual(self.pe.read_rva(TEXT_VA, 8), bytes(range(8)))
        with self.assertRaises(pe_utils.RvaError):
            self.pe.read_rva(IL2CPP_VA + IL2CPP_RAW, 8)

    def test_va_hint(self):
        with self.assertRaises(pe_utils.RvaError) as cm:
            self.pe.rva_to_off(IMAGE_BASE + 0x999999)
        self.assertIn('VA', str(cm.exception))

    def test_il2cpp_helper(self):
        self.assertEqual(self.pe.il2cpp().name, 'il2cpp')
        with self.assertRaises(pe_utils.PEFormatError):
            self.pe.section_by_name('il2cpp2')

    def test_file_is_read_once(self):
        """load_pe 只读一次文件：data 长度 == 文件大小。"""
        self.assertEqual(len(self.pe.data), os.path.getsize(self.fx.path))

    def test_load_pe_opens_file_exactly_once(self):
        """★ 不能既 open().read() 又 pefile.PE(path)：这些 exe 有几百 MB。"""
        import builtins
        real_open = builtins.open
        opened = []

        def counting_open(file, *args, **kwargs):
            opened.append(os.fspath(file) if not isinstance(file, int) else file)
            return real_open(file, *args, **kwargs)

        with mock.patch('builtins.open', side_effect=counting_open):
            pe = pe_utils.load_pe(self.fx.path)
        self.assertEqual(opened, [self.fx.path])
        self.assertGreater(len(pe.data), 0)

    def test_hexfmt(self):
        self.assertEqual(pe_utils.hexfmt(0x1F), '0x0000001F')
        self.assertEqual(pe_utils.hexfmt(-8), '-0x00000008')
        self.assertEqual(pe_utils.hexfmt(None), '—')


class TestBadPE(unittest.TestCase):
    def test_not_a_pe(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'notpe.bin')
            with open(p, 'wb') as fh:
                fh.write(b'not a pe at all' * 10)
            with self.assertRaises(pe_utils.PEFormatError):
                pe_utils.load_pe(p)

    def test_missing_file(self):
        with self.assertRaises(OSError):
            pe_utils.load_pe(os.path.join(tempfile.gettempdir(), 'definitely-missing.exe'))


if __name__ == '__main__':
    unittest.main()
