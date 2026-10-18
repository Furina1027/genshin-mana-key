#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""函数边界表来源选择（异常目录 vs `.pdata` 段诱饵）。

真实 exe（2026-10-18 实测）里 `.pdata` 段是**诱饵**：1,177,301 条里 588,950 条
`end<=start`，连一个真实函数起点都找不到；真正的 RUNTIME_FUNCTION 表被搬进 `.upx0`，
只有**异常目录**（数据目录[3]，RVA 0x19F73B00）指向它（1,177,402 条，全部合法）。
读错表不会有任何报错，只会让指纹截断错位、跨版本迁移匹配不到 —— 所以这里必须有回归用例。

用 _synth_pe 造三种形态：
  · 异常目录 + 诱饵 `.pdata`：必须选异常目录，且把诱饵的低分写进 warnings；
  · 只有 `.pdata`：回退老行为；
  · 异常目录指向段外：回退 `.pdata` 并给出警告；
  · 两者都没有：抛 PEFormatError（绝不返回空表）。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pdata  # noqa: E402
import pe_utils  # noqa: E402
from _synth_pe import CHARS_CODE, CHARS_DATA, write_pe  # noqa: E402

EXCEPTION_DIRECTORY_INDEX = 3


def rtf(start: int, end: int, unwind: int = 0) -> bytes:
    """一条 RUNTIME_FUNCTION（12 字节）。"""
    return struct.pack('<III', start, end, unwind)


# 真实表（异常目录指向它）：3 个函数
REAL_TABLE = b''.join([
    rtf(0x1000, 0x1050),
    rtf(0x1050, 0x10C0),
    rtf(0x10C0, 0x1200),
])

# 诱饵表：全是 end<=start 的垃圾条目
DECOY_TABLE = b''.join([
    rtf(0x2000, 0x1000),
    rtf(0x2100, 0x2000),
    rtf(0x2200, 0x2100),
    rtf(0x2300, 0x2200),
])


def _sections(*, with_decoy_pdata: bool = True) -> list:
    secs = [{'name': '.text', 'va': 0x1000, 'data': b'\x90' * 0x200, 'chars': CHARS_CODE},
            {'name': '.upx0', 'va': 0x3000, 'data': REAL_TABLE, 'chars': CHARS_DATA}]
    if with_decoy_pdata:
        secs.insert(1, {'name': '.pdata', 'va': 0x2000, 'data': DECOY_TABLE,
                        'chars': CHARS_DATA})
    return secs


class BoundarySourceTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _pe(self, name: str, **kwargs):
        path = os.path.join(self._tmp.name, name)
        if os.path.exists(path):
            os.unlink(path)
        write_pe(path, **kwargs)
        return pe_utils.load_pe(path)

    def test_prefers_exception_directory_over_decoy_pdata(self):
        """异常目录合法、`.pdata` 是诱饵 → 选异常目录，并把诱饵分数写进 warnings。"""
        pe = self._pe('exc_vs_decoy.exe', sections=_sections(),
                      data_directories={EXCEPTION_DIRECTORY_INDEX: (0x3000, len(REAL_TABLE))})
        fb = pdata.parse_pdata(pe)
        self.assertEqual(fb.info['source'], '异常目录')
        self.assertEqual(len(fb), 3)
        self.assertEqual([b.start for b in fb], [0x1000, 0x1050, 0x10C0])
        self.assertEqual([b.size for b in fb], [0x50, 0x70, 0x140])
        joined = '\n'.join(fb.warnings)
        self.assertIn('未采用', joined, fb.warnings)
        self.assertIn('诱饵', joined, fb.warnings)

    def test_containing_and_end_of_come_from_the_chosen_table(self):
        """查询接口必须基于选中的表（诱饵表里根本没有 0x1050 这个起点）。"""
        pe = self._pe('exc_query.exe', sections=_sections(),
                      data_directories={EXCEPTION_DIRECTORY_INDEX: (0x3000, len(REAL_TABLE))})
        fb = pdata.parse_pdata(pe)
        b = fb.containing(0x1060)
        self.assertIsNotNone(b)
        self.assertEqual((b.start, b.end), (0x1050, 0x10C0))
        self.assertEqual(fb.end_of(0x1000), 0x1050)
        self.assertIsNone(fb.containing(0x1200))     # 表尾之后没有函数

    def test_falls_back_to_pdata_section_when_no_exception_directory(self):
        """没有异常目录（数据目录全 0）→ 老行为：解析 `.pdata` 段。"""
        real = b''.join([rtf(0x1000, 0x1050), rtf(0x1050, 0x1100)])
        pe = self._pe('only_pdata.exe', sections=[
            {'name': '.text', 'va': 0x1000, 'data': b'\x90' * 0x200, 'chars': CHARS_CODE},
            {'name': '.pdata', 'va': 0x2000, 'data': real, 'chars': CHARS_DATA},
        ])
        fb = pdata.parse_pdata(pe)
        self.assertEqual(fb.info['source'], '.pdata')
        self.assertEqual([b.start for b in fb], [0x1000, 0x1050])

    def test_falls_back_when_exception_directory_is_out_of_range(self):
        """异常目录指向段外 → 不崩，回退 `.pdata` 并在 warnings 里说明。"""
        real = b''.join([rtf(0x1000, 0x1050)])
        pe = self._pe('bad_exc.exe', sections=[
            {'name': '.text', 'va': 0x1000, 'data': b'\x90' * 0x200, 'chars': CHARS_CODE},
            {'name': '.pdata', 'va': 0x2000, 'data': real, 'chars': CHARS_DATA},
        ], data_directories={EXCEPTION_DIRECTORY_INDEX: (0x900000, len(real))})
        fb = pdata.parse_pdata(pe)
        self.assertEqual(fb.info['source'], '.pdata')
        self.assertEqual(len(fb), 1)
        self.assertIn('异常目录不可用', '\n'.join(fb.warnings))

    def test_raises_when_no_boundary_source_at_all(self):
        """既没有异常目录也没有 `.pdata` 段 → 显式报错，绝不返回空表。"""
        pe = self._pe('none.exe', sections=[
            {'name': '.text', 'va': 0x1000, 'data': b'\x90' * 0x200, 'chars': CHARS_CODE},
        ])
        with self.assertRaises(pe_utils.PEFormatError):
            pdata.parse_pdata(pe)
        self.assertIsNone(pdata.load_function_bounds(pe))
        with self.assertRaises(pe_utils.PEFormatError):
            pdata.load_function_bounds(pe, required=True)


if __name__ == '__main__':
    unittest.main()
