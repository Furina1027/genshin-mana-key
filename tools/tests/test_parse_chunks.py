#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""parse_chunks 的畸形块测试：必须**显式抛出带偏移的异常**，不许静默 break。

C1/C2 都要求 ``usm.parse_chunks`` 成为唯一实现，并且：
  · ``size`` 过小 / 越界 / ``data_offset + padding > size`` → 抛 UsmFormatError（带文件偏移）；
  · ``dlen <= 0`` 的块不产出（计入 skipped_empty），而不是当成 0 长度载荷塞进结果；
  · 未知的 4 字节标签 = 容器尾部（MKV 头），正常结束并记录 tail_offset。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import usm  # noqa: E402
from _usm_fixture import make_chunk  # noqa: E402


class TestParseChunksOk(unittest.TestCase):
    def test_valid_chain(self):
        blob = (make_chunk(b'@SFV', 1234, b'A' * 100)
                + make_chunk(b'@SFA', 0, b'B' * 50, chno=3)
                + make_chunk(b'@UTF', 0, b'C' * 20, dt=1))
        chunks = usm.parse_chunks(blob)
        self.assertEqual(len(chunks), 3)
        self.assertEqual([c.typ for c in chunks], [b'@SFV', b'@SFA', b'@UTF'])
        self.assertEqual(chunks[0].frame_time, 1234)
        self.assertEqual(chunks[1].chno, 3)
        self.assertEqual(chunks[2].dt, 1)
        self.assertEqual(chunks[0].dl, 100)
        self.assertEqual(chunks[0].ds, 24)
        self.assertEqual(chunks.total, 3)
        self.assertEqual(chunks.skipped_empty, 0)
        self.assertEqual(chunks.tail_offset, len(blob))
        # payload 切出来就是原来写进去的字节
        self.assertEqual(chunks[0].payload(blob), b'A' * 100)

    def test_trailing_mkv_header_is_tail_not_error(self):
        """真实 USM 文件尾部是 MKV 头（不是 chunk）—— 必须当正常结束。"""
        mkv = b'\x1a\x45\xdf\xa3' + bytes(range(200))
        blob = make_chunk(b'@SFV', 1, b'X' * 64) + mkv
        chunks = usm.parse_chunks(blob)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks.tail_offset, len(blob) - len(mkv))

    def test_zero_padding_tail(self):
        blob = make_chunk(b'@SFV', 1, b'X' * 64) + b'\x00' * 64
        chunks = usm.parse_chunks(blob)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks.tail_offset, 24 + 64)

    def test_empty_payload_counted_not_emitted(self):
        """data_offset + padding == size ⇒ dlen == 0：不产出，但记进 skipped_empty。"""
        blob = make_chunk(b'@SFV', 1, b'', data_offset=0x10, padding=0)
        chunks = usm.parse_chunks(blob)
        self.assertEqual(len(chunks), 0)
        self.assertEqual(chunks.skipped_empty, 1)
        self.assertEqual(chunks.total, 1)

    def test_padding_trimmed(self):
        blob = make_chunk(b'@SFV', 1, b'X' * 32, padding=8)
        chunks = usm.parse_chunks(blob)
        self.assertEqual(chunks[0].dl, 32)
        self.assertEqual(chunks[0].payload(blob), b'X' * 32)


class TestParseChunksMalformed(unittest.TestCase):
    def test_size_overruns_file(self):
        blob = make_chunk(b'@SFV', 1, b'X' * 64, size_override=0x7FFF)
        with self.assertRaises(usm.UsmFormatError) as cm:
            usm.parse_chunks(blob)
        msg = str(cm.exception)
        self.assertIn('0x0', msg)
        self.assertIn('超出文件大小', msg)

    def test_size_too_small(self):
        blob = make_chunk(b'@SFV', 1, b'', data_offset=0x10, size_override=0x4)
        with self.assertRaises(usm.UsmFormatError) as cm:
            usm.parse_chunks(blob)
        self.assertIn('过小', str(cm.exception))

    def test_size_zero(self):
        blob = make_chunk(b'@SFV', 1, b'', data_offset=0x10, size_override=0)
        with self.assertRaises(usm.UsmFormatError):
            usm.parse_chunks(blob)

    def test_data_offset_plus_padding_exceeds_size(self):
        # 手工拼：size=0x20 且文件长度足够（到达 pos+8+size），但 data_offset+padding 超过 size
        blob = make_chunk(b'@SFV', 1, b'Y' * 8, data_offset=0x30, padding=0x10,
                          size_override=0x20) + b'\x00' * 8
        with self.assertRaises(usm.UsmFormatError) as cm:
            usm.parse_chunks(blob)
        self.assertIn('data_offset', str(cm.exception))

    def test_malformed_offset_in_message(self):
        """异常信息必须带**真实**偏移：前面先放一个合法块，坏块的偏移就是它的 end。"""
        good = make_chunk(b'@SFV', 1, b'X' * 64)
        bad = make_chunk(b'@SFA', 1, b'Y' * 8, size_override=0x7FFF)
        with self.assertRaises(usm.UsmFormatError) as cm:
            usm.parse_chunks(good + bad)
        self.assertIn(f'0x{len(good):X}', str(cm.exception))

    def test_lenient_mode_records_instead_of_raising(self):
        bad = make_chunk(b'@SFV', 1, b'Y' * 8, size_override=0x7FFF)
        chunks = usm.parse_chunks(bad, strict=False)
        self.assertEqual(len(chunks), 0)
        self.assertEqual(len(chunks.malformed), 1)
        self.assertEqual(chunks.malformed[0][0], 0)

    def test_truncated_tail_chunk_raises(self):
        """文件被截断（最后一个块只有一半）也必须报错，不能静默当末尾。"""
        blob = make_chunk(b'@SFV', 1, b'X' * 1024)
        with self.assertRaises(usm.UsmFormatError):
            usm.parse_chunks(blob[:len(blob) // 2])


if __name__ == '__main__':
    unittest.main()
