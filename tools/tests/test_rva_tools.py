#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RVA 定位链（locate_hooks / table_scan / find_methptr / ptr_semantics /
dump_rva / xref / read_str）的合成 PE 端到端测试。

所有 PE 都是 _synth_pe 现造的：il2cpp 段放代码，.rdata 放 methodPointer 表与字符串。
这里**不需要**真实游戏 exe，也不会执行任何游戏代码。

覆盖要点：
  · locate_hooks：δ=0 与 δ=+37 都能唯一解出表基址；参照项被人为打断时必须非 0 退出；
  · table_scan：文件偏移/RVA 两种给法一致；越界指针非 0；--entries 越界默认报错；
  · find_methptr：向量化找到连续指针区；缺 il2cpp 段时非 0；
  · ptr_semantics：收敛 / 不收敛两种结论；
  · dump_rva：--back 夹取到段首不越界；只认直接 E8 调用；
  · xref：找到 E8 调用点；目标 RVA 不在任何段内时非 0；
  · read_str：--len 不够会自动扩展、解码失败与成功可区分、坏 RVA 非 0。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dump_rva  # noqa: E402
import find_methptr  # noqa: E402
import locate_hooks  # noqa: E402
import pe_utils  # noqa: E402
import ptr_semantics  # noqa: E402
import read_str  # noqa: E402
import table_scan  # noqa: E402
import xref  # noqa: E402
from _synth_pe import CHARS_CODE, CHARS_RODATA, build_pe  # noqa: E402

IMAGE_BASE = 0x140000000
IL2CPP_VA = 0x1000
IL2CPP_SIZE = 0x4000
RDATA_VA = 0x10000
RDATA_SIZE = 0x100000
TABLE_SEC_OFF = 0x1000          # 表在 .rdata 内的偏移

TO_INT32_RVA = IL2CPP_VA + 0x100          # 0x1100
TO_INT32_IDX = 1357
ANCHORS = locate_hooks.ANCHOR_INDICES
TARGET_IDXS = [i for i, _ in locate_hooks.TARGETS]


LAST_STDERR = []


def run_main(mod, argv):
    """返回 (退出码, stdout 文本)。stderr 单独收在 LAST_STDERR 里。

    --json 模式下工具会把人类可读输出改道到 stderr（保证 stdout 只有 JSON），
    所以断言人类可读输出时要用 combined() 把两边拼起来。
    """
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv
    sys.argv = [mod.__name__] + list(argv)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = mod.main()
    finally:
        sys.argv = old
    LAST_STDERR.append(err.getvalue())
    return code, out.getvalue()


def combined(text):
    return text + (LAST_STDERR[-1] if LAST_STDERR else '')


def func_rva(n: int) -> int:
    """给第 n 个方法分配一个 il2cpp 段内的假函数 RVA（避开 to_int32 与调用点）。"""
    return IL2CPP_VA + 0x800 + n * 8


def build_hook_pe(path, *, delta=0, break_anchor=False, tail_va=None):
    """造一个带 methodPointer 表的 PE。delta 就是「全局方法索引平移量」。"""
    rdata = bytearray(RDATA_SIZE)
    table_off = TABLE_SEC_OFF
    slots = {}
    for k, i in enumerate(TARGET_IDXS):
        slots[i + delta] = IMAGE_BASE + func_rva(k + 1)
    if break_anchor:                     # 把参照项的槽位指到 .rdata 里（不是可执行节）
        for i in ANCHORS:
            slots[i + delta] = IMAGE_BASE + RDATA_VA + 0x40
    slots[TO_INT32_IDX + delta] = IMAGE_BASE + TO_INT32_RVA
    for idx, va in slots.items():
        if idx < 0:
            continue
        off = table_off + idx * 8
        if off + 8 <= len(rdata):
            struct.pack_into('<Q', rdata, off, va)
    if tail_va is not None:
        struct.pack_into('<Q', rdata, table_off + tail_va[0] * 8, tail_va[1])

    il2 = bytearray(b'\x90' * IL2CPP_SIZE)
    with open(path, 'wb') as fh:
        fh.write(build_pe([
            dict(name='il2cpp', va=IL2CPP_VA, data=bytes(il2), chars=CHARS_CODE),
            dict(name='.rdata', va=RDATA_VA, data=bytes(rdata), chars=CHARS_RODATA),
        ], image_base=IMAGE_BASE))
    table_file_off = pe_utils.load_pe(path).section_by_name('.rdata').raw_ptr + table_off
    return table_file_off


class LocateHooksTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.pe_d0 = os.path.join(cls.tmp, 'd0.exe')
        cls.off_d0 = build_hook_pe(cls.pe_d0, delta=0)
        cls.pe_d37 = os.path.join(cls.tmp, 'd37.exe')
        cls.off_d37 = build_hook_pe(cls.pe_d37, delta=37)
        cls.pe_bad = os.path.join(cls.tmp, 'bad.exe')
        cls.off_bad = build_hook_pe(cls.pe_bad, delta=0, break_anchor=True)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _argv(self, exe, window, extra=()):
        # 合成 PE 里没有真实 exe 的 0x195DF330，所以显式覆盖 --rva/--idx
        return (['--exe', exe, '--rva', hex(TO_INT32_RVA), '--idx', str(TO_INT32_IDX),
                 '--window', str(window)] + list(extra) + ['--json'])

    def test_delta_zero(self):
        code, text = run_main(locate_hooks, self._argv(self.pe_d0, 4))
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['verdict'], 'ok')
        self.assertEqual(info['table']['delta'], 0)
        self.assertEqual(info['table']['file_offset'], self.off_d0)
        # 表基址必须同时给出文件偏移与 RVA，且两个值语义不同
        self.assertNotEqual(info['table']['rva'], info['table']['file_offset'])
        self.assertEqual(info['table']['rva'],
                         info['table']['file_offset'] - pe_utils.load_pe(self.pe_d0)
                         .section_by_name('.rdata').raw_ptr + RDATA_VA)
        for t in info['targets']:
            self.assertTrue(t['in_il2cpp'], t)
        self.assertEqual(len(info['targets']), 9)

    def test_delta_shift_same_rvas(self):
        """全局方法索引被平移 37 个：解析出的**方法 RVA**必须与 δ=0 时完全一致。

        （表基址与 δ 本身存在整体平移退化，数据无法区分；工具必须把这层退化讲清楚，
        而不是像旧实现那样固定 δ=0 静默读错整张表。）
        """
        code0, text0 = run_main(locate_hooks, self._argv(self.pe_d0, 4))
        code37, text37 = run_main(locate_hooks, self._argv(self.pe_d37, 64))
        self.assertEqual(code0, 0, text0)
        self.assertEqual(code37, 0, text37)
        info0, info37 = json.loads(text0), json.loads(text37)
        rva0 = {t['idx']: t['rva'] for t in info0['targets']}
        rva37 = {t['idx']: t['rva'] for t in info37['targets']}
        self.assertEqual(rva0, rva37)
        self.assertTrue(all(t['in_il2cpp'] for t in info37['targets']))
        self.assertIn(0, info0['table']['delta_choices'])
        self.assertTrue(info37['table']['delta_degenerate'])
        self.assertGreater(len(info37['table']['delta_choices']), 1)
        self.assertIn('退化', combined(text37))

    def test_no_solution_is_nonzero(self):
        code, text = run_main(locate_hooks, self._argv(self.pe_bad, 4))
        self.assertEqual(code, locate_hooks.EXIT_UNTRUSTED, text)
        self.assertEqual(json.loads(text)['verdict'], 'no-solution')

    def test_explicit_table_base(self):
        code, text = run_main(locate_hooks, self._argv(
            self.pe_d0, 4, ['--table-base', hex(self.off_d0)]))
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(text)['table']['file_offset'], self.off_d0)

    def test_missing_exe_is_param_error(self):
        code, _ = run_main(locate_hooks, ['--exe', os.path.join(self.tmp, 'nope.exe')])
        self.assertEqual(code, locate_hooks.EXIT_PARAM)

    def test_unmappable_to_int32_is_nonzero(self):
        """--rva 给的 RVA 在这个 exe 里不存在 → 非 0 退出（不许猜）。"""
        code, _ = run_main(locate_hooks, ['--exe', self.pe_d0, '--rva', '0x195DF330'])
        self.assertNotEqual(code, 0)

    def test_defaults_preserved(self):
        """数值默认必须保持原样（只把本机绝对路径换成了相对文件名）。"""
        self.assertEqual(locate_hooks.SERVERS['cn']['to_int32'], 0x195DF330)
        self.assertEqual(locate_hooks.SERVERS['gl']['to_int32'], 0x1952CC20)
        self.assertEqual(locate_hooks.SERVERS['cn']['to_int32_idx'], 1357)
        self.assertEqual(locate_hooks.SERVERS['gl']['to_int32_idx'], 1357)
        self.assertEqual([i for i, _ in locate_hooks.TARGETS],
                         [75719, 75721, 75762, 75763, 75786, 75787, 75745, 75746, 75712])
        for cfg in locate_hooks.SERVERS.values():
            self.assertNotIn(':', cfg['exe'])       # 不是本机绝对路径


class TableScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.pe = os.path.join(cls.tmp, 't.exe')
        cls.table_off = build_hook_pe(cls.pe, delta=0)
        cls.target_rva = func_rva(1)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_find_by_file_offset(self):
        code, text = run_main(table_scan, [
            '--exe', self.pe, '--base', hex(self.table_off),
            '--find', hex(self.target_rva), '--json'])
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['finds'][0]['indices'], [TARGET_IDXS[0]])
        self.assertEqual(info['finds'][0]['section'], 'il2cpp')

    def test_find_by_rva_matches_file_offset(self):
        pe = pe_utils.load_pe(self.pe)
        rva = pe.off_to_rva(self.table_off)
        code, text = run_main(table_scan, [
            '--exe', self.pe, '--base-rva', hex(rva),
            '--find', hex(self.target_rva), '--json'])
        self.assertEqual(code, 0, text)
        self.assertEqual(json.loads(text)['base_file_offset'], self.table_off)

    def test_entries_overflow_is_param_error(self):
        code, _ = run_main(table_scan, [
            '--exe', self.pe, '--base', hex(self.table_off),
            '--entries', '999999999', '--rva-lo', hex(self.target_rva)])
        self.assertEqual(code, table_scan.EXIT_PARAM)

    def test_entries_clamped(self):
        code, text = run_main(table_scan, [
            '--exe', self.pe, '--base', hex(self.table_off), '--allow-clamp',
            '--entries', '999999999', '--rva-lo', hex(self.target_rva), '--json'])
        self.assertEqual(code, 0, text)
        self.assertGreater(json.loads(text)['entries'], 0)

    def test_out_of_range_pointer_is_nonzero(self):
        """区间内的指针若落在段与段之间的空洞 → 必须非 0 退出。"""
        p = os.path.join(self.tmp, 'oob.exe')
        build_hook_pe(p, delta=0)
        with open(p, 'r+b') as fh:
            fh.seek(self.table_off + TARGET_IDXS[0] * 8)
            fh.write(struct.pack('<Q', IMAGE_BASE + 0x6000))   # il2cpp 与 .rdata 之间的空洞
        code, text = run_main(table_scan, [
            '--exe', p, '--base', hex(self.table_off),
            '--rva-lo', '0x5F00', '--rva-hi', '0x6100'])
        self.assertEqual(code, table_scan.EXIT_OUT_OF_RANGE, text)
        self.assertIn('不在任何段内', text)


class FindMethPtrTest(unittest.TestCase):
    def test_finds_dense_pointer_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'm.exe')
            rdata = bytearray(RDATA_SIZE)
            for k in range(64):                       # 连续 64 项都指向 il2cpp
                struct.pack_into('<Q', rdata, TABLE_SEC_OFF + k * 8,
                                 IMAGE_BASE + func_rva(k))
            struct.pack_into('<Q', rdata, TABLE_SEC_OFF + 5 * 8,
                             IMAGE_BASE + TO_INT32_RVA)
            with open(p, 'wb') as fh:
                fh.write(build_pe([
                    dict(name='il2cpp', va=IL2CPP_VA, data=b'\x90' * IL2CPP_SIZE,
                         chars=CHARS_CODE),
                    dict(name='.rdata', va=RDATA_VA, data=bytes(rdata), chars=CHARS_RODATA),
                ], image_base=IMAGE_BASE))
            rdata_off = pe_utils.load_pe(p).section_by_name('.rdata').raw_ptr
            code, text = run_main(find_methptr, [
                '--exe', p, '--minrun', '16',
                '--known', hex(TO_INT32_RVA) + '=to_int32', '--json'])
            self.assertEqual(code, 0, text)
            info = json.loads(text)
            self.assertTrue(info['candidates'])
            hit = info['known_hits'][0]
            self.assertEqual(hit['index_in_run'], 5)
            self.assertEqual(hit['table_rva'], RDATA_VA + TABLE_SEC_OFF)
    def test_missing_il2cpp_is_param_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'noil2.exe')
            with open(p, 'wb') as fh:
                fh.write(build_pe([dict(name='.text', va=0x1000, data=b'\x90' * 0x100,
                                        chars=CHARS_CODE)], image_base=IMAGE_BASE))
            code, _ = run_main(find_methptr, ['--exe', p])
            self.assertEqual(code, find_methptr.EXIT_PARAM)

    def test_no_candidate_is_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'empty.exe')
            with open(p, 'wb') as fh:
                fh.write(build_pe([
                    dict(name='il2cpp', va=IL2CPP_VA, data=b'\x90' * IL2CPP_SIZE,
                         chars=CHARS_CODE),
                    dict(name='.rdata', va=RDATA_VA, data=bytes(RDATA_SIZE),
                         chars=CHARS_RODATA),
                ], image_base=IMAGE_BASE))
            code, _ = run_main(find_methptr, ['--exe', p, '--minrun', '16'])
            self.assertEqual(code, find_methptr.EXIT_NONE)


class PtrSemanticsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.pe = os.path.join(cls.tmp, 'p.exe')
        rdata = bytearray(RDATA_SIZE)
        cls.idx0, cls.rva0 = 5, func_rva(1)
        cls.idx1, cls.rva1 = 9, func_rva(2)
        struct.pack_into('<Q', rdata, TABLE_SEC_OFF + cls.idx0 * 8,
                         IMAGE_BASE + cls.rva0)
        struct.pack_into('<Q', rdata, TABLE_SEC_OFF + cls.idx1 * 8,
                         IMAGE_BASE + cls.rva1)
        with open(cls.pe, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=IL2CPP_VA, data=b'\x90' * IL2CPP_SIZE,
                     chars=CHARS_CODE),
                dict(name='.rdata', va=RDATA_VA, data=bytes(rdata), chars=CHARS_RODATA),
            ], image_base=IMAGE_BASE))
        cls.rdata_off = pe_utils.load_pe(cls.pe).section_by_name('.rdata').raw_ptr

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_converges(self):
        code, text = run_main(ptr_semantics, [
            '--exe', self.pe,
            '--pair', f'{self.idx0}:0x{self.rva0:X}',
            '--pair', f'{self.idx1}:0x{self.rva1:X}', '--json'])
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['verdict'], '收敛')
        self.assertEqual(info['table_section'], '.rdata')
        self.assertEqual(info['table_base_rva'], pe_utils.hexfmt(RDATA_VA + TABLE_SEC_OFF))

    def test_not_converged_is_nonzero(self):
        """把第 2 对的指针放到一个「下标对不上」的位置 → 基址不收敛。"""
        p = os.path.join(self.tmp, 'p2.exe')
        rdata = bytearray(RDATA_SIZE)
        struct.pack_into('<Q', rdata, TABLE_SEC_OFF + self.idx0 * 8, IMAGE_BASE + self.rva0)
        struct.pack_into('<Q', rdata, TABLE_SEC_OFF + 0x4000, IMAGE_BASE + self.rva1)
        with open(p, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=IL2CPP_VA, data=b'\x90' * IL2CPP_SIZE,
                     chars=CHARS_CODE),
                dict(name='.rdata', va=RDATA_VA, data=bytes(rdata), chars=CHARS_RODATA),
            ], image_base=IMAGE_BASE))
        code, text = run_main(ptr_semantics, [
            '--exe', p, '--pair', f'{self.idx0}:0x{self.rva0:X}',
            '--pair', f'{self.idx1}:0x{self.rva1:X}', '--json'])
        self.assertEqual(code, ptr_semantics.EXIT_NOCONV, text)
        self.assertNotEqual(json.loads(text)['verdict'], '收敛')

    def test_accepts_data_section_only(self):
        """把指针放到 il2cpp（可执行）段里 → 候选被拒绝。"""
        p = os.path.join(self.tmp, 'p3.exe')
        with open(p, 'wb') as fh:
            il2 = bytearray(b'\x90' * IL2CPP_SIZE)
            struct.pack_into('<Q', il2, self.idx0 * 8, IMAGE_BASE + self.rva0)
            fh.write(build_pe([
                dict(name='il2cpp', va=IL2CPP_VA, data=bytes(il2), chars=CHARS_CODE),
                dict(name='.rdata', va=RDATA_VA, data=bytes(RDATA_SIZE),
                     chars=CHARS_RODATA),
            ], image_base=IMAGE_BASE))
        code, text = run_main(ptr_semantics, [
            '--exe', p, '--pair', f'{self.idx0}:0x{self.rva0:X}', '--json'])
        self.assertEqual(code, ptr_semantics.EXIT_NOCONV, text)
        self.assertTrue(json.loads(text)['rejected_reasons'])


class DumpRvaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.pe = os.path.join(cls.tmp, 'c.exe')
        il2 = bytearray(b'\x90' * IL2CPP_SIZE)
        cls.call_site = IL2CPP_VA + 0x2000
        cls.call_target = func_rva(1)
        rel = cls.call_target - (cls.call_site + 5)
        off = cls.call_site - IL2CPP_VA
        il2[off:off + 5] = b'\xE8' + struct.pack('<i', rel)
        with open(cls.pe, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=IL2CPP_VA, data=bytes(il2), chars=CHARS_CODE),
            ], image_base=IMAGE_BASE))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_find_call_defaults_to_il2cpp(self):
        code, text = run_main(dump_rva, [
            '--exe', self.pe, '--find-call', hex(self.call_target), '--json'])
        self.assertEqual(code, 0, text)
        self.assertIn('不可见', combined(text))   # 明确写出「间接调用不可见」

    def test_back_is_clamped(self):
        """--back 超过段首必须夹取，不能读出越界字节（旧实现会算出负偏移）。"""
        code, text = run_main(dump_rva, [
            '--exe', self.pe, '--rva', hex(IL2CPP_VA), '--back', '100000'])
        self.assertEqual(code, 0, text)

    def test_rva_not_mapped_is_nonzero(self):
        code, _ = run_main(dump_rva, ['--exe', self.pe, '--rva', '0x900000'])
        self.assertEqual(code, dump_rva.EXIT_NOT_FOUND)

    def test_len_is_instruction_count(self):
        code, text = run_main(dump_rva, [
            '--exe', self.pe, '--rva', hex(func_rva(3)), '--len', '3'])
        self.assertEqual(code, 0, text)
        self.assertIn('0x', text)


class XrefTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.pe = os.path.join(cls.tmp, 'x.exe')
        il2 = bytearray(b'\x90' * IL2CPP_SIZE)
        cls.call_site = IL2CPP_VA + 0x1000
        cls.call_target = func_rva(4)
        rel = cls.call_target - (cls.call_site + 5)
        off = cls.call_site - IL2CPP_VA
        il2[off:off + 5] = b'\xE8' + struct.pack('<i', rel)
        with open(cls.pe, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=IL2CPP_VA, data=bytes(il2), chars=CHARS_CODE),
            ], image_base=IMAGE_BASE))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_finds_call(self):
        code, text = run_main(xref, [
            '--exe', self.pe, '--only', 'il2cpp', '--rva', 'T=0x%X' % self.call_target,
            '--json'])
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['targets'][0]['hit_count'], 1)
        self.assertEqual(info['targets'][0]['hits'][0]['rva'], self.call_site)
        self.assertIn('不可见', info['caveat'])

    def test_target_outside_sections_is_nonzero(self):
        code, _ = run_main(xref, [
            '--exe', self.pe, '--only', 'il2cpp', '--rva', 'T=0x900000'])
        self.assertEqual(code, xref.EXIT_BAD_TARGET)


class ReadStrTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = cls._tmp.name
        cls.pe = os.path.join(cls.tmp, 's.exe')
        rdata = bytearray(RDATA_SIZE)
        cls.short_rva = RDATA_VA + 0x800
        rdata[0x800:0x800 + 17] = b'cri_ware_unity\x00\x00'
        cls.long_rva = RDATA_VA + 0x900
        rdata[0x900:0x900 + 200] = b'A' * 199 + b'\x00'
        cls.bad_rva = RDATA_VA + 0xA00
        rdata[0xA00:0xA06] = b'\xff\xfe\xfd\xfc\x00\x00'
        with open(cls.pe, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=IL2CPP_VA, data=b'\x90' * IL2CPP_SIZE,
                     chars=CHARS_CODE),
                dict(name='.rdata', va=RDATA_VA, data=bytes(rdata), chars=CHARS_RODATA),
            ], image_base=IMAGE_BASE))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_short_string(self):
        code, text = run_main(read_str, ['--exe', self.pe, '--rva', hex(self.short_rva)])
        self.assertEqual(code, 0, text)
        self.assertIn('cri_ware_unity', text)
        self.assertIn('[UTF-8]', text)

    def test_long_string_is_extended_not_truncated(self):
        code, text = run_main(read_str, [
            '--exe', self.pe, '--rva', hex(self.long_rva), '--len', '32'])
        self.assertEqual(code, 0, text)
        self.assertIn('已自动扩展', text)
        self.assertIn('199', text)

    def test_decode_failure_visible_and_nonzero(self):
        code, text = run_main(read_str, ['--exe', self.pe, '--rva', hex(self.bad_rva)])
        self.assertEqual(code, read_str.EXIT_FAIL, text)
        self.assertIn('UTF-8 解码失败', text)

    def test_bad_rva_nonzero(self):
        code, _ = run_main(read_str, ['--exe', self.pe, '--rva', '0x900000'])
        self.assertEqual(code, read_str.EXIT_FAIL)

    def test_len_zero_rejected(self):
        """旧实现把 --len 0 悄悄当成 96。"""
        code, _ = run_main(read_str, ['--exe', self.pe, '--rva', hex(self.short_rva),
                                      '--len', '0'])
        self.assertEqual(code, read_str.EXIT_PARAM)

    def test_no_terminator_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'n.exe')
            rdata = bytearray(b'B' * 0x200)
            with open(p, 'wb') as fh:
                fh.write(build_pe([
                    dict(name='.rdata', va=RDATA_VA, data=bytes(rdata), chars=CHARS_RODATA),
                ], image_base=IMAGE_BASE))
            code, text = run_main(read_str, ['--exe', p, '--rva', hex(RDATA_VA),
                                             '--len', '16', '--scan-max', '32'])
            self.assertEqual(code, read_str.EXIT_FAIL, text)
            self.assertIn('没有结尾 NUL', text)


if __name__ == '__main__':
    unittest.main()
