#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""align_class / migrate_masked / pdata 的合成 PE 端到端测试。

用 _synth_pe 造两个「同一份代码、不同布局」的 PE：
  · src：函数在 RVA 0x1000
  · dst：同样的函数在另一个 RVA（且 rip 相对位移被改掉 → 只有掩码指纹能匹配）
再配一个 `.pdata` 描述函数边界、一个 methodPointer 表，验证：
  · migrate_masked 能唯一迁移，且**按 .pdata 截断**（短函数不许硬凑指纹）；
  · 两个候选时不唯一 → 非 0 退出；
  · align_class 用全局分配对齐（没有 scipy 时退化为「互相最优」）、能报出 7.1 新增、
    base71 sanity gate 不通过时非 0 退出。

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

import align_class  # noqa: E402
import migrate_masked  # noqa: E402
import pdata  # noqa: E402
import pe_utils  # noqa: E402
from _synth_pe import CHARS_CODE, CHARS_RODATA, build_pe  # noqa: E402

IMAGE_BASE = 0x140000000

# 8 条「无 imm/disp」的指令：这些字节构成指纹里最长的连续非通配锚
SOLID = bytes.fromhex('4889C1' '4889D8' '4839C8' '85C0'
                      '4889C2' '4889CE' '4889F8' '4831C0')


def make_func_bytes(disp: int) -> bytes:
    """12+ 条指令的函数体；两处 rip 相对 disp32 随布局变化。"""
    return (bytes.fromhex('4883EC28')            # sub rsp, 0x28        (imm8)
            + b'\x48\x8B\x05' + struct.pack('<I', disp)   # mov rax,[rip+d] (disp32)
            + bytes.fromhex('4889442420')        # mov [rsp+0x20], rax  (disp8)
            + b'\x8B\x0D' + struct.pack('<I', disp ^ 0x40)  # mov ecx,[rip+d]
            + SOLID
            + bytes.fromhex('4883C428')          # add rsp, 0x28        (imm8)
            + b'\xC3')                           # ret


SHORT_FUNC = bytes.fromhex('4889C1 4889D8 4839C8')      # 3 条指令
TAIL_CODE = bytes.fromhex('4889C2 4889CE 4889F8 4831C0 4889C1 4889D8 4839C8 85C0')


def pdata_blob(entries) -> bytes:
    """.pdata：每项 12 字节 (BeginAddress, EndAddress, UnwindInfoAddress)。"""
    return b''.join(struct.pack('<III', b, e, u) for b, e, u in entries)


def run_main(mod, argv):
    buf = io.StringIO()
    old = sys.argv
    sys.argv = [mod.__name__] + list(argv)
    try:
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            code = mod.main()
    finally:
        sys.argv = old
    return code, buf.getvalue()


class MigrateMaskedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = cls._tmp.name
        src_code = make_func_bytes(0x11111111)
        dst_code = make_func_bytes(0x22222222)      # 位移不同 → 原始字节不同

        cls.src = os.path.join(tmp, 'src.exe')
        cls.dst = os.path.join(tmp, 'dst.exe')
        code_va, pdata_va = 0x1000, 0x2000
        with open(cls.src, 'wb') as fh:
            fh.write(build_pe([
                dict(name='.text', va=code_va, data=src_code, chars=CHARS_CODE),
                dict(name='.pdata', va=pdata_va,
                     data=pdata_blob([(code_va, code_va + len(src_code), 0)])),
            ], image_base=IMAGE_BASE))

        # dst：函数放在 .text 偏移 0x40 处；另外造一份只有单个副本的 dst_u（唯一解用例）
        text = bytearray(b'\x90' * 0x200)
        text[0x40:0x40 + len(dst_code)] = dst_code
        text[0x100:0x100 + len(dst_code)] = dst_code
        text = bytes(text)
        cls.dst_func_off = 0x40
        cls.dst_func_rva = code_va + 0x40
        cls.dst_func2_rva = code_va + 0x100
        with open(cls.dst, 'wb') as fh:
            fh.write(build_pe([
                dict(name='.text', va=code_va, data=text, chars=CHARS_CODE),
                dict(name='.pdata', va=pdata_va, data=pdata_blob([
                    (code_va + 0x40, code_va + 0x40 + len(dst_code), 0),
                    (code_va + 0x100, code_va + 0x100 + len(dst_code), 0)])),
            ], image_base=IMAGE_BASE))

        cls.dst_u = os.path.join(tmp, 'dst_unique.exe')
        with open(cls.dst_u, 'wb') as fh:
            fh.write(build_pe([
                dict(name='.text', va=code_va, data=text[:0x100], chars=CHARS_CODE),
                dict(name='.pdata', va=pdata_va, data=pdata_blob([
                    (code_va + 0x40, code_va + 0x40 + len(dst_code), 0)])),
            ], image_base=IMAGE_BASE))

        # 短函数 + 紧跟更多代码：用来证明「按 .pdata 截断」
        cls.src2 = os.path.join(tmp, 'src2.exe')
        cls.dst2 = os.path.join(tmp, 'dst2.exe')
        with open(cls.src2, 'wb') as fh:
            fh.write(build_pe([
                dict(name='.text', va=code_va, data=SHORT_FUNC + TAIL_CODE,
                     chars=CHARS_CODE),
                dict(name='.pdata', va=pdata_va,
                     data=pdata_blob([(code_va, code_va + len(SHORT_FUNC), 0)])),
            ], image_base=IMAGE_BASE))
        with open(cls.dst2, 'wb') as fh:
            fh.write(build_pe([
                dict(name='.text', va=code_va, data=SHORT_FUNC + TAIL_CODE,
                     chars=CHARS_CODE),
                dict(name='.pdata', va=pdata_va,
                     data=pdata_blob([(code_va, code_va + len(SHORT_FUNC), 0)])),
            ], image_base=IMAGE_BASE))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_unique_migration_via_mask(self):
        code, text = run_main(migrate_masked, [
            '--src', self.src, '--dst', self.dst_u,
            '--rva', 'F=0x1000', '--json'])
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['resolved']['F'], self.dst_func_rva)
        r = info['results'][0]
        self.assertEqual(r['status'], 'ok')
        self.assertGreaterEqual(r['insns'], migrate_masked.MIN_INSNS)
        self.assertEqual(r['hits'][0]['dst_function_start'], self.dst_func_rva)

    def test_ambiguous_is_nonzero(self):
        """dst 里有两份同样的代码 → 不唯一，必须非 0 退出。"""
        code, text = run_main(migrate_masked, [
            '--src', self.src, '--dst', self.dst, '--rva', 'F=0x1000', '--json'])
        self.assertEqual(code, migrate_masked.EXIT_AMBIGUOUS, text)
        info = json.loads(text)
        self.assertEqual(info['results'][0]['status'], 'ambiguous')
        self.assertEqual(info['results'][0]['hit_count'], 2)

    def test_fingerprint_truncated_by_pdata(self):
        """短函数必须因为 .pdata 边界而凑不出指纹（旧实现会一路反汇编到别的函数里）。"""
        code, text = run_main(migrate_masked, [
            '--src', self.src2, '--dst', self.dst2, '--rva', 'S=0x1000', '--json'])
        self.assertEqual(code, migrate_masked.EXIT_AMBIGUOUS, text)
        info = json.loads(text)
        self.assertEqual(info['results'][0]['status'], 'no-fingerprint')
        self.assertEqual(info['results'][0]['insns'], 3)

    def test_bad_rva_reports_error(self):
        code, text = run_main(migrate_masked, [
            '--src', self.src, '--dst', self.dst, '--rva', 'F=0x900000', '--json'])
        self.assertEqual(code, migrate_masked.EXIT_AMBIGUOUS, text)
        self.assertEqual(json.loads(text)['results'][0]['status'], 'error')


class PdataTest(unittest.TestCase):
    def test_bounds_and_slice_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'a.exe')
            with open(p, 'wb') as fh:
                fh.write(build_pe([
                    dict(name='.text', va=0x1000, data=b'\x90' * 0x400, chars=CHARS_CODE),
                    dict(name='.pdata', va=0x2000, data=pdata_blob([
                        (0x1000, 0x1040, 0x3000),
                        (0x1040, 0x1100, 0x3000)])),
                ], image_base=IMAGE_BASE))
            pe = pe_utils.load_pe(p)
            fb = pdata.load_function_bounds(pe)
            self.assertEqual(len(fb), 2)
            self.assertEqual(fb.end_of(0x1020), 0x1040)
            self.assertEqual(fb.slice_limit(0x1020, 0x400), 0x20)
            self.assertEqual(fb.slice_limit(0x900000, 0x400), 0x400)
            self.assertEqual([b.start for b in fb.in_range(0x1000, 0x1050)], [0x1000, 0x1040])

    def test_missing_pdata(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'b.exe')
            with open(p, 'wb') as fh:
                fh.write(build_pe([dict(name='.text', va=0x1000, data=b'\x90' * 0x10,
                                        chars=CHARS_CODE)], image_base=IMAGE_BASE))
            pe = pe_utils.load_pe(p)
            self.assertIsNone(pdata.load_function_bounds(pe))
            with self.assertRaises(pe_utils.PEFormatError):
                pdata.load_function_bounds(pe, required=True)
            code, _ = run_main(pdata, ['--exe', p, '--count'])
            self.assertEqual(code, pdata.EXIT_PARAM)

    def test_pdata_cli_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, 'c.exe')
            with open(p, 'wb') as fh:
                fh.write(build_pe([
                    dict(name='.text', va=0x1000, data=b'\x90' * 0x400, chars=CHARS_CODE),
                    dict(name='.pdata', va=0x2000, data=pdata_blob([
                        (0x1000, 0x1040, 0x2010), (0x1040, 0x1100, 0x999999)])),
                ], image_base=IMAGE_BASE))
            code, text = run_main(pdata, ['--exe', p, '--list', '0x1000', '0x1100', '--json'])
            self.assertEqual(code, 0, text)
            info = json.loads(text)
            self.assertEqual(info['pdata']['entries'], 2)
            self.assertEqual(info['pdata']['unwind_out_of_image'], 1)
            self.assertEqual(len(info['functions']), 2)


class AlignClassTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        tmp = cls._tmp.name
        # 7.0：三个方法
        cls.f70 = [make_func_bytes(0x1111 + i) for i in range(3)]
        cls.rva70 = [0x1000, 0x1400, 0x1800]
        cls.exe70 = os.path.join(tmp, 'exe70.exe')
        text70 = bytearray(0x2000)
        for rva, code in zip(cls.rva70, cls.f70):
            off = rva - 0x1000
            text70[off:off + len(code)] = code
        with open(cls.exe70, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=0x1000, data=bytes(text70), chars=CHARS_CODE),
            ], image_base=IMAGE_BASE))

        # 7.1：同样的三个方法（位移不同）+ 一个全新的方法
        cls.f71 = [make_func_bytes(0x777 + i) for i in range(3)]
        cls.new71 = bytes.fromhex('554889E5' * 4 + '5DC3' + '90' * 6)
        cls.rva71 = [0x2000, 0x2400, 0x2800]
        cls.rva_new = 0x2C00
        text71 = bytearray(0x3000)
        for rva, code in list(zip(cls.rva71, cls.f71)) + [(cls.rva_new, cls.new71)]:
            off = rva - 0x1000
            text71[off:off + len(code)] = code

        # methodPointer 表：索引 700..710，只有 700..703 非空
        table = bytearray(800 * 8)
        for k, rva in enumerate(cls.rva71 + [cls.rva_new]):
            struct.pack_into('<Q', table, (700 + k) * 8, IMAGE_BASE + rva)
        cls.exe71 = os.path.join(tmp, 'exe71.exe')
        with open(cls.exe71, 'wb') as fh:
            fh.write(build_pe([
                dict(name='il2cpp', va=0x1000, data=bytes(text71), chars=CHARS_CODE),
                dict(name='.rdata', va=0x10000, data=bytes(table), chars=CHARS_RODATA),
            ], image_base=IMAGE_BASE))
        cls.rdata_off = pe_utils.load_pe(cls.exe71).section_by_name('.rdata').raw_ptr

        # dump70.cs
        cls.dump = os.path.join(tmp, 'dump70.cs')
        with open(cls.dump, 'w', encoding='utf-8') as fh:
            fh.write('// TypeDefIndex: 100\n')
            fh.write('class CriWare.CriMana.Player\n{\n')
            for k, rva in enumerate(cls.rva70):
                fh.write(f'    public void M{k}(); // idx {700 + k} RVA 0x{rva:X}\n')
            fh.write('}\n// TypeDefIndex: 101\nclass Other\n{\n}\n')

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _argv(self, **kw):
        argv = ['--dump70', self.dump, '--exe70', self.exe70, '--exe71', self.exe71,
                '--class', 'CriWare.CriMana.Player', '--idx71', '700:710',
                '--base71', hex(self.rdata_off), '--json']
        return argv

    @unittest.skipUnless(align_class.HAVE_SCIPY,
                         'scipy 是可选依赖（CI 只装 requirements.txt 里四个固定依赖）：'
                         '「全局最优先找齐全部 3 对」这组断言只在它可用时有意义')
    def test_alignment_finds_new_method(self):
        code, text = run_main(align_class, self._argv())
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['methods71'], 4)
        self.assertEqual(info['matcher'], 'scipy.linear_sum_assignment')
        self.assertEqual(len(info['matched']), 3)
        pairs = {m['idx70']: m['rva71'] for m in info['matched']}
        for k, rva in enumerate(self.rva71):
            self.assertEqual(pairs[700 + k], rva)
        self.assertEqual([m['idx71'] for m in info['new_in_71']], [703])
        self.assertEqual(info['unmappable_71'], [])
        self.assertEqual(info['unmatched_70'], [])

    @unittest.skipIf(align_class.HAVE_SCIPY, '装了 scipy 就不会走退化路径')
    def test_alignment_falls_back_without_scipy(self):
        """没有 scipy 时退化到「互相最优」：必须如实上报后端、写出警告，且**不许错配**。

        退化匹配达不到全局最优（同一份合成样本上只能找到 1 对，因此会把 701/702 也当成
        7.1 新增 —— 这正是"有 scipy 就优先用它"的理由），所以这里只断言两条硬约束：
        上报名是 mutual-best + 有警告，以及给出的每一对都是真配对（子集正确）。
        """
        code, text = run_main(align_class, self._argv())
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['matcher'], 'mutual-best')
        self.assertTrue(any('scipy' in w for w in info['warnings']),
                        f'退化时该给出警告，实际 warnings={info["warnings"]}')
        self.assertGreaterEqual(len(info['matched']), 1, '退化匹配至少得找到一对')
        for m in info['matched']:
            self.assertEqual(m['rva71'], self.rva71[m['idx70'] - 700],
                             f'idx70={m["idx70"]} 配错了')

    def test_sanity_gate_rejects_bad_base(self):
        """base71 指到代码段 → 条目几乎都不在 il2cpp 段 → 非 0 退出。"""
        argv = self._argv()
        argv[argv.index('--base71') + 1] = hex(pe_utils.load_pe(self.exe71)
                                               .section_by_name('il2cpp').raw_ptr)
        code, _ = run_main(align_class, argv)
        self.assertEqual(code, align_class.EXIT_UNTRUSTED)

    def test_idx70_filter(self):
        argv = self._argv()
        argv += ['--idx70', '701:702']
        code, text = run_main(align_class, argv)
        self.assertEqual(code, 0, text)
        info = json.loads(text)
        self.assertEqual(info['methods70'], 2)

    def test_empty_class_is_param_error(self):
        code, _ = run_main(align_class, ['--dump70', self.dump, '--exe70', self.exe70,
                                         '--exe71', self.exe71, '--class', 'No.Such.Class'])
        self.assertEqual(code, align_class.EXIT_PARAM)


if __name__ == '__main__':
    unittest.main()
