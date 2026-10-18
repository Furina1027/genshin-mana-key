#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""update_rva.py 的纯函数：常量读写（唯一会改源码的一步）+ 多候选消歧。

真正的 RVA 迁移需要两代 exe，本机造不出来（7.0 也没有同一条加密链路），所以这里只钉住
两块"写错就很难发现"的逻辑：
  · 只改目标常量集（Cn / Gl 不许串），值统一写成 8 位十六进制，注释与其它字段原样保留；
  · 写源码前必须留备份；没有变化时不许乱写、也不许产生备份；
  · 多个候选时**绝不自动猜**：只提示"离 NF 位移最近"，最终必须人来选（7.0↔7.1 实测里
    正确与错误候选的位移差只有 1 KB 量级，机器分不出来）。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import update_rva  # noqa: E402

SAMPLE_SRC = '''namespace GenshinSniffer;

internal static class Application {

    private sealed class RvaSet {
        public string Name = "";
        public uint SetVideoAudioKeys;
        public uint NativeSetFile;
    }

    private static readonly RvaSet Cn = new() {
        Name = "国服 YuanShen.exe 7.1",
        SetVideoAudioKeys = 0x070546F0,
        NativeSetFile = 0x070538C0,            // ★ 文件名来源
    };

    private static readonly RvaSet Gl = new() {
        Name = "国际服 GenshinImpact.exe",
        SetVideoAudioKeys = 0x070515D0,
        NativeSetFile = 0x070507A0,
    };
}
'''


class ConstantsTest(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, 'Application.cs')
        with open(self.path, 'w', encoding='utf-8', newline='') as fh:
            fh.write(SAMPLE_SRC)

    def tearDown(self):
        self._tmp.cleanup()

    def _text(self) -> str:
        with open(self.path, 'r', encoding='utf-8') as fh:
            return fh.read()

    def test_detect_server_by_exe_name(self):
        self.assertEqual(update_rva.detect_server(r'D:\g\YuanShen.exe'), 'Cn')
        self.assertEqual(update_rva.detect_server(r'D:\g\GenshinImpact.exe'), 'Gl')

    def test_read_constants_splits_the_two_sets(self):
        cn = update_rva.read_constants(self.path, 'Cn')
        gl = update_rva.read_constants(self.path, 'Gl')
        self.assertEqual(cn['SetVideoAudioKeys'], 0x070546F0)
        self.assertEqual(cn['NativeSetFile'], 0x070538C0)
        self.assertEqual(gl['SetVideoAudioKeys'], 0x070515D0)
        self.assertEqual(gl['NativeSetFile'], 0x070507A0)
        self.assertNotIn('Name', cn)          # 字符串字段不是 RVA，不能被当成常量
        self.assertNotIn('RvaSet', cn)

    def test_read_constants_rejects_unknown_set(self):
        with self.assertRaises(SystemExit):
            update_rva.read_constants(self.path, 'Nope')

    def test_write_constants_touches_only_the_target_set(self):
        changed, backup = update_rva.write_constants(self.path, 'Cn',
                                                     {'NativeSetFile': 0x07060000,
                                                      'SetVideoAudioKeys': 0x070546F0})  # 第二项没变
        self.assertEqual(changed, [('NativeSetFile', 0x070538C0, 0x07060000)])
        self.assertTrue(backup and os.path.exists(backup))
        text = self._text()
        self.assertIn('NativeSetFile = 0x07060000', text)      # 8 位十六进制
        self.assertIn('NativeSetFile = 0x070507A0', text)      # 国际服不许被改
        self.assertIn('SetVideoAudioKeys = 0x070546F0', text)
        self.assertIn('★ 文件名来源', text)                     # 行尾注释保留
        self.assertEqual(update_rva.read_constants(self.path, 'Cn')['NativeSetFile'],
                         0x07060000)

    def test_write_constants_backs_up_before_touching(self):
        _, backup = update_rva.write_constants(self.path, 'Cn', {'NativeSetFile': 0x07060000})
        self.assertTrue(backup and os.path.exists(backup))
        baks = [f for f in os.listdir(self._tmp.name) if '.bak-' in f]
        self.assertEqual(len(baks), 1, baks)
        with open(os.path.join(self._tmp.name, baks[0]), 'r', encoding='utf-8') as fh:
            self.assertIn('NativeSetFile = 0x070538C0', fh.read())

    def test_write_constants_is_a_noop_without_changes(self):
        changed, backup = update_rva.write_constants(self.path, 'Cn',
                                                     {'NativeSetFile': 0x070538C0})
        self.assertEqual(changed, [])
        self.assertIsNone(backup)
        self.assertFalse([f for f in os.listdir(self._tmp.name) if '.bak-' in f])
        self.assertEqual(self._text(), SAMPLE_SRC)


class PickCandidateTest(unittest.TestCase):
    """只收唯一命中；不唯一的必须交给用户选（脚本绝不自动猜）。"""

    def test_unique_hit(self):
        res = {'status': 'ok', 'hits': [{'rva': 0x70538C0, 'delta': 0}]}
        self.assertEqual(update_rva.pick(res), (0x70538C0, '唯一命中'))

    def test_ambiguous_is_never_auto_accepted(self):
        res = {'status': 'ambiguous', 'hit_count': 2,
               'hits': [{'rva': 0x70547F0, 'delta': 0x2A6270},
                        {'rva': 0x7054D00, 'delta': 0x2A8000}]}
        rva, why = update_rva.pick(res)
        self.assertIsNone(rva)
        self.assertIn('不唯一', why)
        self.assertIn('手选', why)

    def test_candidates_are_sorted_by_proximity_to_anchor(self):
        res = {'status': 'ambiguous', 'hit_count': 3,
               'hits': [{'rva': 0x300, 'delta': 0x5000},
                        {'rva': 0x100, 'delta': 0x120},
                        {'rva': 0x200, 'delta': 0x900}]}
        cands = update_rva.candidates(res, anchor_delta=0x100)
        self.assertEqual([c[0] for c in cands], [0x100, 0x200, 0x300])
        self.assertEqual(cands[0][2], 0x20)          # 与锚位移差只用于提示
        self.assertEqual(update_rva.candidates(res, None)[0][2], None)

    def test_not_found_reports_reason(self):
        res = {'status': 'not-found', 'reason': '在目标 exe 里没有任何候选通过验证'}
        rva, why = update_rva.pick(res)
        self.assertIsNone(rva)
        self.assertIn('没有任何候选', why)


if __name__ == '__main__':
    unittest.main()
