#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""update_rva.py 的纯函数：常量读写（唯一会改源码的一步）+ 多候选消歧 + 版本指纹。

真正的 RVA 迁移需要两代 exe，本机造不出来（7.0 也没有同一条加密链路），所以这里只钉住
几块"写错就很难发现"的逻辑：
  · 只改目标常量集（Cn / Gl 不许串），值统一写成 8 位十六进制，注释与其它字段原样保留；
  · 写源码前必须留备份；没有变化时不许乱写、也不许产生备份；
  · 多个候选时**绝不自动猜**：只提示"离 NF 位移最近"，最终必须人来选（7.0↔7.1 实测里
    正确与错误候选的位移差只有 1 KB 量级，机器分不出来）；
  · **Fingerprint 只在全部常量都迁移成功时才写回**：NF 失败还登记指纹 = "版本对得上、
    地址是旧的"假绿灯，比不登记危险；
  · `--old-rva` 覆盖项（源码里常量为 0 时的救场路径）必须解析得动、非法输入当场退出。

运行：python -m unittest discover -s tools/tests -v
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import update_rva  # noqa: E402
from _synth_pe import CHARS_CODE, build_pe  # noqa: E402

TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(TOOLS_DIR)

#: 源码里两个常量集的写法（与真实 Application.cs 对齐：值一律 0x 字面量，
#: 未登记的指纹写 0x00000000 而不是裸 0 —— FIELD_RE 只认 0x）。
SAMPLE_SRC = '''namespace GenshinSniffer;

internal static class Application {

    private sealed class RvaSet {
        public string Name = "";
        public uint Fingerprint;
        public uint SetVideoAudioKeys;
        public uint NativeSetFile;
    }

    private static readonly RvaSet Cn = new() {
        Name = "国服 YuanShen.exe 7.1",
        Fingerprint = 0xA1B2C3D4,
        SetVideoAudioKeys = 0x070546F0,
        NativeSetFile = 0x070538C0,            // ★ 文件名来源
    };

    private static readonly RvaSet Gl = new() {
        Name = "国际服 GenshinImpact.exe",
        Fingerprint = 0x00000000,
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


class FingerprintFieldTest(unittest.TestCase):
    """Fingerprint 与其它 RVA 字段走同一套正则 —— 但它的值来自 exe 头部 SizeOfHeaders 字节，格式契约要钉死。"""

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

    def test_read_constants_sees_fingerprint_in_both_sets(self):
        self.assertEqual(update_rva.read_constants(self.path, 'Cn')['Fingerprint'],
                         0xA1B2C3D4)
        # 0x00000000（未登记）必须被读成 0，而不是"字段不存在"：
        # 否则国际服永远走"源码是旧格式，跳过指纹登记"，跑一次 update_rva 也补不上。
        gl = update_rva.read_constants(self.path, 'Gl')
        self.assertIn('Fingerprint', gl)
        self.assertEqual(gl['Fingerprint'], 0)

    def test_write_constants_registers_fingerprint_into_zero_slot(self):
        changed, backup = update_rva.write_constants(self.path, 'Gl',
                                                     {'Fingerprint': 0x1234ABCD})
        self.assertEqual(changed, [('Fingerprint', 0, 0x1234ABCD)])
        self.assertTrue(backup)
        text = self._text()
        self.assertIn('Fingerprint = 0x1234ABCD', text)        # 8 位大写十六进制
        self.assertIn('Fingerprint = 0xA1B2C3D4', text)        # 国服那套不许被改
        self.assertEqual(update_rva.read_constants(self.path, 'Gl')['Fingerprint'],
                         0x1234ABCD)

    def test_write_constants_rewrites_fingerprint_only_when_it_changed(self):
        changed, backup = update_rva.write_constants(self.path, 'Cn',
                                                     {'Fingerprint': 0xA1B2C3D4})
        self.assertEqual((changed, backup), ([], None))
        with open(self.path, 'r', encoding='utf-8') as fh:
            self.assertEqual(fh.read(), SAMPLE_SRC)


def _u32(blob: bytearray, off: int, value: int) -> bytes:
    struct.pack_into('<I', blob, off, value)
    return bytes(blob)


class FingerprintLengthTest(unittest.TestCase):
    """指纹长度 = SizeOfHeaders（只有 `[0, SizeOfHeaders)` 在文件与内存镜像里逐字节一致）。"""

    def _blob(self):
        return bytearray(build_pe([dict(name='.text', va=0x1000, data=b'\x90' * 0x200,
                                        chars=CHARS_CODE)]))

    def test_uses_size_of_headers_from_the_image(self):
        blob = bytes(self._blob())
        e_lfanew = struct.unpack_from('<I', blob, 0x3C)[0]
        soh = struct.unpack_from('<I', blob, e_lfanew + 0x54)[0]
        self.assertEqual(update_rva.fingerprint_length(blob), soh)
        # 单节合成 PE 的 SizeOfHeaders 是 0x200（别照抄真实 exe 的 0x400）
        self.assertEqual(soh, 0x200)

    def test_too_short_falls_back(self):
        self.assertEqual(update_rva.fingerprint_length(b'MZ' + b'\x00' * 0x10),
                         update_rva.FINGERPRINT_FALLBACK_BYTES)

    def test_bad_e_lfanew_falls_back(self):
        for bad in (0x10, 0x2000):           # 指向 DOS 头内部 / 超出允许窗口
            blob = self._blob()
            self.assertEqual(update_rva.fingerprint_length(_u32(blob, 0x3C, bad)),
                             update_rva.FINGERPRINT_FALLBACK_BYTES, hex(bad))

    def test_bad_signature_falls_back(self):
        blob = self._blob()
        e_lfanew = struct.unpack_from('<I', bytes(blob), 0x3C)[0]
        self.assertEqual(update_rva.fingerprint_length(_u32(blob, e_lfanew, 0x1234)),
                         update_rva.FINGERPRINT_FALLBACK_BYTES)

    def test_implausible_size_of_headers_falls_back(self):
        blob = self._blob()
        e_lfanew = struct.unpack_from('<I', bytes(blob), 0x3C)[0]
        for bad in (0, 0x80, 0x100000):      # 低于下限 / 高于上限
            self.assertEqual(
                update_rva.fingerprint_length(_u32(self._blob(), e_lfanew + 0x54, bad)),
                update_rva.FINGERPRINT_FALLBACK_BYTES, hex(bad))

    def test_declared_size_is_returned_verbatim_never_clamped(self):
        """声明值原样返回（不夹到实际可读字节）：夹一下就成了"凑一个 CRC"，那是假绿灯。"""
        blob = bytes(self._blob())[:0x300]   # soh=0x200，文件有 0x300 字节
        self.assertEqual(update_rva.fingerprint_length(blob), 0x200)
        blob = bytes(self._blob())[:0x100]   # 头部被截断，但 soh 字段仍读得出 0x200
        self.assertEqual(update_rva.fingerprint_length(blob), 0x200)


class ExeFingerprintTest(unittest.TestCase):
    """exe 指纹 = CRC32(头部 SizeOfHeaders 字节)，zlib 口径。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, 'synth.exe')
        self.blob = build_pe([dict(name='.text', va=0x1000, data=bytes(range(256)) * 8,
                                   chars=CHARS_CODE)])
        with open(self.path, 'wb') as fh:
            fh.write(self.blob)

    def tearDown(self):
        self._tmp.cleanup()

    def test_matches_zlib_over_header_bytes(self):
        self.assertEqual(update_rva.exe_fingerprint(self.path),
                         zlib.crc32(self.blob[:0x200]) & 0xFFFFFFFF)

    def test_is_not_the_whole_file_crc(self):
        """★ 反向回归：整文件（或固定的头 64KB）口径会在内存镜像里算出另一个值。

        加载器只把文件开头 SizeOfHeaders 字节映射到模块基址，其后的段数据在内存里是 0 填充
        或另一段排布 —— 按整文件/头部 64KB 算，DLL 运行时永远算不出同一个数，于是每次启动
        都报"版本指纹不匹配"。这条钉住"别退回那个口径"。
        """
        self.assertNotEqual(update_rva.exe_fingerprint(self.path),
                            zlib.crc32(self.blob) & 0xFFFFFFFF)

    def test_extra_bytes_beyond_size_of_headers_change_nothing(self):
        """SizeOfHeaders 之后的内容不参与指纹（换一版代码段不该改变头部指纹）。"""
        fp_a = update_rva.exe_fingerprint(self.path)
        blob = bytearray(self.blob)
        blob[0x200] = (blob[0x200] + 1) & 0xFF
        with open(self.path, 'wb') as fh:
            fh.write(bytes(blob))
        self.assertEqual(update_rva.exe_fingerprint(self.path), fp_a)

    def test_returns_none_when_declared_header_exceeds_the_file(self):
        """★ 声明比实际可读多 → **算不出来（None）**，绝不夹到文件长度凑一个 CRC。

        与 C# 侧 Application.CheckVersion 同语义（那边跳过校验并打一行日志）：指纹的全部
        意义是"两边算出同一个数"，凑出来的值只会变成永久误报，或者更糟——假绿灯。
        """
        blob = bytearray(self.blob)
        e_lfanew = struct.unpack_from('<I', bytes(blob), 0x3C)[0]
        _u32(blob, e_lfanew + 0x54, 0x2000)         # 声明 0x2000，文件只有 0xA00
        self.assertLess(len(blob), 0x2000)
        with open(self.path, 'wb') as fh:
            fh.write(bytes(blob))
        self.assertIsNone(update_rva.exe_fingerprint(self.path))
        self.assertEqual(update_rva.head_span(self.path), (0x2000, len(blob)))

    def test_never_negative_or_wrapping(self):
        fp = update_rva.exe_fingerprint(self.path)
        self.assertIsInstance(fp, int)
        self.assertTrue(0 <= fp <= 0xFFFFFFFF)

    def test_known_baseline_of_the_cached_exe(self):
        """对拍基线：rva_cache\\YuanShen.exe（当前缓存 = 7.2 国服）SizeOfHeaders=0x400 → 0x88FB991A。

        只在真 exe 存在时断言（0x88FB991A / 0x400 都是这一版客户端的实测值，别在别处写死）；
        其余用例一律用合成 PE 自己的 SizeOfHeaders 推期望值。这条一旦红，说明"源码登记的
        版本"和"缓存里的参照 exe"不是同一版（或是口径又漂了）。

        ⚠ 这是**会随游戏更新变化的锚**：rva_cache 换了，这里和
        `ManaKeyDumper.Tests/VersionGuardTests.Cached_client_header_matches_registered_fingerprint`
        两处期望值要一起换（7.1 时是 0xC66689B9）。
        """
        cached = os.path.join(ROOT, 'rva_cache', 'YuanShen.exe')
        if not os.path.isfile(cached):
            self.skipTest(f'没有 {cached}（rva_cache 不入库，属正常）')
        with open(cached, 'rb') as fh:
            head = fh.read(0x1000)
        self.assertEqual(update_rva.fingerprint_length(head), 0x400)
        self.assertEqual(update_rva.exe_fingerprint(cached), 0x88FB991A)

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            update_rva.exe_fingerprint(os.path.join(self._tmp.name, 'nope.exe'))


class PlanFingerprintTest(unittest.TestCase):
    """指纹写回的**决策**：全部常量迁移成功才登记（防假绿灯）。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, 'new.exe')
        self._write(build_pe([dict(name='.text', va=0x1000, data=b'\x90' * 0x200,
                                   chars=CHARS_CODE)]))
        self.consts = {'Fingerprint': 0x11111111, 'NativeSetFile': 0x70538C0}

    def _write(self, blob):
        with open(self.path, 'wb') as fh:
            fh.write(blob)

    def tearDown(self):
        self._tmp.cleanup()

    def test_registers_when_everything_migrated(self):
        fp, why = update_rva.plan_fingerprint(self.consts, [], ['NativeSetFile'], self.path)
        self.assertIsNotNone(fp)                      # 合成 PE 的头部是完整的 → 算得出来
        self.assertEqual(fp, update_rva.exe_fingerprint(self.path))
        self.assertEqual(why, '')

    def test_no_fingerprint_when_declared_header_exceeds_the_file(self):
        """★ 声明 SizeOfHeaders > 实际可读 → 不登记指纹（也不夹一个值出来）。"""
        blob = bytearray(build_pe([dict(name='.text', va=0x1000, data=b'\x90' * 0x200,
                                        chars=CHARS_CODE)]))
        e_lfanew = struct.unpack_from('<I', bytes(blob), 0x3C)[0]
        self._write(_u32(blob, e_lfanew + 0x54, 0x800))   # 声明 0x800，文件只有 0x400
        fp, why = update_rva.plan_fingerprint(self.consts, [], ['NativeSetFile'], self.path)
        self.assertIsNone(fp)
        self.assertIn('跳过指纹登记', why)
        self.assertIn('SizeOfHeaders=2048', why)

    def test_never_registers_when_a_hook_failed(self):
        """NF 失败 + 新 exe 指纹不同 → 不许写指纹（否则留下"版本对、地址旧"的假绿灯）。"""
        fp, why = update_rva.plan_fingerprint(
            self.consts, [('NativeSetFile', '不唯一（2 个候选，需手选）')],
            ['NativeSetFile'], self.path)
        self.assertIsNone(fp)
        self.assertIn('假绿灯', why)

    def test_skips_old_format_source_without_fingerprint_field(self):
        fp, why = update_rva.plan_fingerprint({'NativeSetFile': 0x70538C0}, [],
                                              ['NativeSetFile'], self.path)
        self.assertIsNone(fp)
        self.assertIn('旧格式', why)

    def test_io_error_is_reported_not_raised(self):
        with mock.patch.object(update_rva, 'exe_fingerprint',
                               side_effect=OSError('boom')):
            fp, why = update_rva.plan_fingerprint(self.consts, [], ['NativeSetFile'],
                                                  self.path)
        self.assertIsNone(fp)
        self.assertIn('boom', why)


class OldRvaOverrideTest(unittest.TestCase):
    """--old-rva：源码里常量是 0（上次迁移失败）时的救场路径。"""

    def test_parses_single_entry(self):
        self.assertEqual(update_rva.parse_old_rva(['NativeSetFile=0x070538C0']),
                         {'NativeSetFile': 0x070538C0})

    def test_parses_multiple_entries_and_prefixless_hex(self):
        out = update_rva.parse_old_rva(['NativeSetFile=0x070538C0', 'Other=70507A0'])
        self.assertEqual(out, {'NativeSetFile': 0x070538C0, 'Other': 0x70507A0})

    def test_last_duplicate_wins(self):
        out = update_rva.parse_old_rva(['NF=0x100', 'NF=0x200'])
        self.assertEqual(out, {'NF': 0x200})

    def test_empty_list_is_empty_dict(self):
        self.assertEqual(update_rva.parse_old_rva([]), {})
        self.assertEqual(update_rva.parse_old_rva(None), {})

    def test_rejects_missing_equals(self):
        with self.assertRaises(SystemExit):
            update_rva.parse_old_rva(['NativeSetFile'])

    def test_rejects_unparsable_value(self):
        with self.assertRaises(SystemExit):
            update_rva.parse_old_rva(['NativeSetFile=0xZZZZ'])

    def test_rejects_zero_and_negative(self):
        # 0 的语义是"该服务器未定位"，拿它当旧 RVA 毫无意义 —— 当场拒绝，别让迁移空转。
        for bad in ('NativeSetFile=0', 'NativeSetFile=0x0', 'NativeSetFile=-1'):
            with self.assertRaises(SystemExit, msg=bad):
                update_rva.parse_old_rva([bad])


class ExitCodeTest(unittest.TestCase):
    """退出码有语义：3 = 已写回但编译失败，绝不能和 1（源码未改）混用。"""

    def test_build_failed_has_its_own_code(self):
        self.assertEqual(update_rva.EXIT_BUILD_FAILED, 3)
        self.assertEqual(len({update_rva.EXIT_OK, update_rva.EXIT_PARTIAL,
                              update_rva.EXIT_PARAM, update_rva.EXIT_BUILD_FAILED}), 4)

    def test_fingerprint_window_bounds(self):
        # 长度不是常量而是 SizeOfHeaders；这三个常量是它的可信区间与兜底值。
        self.assertEqual(update_rva.FINGERPRINT_MAX_BYTES, 0x10000)
        self.assertEqual(update_rva.FINGERPRINT_MIN_BYTES, 0x200)
        self.assertEqual(update_rva.FINGERPRINT_FALLBACK_BYTES, 0x400)
        self.assertTrue(update_rva.FINGERPRINT_MIN_BYTES
                        <= update_rva.FINGERPRINT_FALLBACK_BYTES
                        <= update_rva.FINGERPRINT_MAX_BYTES)


class NoNumpyDependencyTest(unittest.TestCase):
    """迁移链路不许依赖 numpy：requirements.txt 只装 capstone+pefile。"""

    def test_migrate_masked_imports_without_numpy(self):
        code = ('import sys; sys.modules["numpy"] = None; '
                'import migrate_masked; print(migrate_masked.MIN_INSNS)')
        proc = subprocess.run([sys.executable, '-c', code], cwd=TOOLS_DIR,
                            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), str(update_rva.migrate_masked.MIN_INSNS))

    def test_find_direct_calls_reports_missing_numpy(self):
        """缺 numpy 时抛带提示的异常，**不许**静默返回"0 处调用"。"""
        import pe_utils
        fake_pe = mock.Mock(image_base=0x140000000, data=b'\x00' * 0x200)
        fake_sec = mock.Mock(raw_ptr=0, raw_size=0x200, virtual_address=0x1000)
        with mock.patch.dict(sys.modules, {'numpy': None}):
            with self.assertRaises(pe_utils.NumpyMissing) as cm:
                pe_utils.find_direct_calls(fake_pe, fake_sec, [0x1234])
        self.assertIn('numpy', str(cm.exception))


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
