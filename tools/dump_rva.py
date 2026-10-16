#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump_rva.py — 定点反汇编 + 直接调用点查找。

用法：
  python dump_rva.py --exe <exe> --rva 0x6B46620[,0x...] [--len 30] [--back 0]
  python dump_rva.py --exe <exe> --find-call 0x6B46620 [--only il2cpp] [--ctx 4]

  · ``--len`` 是**反汇编指令条数**（不是字节数！旧文档写成字节，实现却按条数截断）；
    想限制字节窗口用 ``--max-bytes``。
  · ``--find-call`` 默认扫 ``il2cpp`` 段（README：原神 IL2CPP 代码在 exe 的 il2cpp 段里），
    可用 ``--only`` 改成别的段；**只找直接 E8 rel32 调用**。
  · ``--back`` 会夹取到段首，不会读出越界字节。
  · 整个 exe 只加载一次（旧实现每个 RVA 都重读一遍几百 MB 的文件）。

退出码：0=正常；1=有请求的 RVA 无法映射（定位失败）；2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import os
import re
import sys

try:
    import numpy as np
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError as exc:                       # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。安装：pip install -r tools/requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

import pe_utils

EXIT_OK = 0
EXIT_NOT_FOUND = 1
EXIT_PARAM = 2

md = Cs(CS_ARCH_X86, CS_MODE_64)


def annotate(ins, base):
    tag = ''
    m = re.search(r'\[rip ([+-]) (0x[0-9a-f]+)\]', ins.op_str)
    if m:
        d = int(m.group(2), 16) * (1 if m.group(1) == '+' else -1)
        va = ins.address + ins.size + d
        tag = f'   -> VA 0x{va:X} (RVA 0x{va - base:X})'
    if ins.mnemonic == 'movabs':
        tag += '   <<< imm64'
    return tag


def dump(pe: pe_utils.PEFile, rva: int, n: int, back: int = 0,
         max_bytes: int = 0x400) -> bool:
    """反汇编 RVA 处 n 条指令（并可向前回看 back 字节）。返回是否成功定位。"""
    try:
        sec = pe.section_of_rva(rva)
        off = pe.rva_to_off(rva)
    except pe_utils.RvaError as exc:
        print(f'  ✗ RVA 0x{rva:X} 无法定位：{exc}')
        return False
    if back < 0:
        print(f'  ✗ --back 不能为负（收到 {back}）')
        return False
    off_in_sec = rva - sec.virtual_address
    back = min(back, off_in_sec)          # ★ 夹取到段首，不再越界
    start_off = off - back
    avail = sec.raw_end - start_off
    window = max(16, min(max_bytes, avail))
    print(f'\n########## {os.path.basename(pe.path)}  RVA 0x{rva:X}  '
          f'(VA 0x{pe.rva_to_va(rva):X})  段 {sec.name} ##########')
    k = 0
    for ins in md.disasm(pe.data[start_off:start_off + window], pe.image_base + rva - back):
        print(f'   0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{annotate(ins, pe.image_base)}')
        k += 1
        if k >= n:
            break
    if k == 0:
        print('   （窗口内没有解出任何指令 —— 可能不是代码或字节不对齐）')
    elif k < n:
        print(f'   （窗口 0x{window:X} B 内只解出 {k} 条指令，少于请求的 {n} 条）')
    return True


def find_call(pe: pe_utils.PEFile, rva: int, sec_names, context: int = 0x90,
              max_show: int = 8) -> bool:
    """找直接 E8 rel32 指向该 RVA 的调用点。返回是否成功定位到目标段。"""
    secs = []
    for nm in sec_names:
        sec = pe.section_by_name(nm, required=False)
        if sec is None:
            print(f'  ⚠ 段 {nm!r} 不存在（现有段: {", ".join(pe.section_names)}）')
            continue
        if sec.raw_size:
            secs.append(sec)
    if not secs:
        print(f'  ✗ 没有任何可扫描的段（--only {",".join(sec_names)}）')
        return False

    hits = {rva: []}
    stats = {'e8_total': 0, 'chunks': 0}
    for sec in secs:
        h, st = pe_utils.find_direct_calls(pe, sec, [rva])
        hits[rva] = sorted(set(hits[rva]) | set(h.get(rva, [])))
        stats['e8_total'] += st['e8_total']
        stats['chunks'] += st['chunks']

    found = hits.get(rva, [])
    names = ','.join(s.name for s in secs)
    print(f'\n########## {os.path.basename(pe.path)}  call RVA 0x{rva:X} '
          f'调用点 ×{len(found)}  （扫描段: {names}，E8 总数 {stats["e8_total"]:,}）##########')
    print('  注意：这里**只**找直接 E8 rel32 调用；间接调用（FF /2）、thunk/跳板、'
          'IAT 与\n        跳转表、lea rip + call reg 全部不可见 ——'
          '「0 处」不等于「确认无调用者」。')
    if not found:
        return True
    for h in found[:max_show]:
        try:
            ho = pe.rva_to_off(h)
            sec = pe.section_of_rva(h)
        except pe_utils.RvaError as exc:
            print(f'   调用点 RVA 0x{h:X} 无法回读：{exc}')
            continue
        back = min(context, h - sec.virtual_address, ho)
        start = ho - back
        print(f'\n  ◆ 调用点 RVA 0x{h:X} (段 {sec.name})')
        for ins in md.disasm(pe.data[start:start + back + 0x20],
                             pe.image_base + h - back):
            mark = '   <<< call target' if ins.address == pe.image_base + h else ''
            print(f'     0x{ins.address:X}: {ins.mnemonic} {ins.op_str}'
                  f'{annotate(ins, pe.image_base)}{mark}')
    if len(found) > max_show:
        print(f'\n  （还有 {len(found) - max_show} 处调用点未打印）')

    # 顺带看看这个 RVA / VA 是否作为 8 字节指针出现在数据段里
    pat8 = rva.to_bytes(8, 'little')
    pata8 = pe.rva_to_va(rva).to_bytes(8, 'little')
    for sec in pe.sections:
        if not sec.raw_size:
            continue
        seg = pe.data[sec.raw_ptr:sec.raw_ptr + sec.raw_size]
        c1, c2 = seg.count(pat8), seg.count(pata8)
        if c1 or c2:
            print(f'   数据段 {sec.name}: RVA字面 ×{c1}  VA字面 ×{c2}')
    return True


def split_rvas(text: str) -> list:
    out = []
    for tok in text.split(','):
        tok = tok.strip()
        if tok:
            out.append(pe_utils.parse_int(tok))
    return out


@pe_utils.json_aware_main
def main() -> int:
    ap = argparse.ArgumentParser(
        description='定点反汇编 / 直接调用点查找（PE 只加载一次）')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--rva', default='', help='要反汇编的 RVA，逗号分隔')
    ap.add_argument('--len', type=int, default=30,
                    help='反汇编**指令条数**（不是字节数；默认 30）')
    ap.add_argument('--max-bytes', type=pe_utils.parse_int, default=0x400,
                    help='反汇编窗口字节上限（默认 0x400）')
    ap.add_argument('--back', type=int, default=0, help='向前回看的字节数（会夹取到段首）')
    ap.add_argument('--find-call', default='', help='找指向该 RVA 的直接调用点，逗号分隔')
    ap.add_argument('--only', default='il2cpp',
                    help='--find-call 扫描的段（逗号分隔，默认 il2cpp）')
    ap.add_argument('--ctx', type=pe_utils.parse_int, default=0x90,
                    help='调用点上下文回看字节数（默认 0x90）')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.len < 1:
        print('错误：--len 必须 >= 1', file=sys.stderr)
        return EXIT_PARAM
    if a.back < 0:
        print('错误：--back 必须 >= 0', file=sys.stderr)
        return EXIT_PARAM
    if not a.rva and not a.find_call:
        print('错误：至少要给 --rva 或 --find-call', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    try:
        rvas = split_rvas(a.rva) if a.rva else []
        calls = split_rvas(a.find_call) if a.find_call else []
    except ValueError as exc:
        print(f'错误：{exc}', file=sys.stderr)
        return EXIT_PARAM

    ok = True
    caveat = ('只找直接 E8 rel32 调用；间接调用（FF /2）、thunk/跳板、IAT、跳转表、'
              'lea rip + call reg 全部不可见 —— 「0 处调用」不等于「确认无调用者」')
    result = dict(exe=a.exe, image_base=pe.image_base, disassembly=[], calls=[],
                  caveat=caveat)
    if a.json:
        result['sections'] = pe.section_names
    for rva in rvas:
        sec = pe.section_of_rva(rva, required=False)
        ok = dump(pe, rva, a.len, a.back, a.max_bytes) and ok
        result['disassembly'].append(dict(rva=rva, section=sec.name if sec else None))
    for rva in calls:
        ok = find_call(pe, rva, [s.strip() for s in a.only.split(',') if s.strip()],
                       a.ctx) and ok
        result['calls'].append(dict(rva=rva))
    if a.json:
        pe_utils.emit_json(result)
    return EXIT_OK if ok else EXIT_NOT_FOUND


if __name__ == '__main__':
    raise SystemExit(main())
