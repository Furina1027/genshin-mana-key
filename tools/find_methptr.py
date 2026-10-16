#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""find_methptr.py — 定位 exe 里真正的 methodPointer 表。

思路：methodPointer 表是一大段连续的 8 字节指针，全部指向 il2cpp 段内的函数。
      在文件里扫「连续 N 个 8 字节值都落在 il2cpp 段范围内」的密集区。
      再用官方 CDN 给的已知 RVA（to_int32 / decompress）反查它出现在表的第几项。

用法：
  python find_methptr.py --exe <exe> [--known 0x195DF330=to_int32 ...] [--minrun 2000]
                         [--sections .rdata,.data] [--all-sections] [--json]

修掉的老问题：
  · il2cpp 段缺失时裸 IndexError → 现在显式报错并非 0 退出；
  · 只扫 .rdata/.data/_RDATA → 默认扫**所有非代码段**（可用 --sections 指定）；
  · 用 Python 循环找连续 True 段 → 改成 numpy 差分向量化；
  · 已知符号用线性扫描 → np.flatnonzero；
  · 一个候选都没有时照样 return 0 → 现在非 0。

退出码：0=找到候选；1=没有找到任何候选密集区；2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import sys

try:
    import numpy as np
except ImportError as exc:                       # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。安装：pip install -r tools/requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

import pe_utils

EXIT_OK = 0
EXIT_NONE = 1
EXIT_PARAM = 2


def find_runs(ok: np.ndarray, minrun: int) -> list:
    """向量化求连续 True 段：返回 [(start, end), ...]（end 不含）。"""
    if ok.size == 0:
        return []
    pad = np.zeros(ok.size + 2, dtype=np.int8)
    pad[1:-1] = ok.astype(np.int8)
    diff = np.diff(pad)
    starts = np.flatnonzero(diff == 1)
    ends = np.flatnonzero(diff == -1)
    return [(int(s), int(e)) for s, e in zip(starts, ends) if e - s >= minrun]


@pe_utils.json_aware_main
def main() -> int:
    ap = argparse.ArgumentParser(
        description='在 exe 里找 methodPointer 表（连续指向 il2cpp 段的 8 字节指针）')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--known', action='append', default=[], help='rva=name，可重复')
    ap.add_argument('--minrun', type=int, default=2000, help='连续多少项才算一个表（默认 2000）')
    ap.add_argument('--top', type=int, default=8, help='每个段最多报告几段（默认 8）')
    ap.add_argument('--sections', default='',
                    help='只扫这些段（逗号分隔）；默认扫所有非代码段')
    ap.add_argument('--all-sections', action='store_true', help='连代码段也一起扫')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.minrun < 8 or a.top < 1:
        print('错误：--minrun 必须 >= 8，--top 必须 >= 1', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    # ★ 旧实现 [s for s in secs if s[0] == 'il2cpp'][0] 会裸 IndexError
    try:
        il2 = pe.section_by_name('il2cpp')
    except pe_utils.PEFormatError as exc:
        print(f'错误：{exc}', file=sys.stderr)
        print('      原神的 IL2CPP 代码在 exe 的 il2cpp 段里；这个 exe 里没有该段，'
              '说明它不是原神主模块（或段名变了）。', file=sys.stderr)
        return EXIT_PARAM

    lo_rva, hi_rva = il2.virtual_address, il2.virtual_end
    lo, hi = pe.rva_to_va(lo_rva), pe.rva_to_va(hi_rva)

    if a.sections:
        wanted = [s.strip() for s in a.sections.split(',') if s.strip()]
        scan = []
        for nm in wanted:
            sec = pe.section_by_name(nm, required=False)
            if sec is None:
                print(f'  ⚠ 段 {nm!r} 不存在，跳过（现有段: {", ".join(pe.section_names)}）')
                continue
            if sec.raw_size:
                scan.append(sec)
    elif a.all_sections:
        scan = [s for s in pe.sections if s.raw_size]
    else:
        scan = [s for s in pe.sections if s.raw_size and not s.is_code and not s.executable]

    print(f'{a.exe}\nImageBase=0x{pe.image_base:X}  il2cpp 段 RVA 0x{lo_rva:X}..0x{hi_rva:X}'
          f'（VA 0x{lo:X}..0x{hi:X}）')
    print(f'扫描段: {[s.name for s in scan] or "(无)"}')

    known = []
    for spec in a.known:
        if '=' not in spec:
            print(f'错误：--known 需要 rva=name 形式，收到 {spec!r}', file=sys.stderr)
            return EXIT_PARAM
        hs, nm = spec.split('=', 1)
        try:
            known.append((pe.rva_to_va(pe_utils.parse_int(hs)), nm, pe_utils.parse_int(hs)))
        except (ValueError, pe_utils.RvaError) as exc:
            print(f'错误：--known {spec!r} 无效：{exc}', file=sys.stderr)
            return EXIT_PARAM

    out = dict(exe=a.exe, image_base=pe.image_base,
               il2cpp=dict(rva=lo_rva, end_rva=hi_rva, va=lo, end_va=hi),
               scanned=[s.name for s in scan], candidates=[], known_hits=[])
    found_any = False
    for sec in scan:
        n = sec.raw_size // 8
        if n < a.minrun:
            continue
        q = np.frombuffer(pe.data, dtype='<u8', count=n, offset=sec.raw_ptr)
        ok = (q >= np.uint64(lo)) & (q < np.uint64(hi))
        runs = find_runs(ok, a.minrun)
        if not runs:
            continue
        found_any = True
        for i, j in runs[:a.top]:
            rva = sec.virtual_address + i * 8
            item = dict(section=sec.name, file_offset=sec.raw_ptr + i * 8,
                        rva=rva, entries=j - i, bytes=(j - i) * 8)
            print(f'  [{sec.name}] 连续指针段: 文件偏移 0x{item["file_offset"]:X}  '
                  f'RVA 0x{rva:X}  共 {j - i} 项  (0x{(j - i) * 8:X} B)')
            for target, nm, trva in known:
                hits = np.flatnonzero(q[i:j] == np.uint64(target))
                if hits.size:
                    k = int(hits[0])
                    # 这里能确定的是「已知符号在该密集区里的第 k 项」。若该密集区就是表的
                    # 起点（连续指针区通常正是如此），第 k 项就是全局方法索引 k；但本脚本
                    # 无法证实「密集区 == 表起点」，所以只报密集区起点 RVA 与 k，
                    # 真正的表基址推导交给 locate_hooks.py（它用参照项做自洽性验证）。
                    item.setdefault('known', []).append(
                        dict(name=nm, rva=trva, index_in_run=k, table_rva=rva))
                    print(f'      ★ 已知 {nm} (VA 0x{target:X}) 位于该密集区第 {k} 项'
                          f'（若该区即表起点，则它的全局索引就是 {k}）；'
                          f'密集区起点 RVA 0x{rva:X}')
                    out['known_hits'].append(dict(name=nm, section=sec.name, run_rva=rva,
                                                  index_in_run=k, table_rva=rva))
                else:
                    print(f'      -- 未在该段找到 {nm}')
            out['candidates'].append(item)

    if not found_any:
        print(f'错误：没有找到任何连续 >= {a.minrun} 项都指向 il2cpp 段的密集区。'
              f'（--minrun 太大？段选错了？用 --all-sections 再试）', file=sys.stderr)
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_NONE
    if a.json:
        pe_utils.emit_json(out)
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
