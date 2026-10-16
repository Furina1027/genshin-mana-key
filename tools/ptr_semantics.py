#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ptr_semantics.py — 验证「指针数组下标 == dump 的全局方法索引」。

输入若干 (idx, rva) 对（来自 dump70.cs），在 exe 里找该函数 VA 的存放位置，
再检查 (offset - idx*8) 是否收敛到同一个基址 → 是则数组即 methodPointer 表。

修掉的老问题：旧实现把**每一个出现位置**都算成一个候选基址塞进 Counter 里，
于是「一个随机出现在别处的相同 VA」就被当成了证据，Counter 被污染、结论不可信。
现在每个候选基址都要过一套接受/拒绝判据（对齐、属于数据段、下标不越界、非负），
只有**被所有输入对共同支持**的基址才判定为「收敛」。

用法：
  python ptr_semantics.py --exe <exe> --pair 1357:0x195DF330 --pair 83127:0x6DAB600 [...] [--json]

退出码：0=收敛（该数组即 methodPointer 表）；1=不收敛/证据不足；2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict

import pe_utils

EXIT_OK = 0
EXIT_NOCONV = 1
EXIT_PARAM = 2


def judge(pe: pe_utils.PEFile, base: int, idx: int, slot_size: int = 8):
    """判断一个「隐含表基址」是否可信。返回 (是否接受, 理由)。"""
    if base < 0:
        return False, '基址为负'
    if base % slot_size:
        return False, f'基址未按 {slot_size} 字节对齐'
    sec = pe.section_of_off(base, required=False)
    if sec is None:
        return False, '基址不落在任何段的文件范围内'
    if sec.is_code or sec.executable:
        return False, f'基址落在代码段 {sec.name}（表应该在数据段）'
    if base + (idx + 1) * slot_size > sec.raw_end:
        return False, f'基址 + {idx + 1} 项越出段 {sec.name} 的原始范围'
    return True, f'接受：段 {sec.name}'


def main() -> int:
    ap = argparse.ArgumentParser(
        description='验证「指针数组下标 == 全局方法索引」（带接受/拒绝判据）')
    ap.add_argument('--exe', required=True)
    ap.add_argument('--pair', action='append', required=True, help='idx:rva')
    ap.add_argument('--max-occ', type=int, default=8, help='每对最多考察几个出现位置（默认 8）')
    ap.add_argument('--min-agree', type=int, default=0,
                    help='至少多少对输入支持同一个基址才算收敛（默认=全部门数）')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.max_occ < 1:
        print('错误：--max-occ 必须 >= 1', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(a.exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    pairs = []
    for spec in a.pair:
        if ':' not in spec:
            print(f'错误：--pair 需要 idx:rva 形式，收到 {spec!r}', file=sys.stderr)
            return EXIT_PARAM
        hs, rs = spec.split(':', 1)
        try:
            pairs.append((pe_utils.parse_int(hs), pe_utils.parse_int(rs)))
        except ValueError as exc:
            print(f'错误：--pair {spec!r} 无效：{exc}', file=sys.stderr)
            return EXIT_PARAM

    min_agree = a.min_agree or len(pairs)
    out = dict(exe=a.exe, image_base=pe.image_base, pairs=[],
               accepted_bases={}, rejected_reasons={}, verdict='不收敛')
    if not a.json:
        print(f'{a.exe}  ImageBase=0x{pe.image_base:X}')
        for s in pe.sections:
            print(f'   {s.name:10} VA 0x{s.virtual_address:08X}  '
                  f'VSize 0x{s.virtual_size:08X}  Raw 0x{s.raw_size:08X} @0x{s.raw_ptr:X}')

    support = defaultdict(set)          # base -> {pair_index}
    accepted_count = Counter()
    rejected = Counter()
    for pi, (idx, rva) in enumerate(pairs):
        va = pe.rva_to_va(rva)
        pat = va.to_bytes(8, 'little')
        occ = []
        o = pe.data.find(pat)
        while o >= 0:
            occ.append(o)
            o = pe.data.find(pat, o + 1)
        entry = dict(idx=idx, rva=rva, va=va, occurrences=len(occ),
                     considered=min(len(occ), a.max_occ), candidates=[])
        if not a.json:
            print(f'\n[{idx:>7}] RVA 0x{rva:X}  VA 0x{va:X}  出现 {len(occ)} 次'
                  f'（只考察前 {min(len(occ), a.max_occ)} 个）')
        if not occ:
            entry['candidates'].append(dict(reason='该 VA 在文件里一次都没出现'))
            rejected['该 VA 在文件里一次都没出现'] += 1
            out['pairs'].append(entry)
            continue
        for o in occ[:a.max_occ]:
            base = o - idx * 8
            ok, reason = judge(pe, base, idx)
            cand = dict(occurrence=o, implied_base=base, implied_base_hex=pe_utils.hexfmt(base),
                        accepted=ok, reason=reason)
            entry['candidates'].append(cand)
            if ok:
                support[base].add(pi)
                accepted_count[base] += 1
                sec = pe.section_of_off(base)
                cand['section'] = sec.name
                if not a.json:
                    print(f'      文件 0x{o:X}  → 基址 {pe_utils.hexfmt(base)}  '
                          f'✅ {reason}')
            else:
                rejected[reason] += 1
                if not a.json:
                    print(f'      文件 0x{o:X}  → 基址 {pe_utils.hexfmt(base)}  '
                          f'❌ {reason}（已拒绝，不参与统计）')
        out['pairs'].append(entry)

    out['accepted_bases'] = {pe_utils.hexfmt(b): dict(
        support_pairs=len(support[b]), accepted_occurrences=accepted_count[b])
        for b in support}
    out['rejected_reasons'] = dict(rejected)

    if support:
        ranked = sorted(support.items(), key=lambda kv: (-len(kv[1]), -accepted_count[kv[0]]))
        best_base, best_support = ranked[0]
        tied = [b for b, s in ranked if len(s) == len(best_support) and b != best_base]
        if not a.json:
            print('\n== 隐含基址统计（只统计通过的候选）==')
            for b, s in ranked[:6]:
                sec = pe.section_of_off(b, required=False)
                print(f'   {pe_utils.hexfmt(b)}  被 {len(s)}/{len(pairs)} 对支持  '
                      f'（{accepted_count[b]} 个出现位置）  段 {sec.name if sec else "?"}')
        if len(best_support) >= min_agree and not tied:
            out['verdict'] = '收敛'
            out['table_base'] = pe_utils.hexfmt(best_base)
            out['table_base_rva'] = pe_utils.hexfmt(pe.off_to_rva(best_base))
            out['table_section'] = pe.section_of_off(best_base).name
            if not a.json:
                print(f'\n✅ 收敛：表基址 文件 {pe_utils.hexfmt(best_base)} '
                      f'RVA {out["table_base_rva"]} (段 {out["table_section"]})，'
                      f'被 {len(best_support)}/{len(pairs)} 对支持 → 该数组即 methodPointer 表')
        else:
            out['verdict'] = '不收敛' if not tied else '存在并列基址，无法判定'
            if not a.json:
                why = (f'有 {len(tied)} 个基址并列' if tied
                       else f'最好的基址只被 {len(best_support)}/{len(pairs)} 对支持'
                              f'（要求 >= {min_agree}）')
                print(f'\n❌ 不收敛：{why} —— 这些 (idx, rva) 对不能证明「下标==全局方法索引」')
    else:
        out['verdict'] = '不收敛：没有任何候选基址通过判据'
        if not a.json:
            print('\n== 隐含基址统计 ==\n  （没有任何候选基址通过判据：）')
            for r, c in rejected.most_common(6):
                print(f'   拒绝 {c} 次：{r}')
            print('\n❌ 不收敛：没有任何候选基址满足「对齐 + 落在数据段 + 下标不越界」')

    if a.json:
        pe_utils.emit_json(out)
    return EXIT_OK if out['verdict'] == '收敛' else EXIT_NOCONV


if __name__ == '__main__':
    raise SystemExit(main())
