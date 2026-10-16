#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""locate_hooks.py — 由 CDN 下发的 to_int32 RVA 反推 methodPointer 表基址，读表拿 RVA。

方法：
  1. methodPointer 表基址 = (已知函数 VA 的存放文件偏移) − (该函数的全局方法索引)×8。
     `ToInt32` 的全局索引在 7.0/7.1 都记作 1357。
  2. 新版本可能在它前面插入了方法，于是真实索引变成 1357+δ —— `--window` 就是 δ 的
     搜索半径（单位：**索引个数**，默认 0x400）。
  3. 一个 (occurrence, δ) 只有让**全部参照项**（SetFile / NativeMethods_SetFile /
     NativeMethods_EntryFile 等）同时落在 il2cpp 段或可执行节里，才算自洽解；
     自洽解必须唯一，否则报错退出（不猜）。

修掉的老问题：
  · ``occ = [i for i in range(len(data)) ...]`` 那个遍历整个 exe 的空转表达式 → 删除；
  · ``--window`` 解析了从未使用 → 现在真的用它搜索索引平移；
  · ``tbl`` 是**文件偏移**却传给期望 RVA 的函数，打印出的「RVA」其实是文件偏移，
    且越界时 ``f'0x{trva:X}'`` 会因 None 抛 TypeError → 现在语义分开、越界显式报错；
  · ``np.frombuffer(count=n, offset=tbl)`` 越界抛裸 ValueError → 显式校验；
  · 从不验证解析出的 RVA 是否真在 il2cpp 段 → 现在逐条标注。

用法：
  python locate_hooks.py --server cn --exe <YuanShen.exe> [--window 0x400] [--json]
  python locate_hooks.py --exe <exe> --rva 0x195DF330 --idx 1357 --table-base 0x2870C78

退出码：0=唯一自洽解；1=无解或并列解（结果不可信）；2=参数/IO/PE 错误。
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
EXIT_UNTRUSTED = 1
EXIT_PARAM = 2

#: 双服默认参数。exe 只留文件名 —— 本机绝对路径不该进仓库；
#: 数值（to_int32 的 RVA 与全局索引）保持原样不动。
SERVERS = {
    'cn': dict(exe='YuanShen.exe', to_int32=0x195DF330, to_int32_idx=1357),
    'gl': dict(exe='GenshinImpact.exe', to_int32=0x1952CC20, to_int32_idx=1357),
}

# 7.1 CriMana.Player 新增方法的索引（由 7.0↔7.1 指纹序列对齐得到）
TARGETS = [
    (75719, 'SetVideoAudioDecryptionKeys(提钥匙, 托管层)'),
    (75721, 'SetVideoAesKeyAudioDecryptionKey(提钥匙, 托管层)'),
    (75762, 'NativeMethods_SetVideoAudioDecryptionKeys → CRIWARE948D1068'),
    (75763, 'NativeMethods_SetVideoAesKeyAudioDecryptionKey2 → CRIWARE1E4885A8'),
    (75786, '新增#5 ?'),
    (75787, '新增#6 ?'),
    (75745, 'NativeMethods_SetFile（文件名, 参照）'),
    (75746, 'NativeMethods_EntryFile（参照）'),
    (75712, 'SetFile（参照）'),
]

#: 必须成立的参照项（这些方法在 7.0 就存在，7.1 一定还有）
ANCHOR_INDICES = [75712, 75745, 75746]
#: 佐证项（同一 CRI 入口的两个新包装；不强制，但能区分候选）
OPTIONAL_INDICES = [75762, 75763]

MAX_TARGET_IDX = max(i for i, _ in TARGETS)


def plausible_pointer(pe: pe_utils.PEFile, va: int, il2: pe_utils.Section):
    """判断一个表项（VA）是否像「指向 il2cpp/可执行节的函数指针」。"""
    if va == 0:
        return False, '空槽(0)'
    rva = va - pe.image_base
    if rva <= 0:
        return False, f'VA 0x{va:X} 小于 ImageBase（不像指针）'
    sec = pe.section_of_rva(rva, required=False)
    if sec is None:
        return False, f'RVA 0x{rva:X} 不属于任何段'
    if il2 is not None and il2.contains_rva(rva):
        return True, f'il2cpp (RVA 0x{rva:X})'
    if sec.executable:
        return True, f'可执行节 {sec.name} (RVA 0x{rva:X})'
    return False, f'段 {sec.name} 既不是 il2cpp 也不是可执行节 (RVA 0x{rva:X})'


def score_solution(pe: pe_utils.PEFile, q, base: int, delta: int, pos0: int,
                   il2: pe_utils.Section):
    """给一个 (base, δ) 打分：锚点全过 + 目标命中数 + 表所在段是否数据段。"""
    need = MAX_TARGET_IDX + delta + 1
    if need <= 0 or pos0 + need > q.size:
        return None
    anchors = []
    for m in ANCHOR_INDICES:
        m2 = m + delta
        if m2 < 0 or pos0 + m2 >= q.size:
            return None
        ok, why = plausible_pointer(pe, int(q[pos0 + m2]), il2)
        if not ok:
            return None
        anchors.append((m, why))
    optional_ok = 0
    for m in OPTIONAL_INDICES:
        m2 = m + delta
        if 0 <= m2 and pos0 + m2 < q.size:
            if plausible_pointer(pe, int(q[pos0 + m2]), il2)[0]:
                optional_ok += 1
    good_targets = 0
    details = []
    for i, desc in TARGETS:
        m2 = i + delta
        va = int(q[pos0 + m2])
        ok, why = plausible_pointer(pe, va, il2)
        good_targets += 1 if ok else 0
        details.append(dict(idx=i, shifted_idx=m2, va=va, rva=va - pe.image_base,
                            plausible=ok, reason=why, desc=desc))
    sec = pe.section_of_off(base, required=False)
    return dict(base=base, delta=delta, anchors=anchors, optional_ok=optional_ok,
                good_targets=good_targets, details=details,
                section=sec.name if sec else None,
                data_section=bool(sec is not None and not sec.executable))


@pe_utils.json_aware_main
def main() -> int:
    ap = argparse.ArgumentParser(
        description='反推 methodPointer 表基址并按全局索引读 RVA（自洽解唯一才采信）')
    ap.add_argument('--server', default='cn', choices=sorted(SERVERS))
    ap.add_argument('--exe', default='', help='覆盖服务器默认 exe 路径')
    ap.add_argument('--rva', default='', help='覆盖 to_int32 的 RVA（支持 0x...）')
    ap.add_argument('--idx', default='', help='覆盖 to_int32 的全局方法索引')
    ap.add_argument('--window', type=pe_utils.parse_int, default=0x400,
                    help='索引平移 δ 的搜索半径，单位是索引个数（默认 0x400）')
    ap.add_argument('--table-base', default='', help='直接指定表基址的**文件偏移**')
    ap.add_argument('--table-rva', default='', help='直接指定表基址的 RVA')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    cfg = SERVERS[a.server]
    exe = a.exe or cfg['exe']
    exe_is_default = not a.exe
    try:
        idx0 = pe_utils.parse_int(a.idx) if a.idx else cfg['to_int32_idx']
        to_int32_rva = pe_utils.parse_int(a.rva) if a.rva else cfg['to_int32']
    except ValueError as exc:
        print(f'错误：--rva/--idx 无效：{exc}', file=sys.stderr)
        return EXIT_PARAM
    if a.window < 0:
        print('错误：--window 不能为负', file=sys.stderr)
        return EXIT_PARAM

    try:
        pe = pe_utils.load_pe(exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        hint = ''
        if exe_is_default:
            hint = (f'（默认文件名 {exe!r} 只是占位；用 --exe 指定真实路径，'
                    f'或用 --server gl 切换国际服）')
        print(f'错误：无法加载 PE {exe}：{exc}{hint}', file=sys.stderr)
        return EXIT_PARAM

    try:
        to_off = pe.rva_to_off(to_int32_rva)
    except pe_utils.RvaError as exc:
        print(f'错误：to_int32 的 RVA 无法映射：{exc}', file=sys.stderr)
        return EXIT_PARAM
    to_va = pe.rva_to_va(to_int32_rva)
    il2 = pe.find_section('il2cpp')
    if il2 is None:
        print(f'警告：exe 里没有 il2cpp 段（现有段: {", ".join(pe.section_names)}）——'
              f'只能是「可执行节」判据兜底', file=sys.stderr)

    pat = to_va.to_bytes(8, 'little')
    occ = []
    o = pe.data.find(pat)
    while o >= 0:
        occ.append(o)
        o = pe.data.find(pat, o + 1)
    aligned = [x for x in occ if x % 8 == 0]
    print(f'{a.server}: exe={exe}  ImageBase=0x{pe.image_base:X}')
    print(f'  to_int32 RVA 0x{to_int32_rva:X} (VA 0x{to_va:X}, 文件 0x{to_off:X})  '
          f'idx={idx0}')
    print(f'  该 VA 的 8 字节指针在文件里出现 {len(occ)} 次'
          f'（其中 {len(aligned)} 个 8 字节对齐，非对齐的无法构成表项，已排除）: '
          f'{[hex(x) for x in occ[:8]]}{" …" if len(occ) > 8 else ""}')

    out = dict(server=a.server, exe=exe, image_base=pe.image_base,
               to_int32=dict(rva=to_int32_rva, va=to_va, file_offset=to_off, idx=idx0),
               window=a.window, occurrences=[hex(x) for x in occ],
               aligned_occurrences=[hex(x) for x in aligned],
               table=None, targets=[], warnings=[], verdict='no-solution')

    if not occ:
        print('错误：文件里找不到 to_int32 的 VA 指针 —— --rva 给错了？'
              '或这个 exe 不是该服务器版本？', file=sys.stderr)
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_UNTRUSTED
    if not aligned:
        print('错误：虽然出现了该 VA，但没有 8 字节对齐的出现位置，构不成 methodPointer 表。',
              file=sys.stderr)
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_UNTRUSTED

    # ---- 固定表基址（--table-base / --table-rva）----
    fixed_base = None
    if a.table_base or a.table_rva:
        try:
            fixed_base = (pe.rva_to_off(pe_utils.parse_int(a.table_rva))
                          if a.table_rva else pe_utils.parse_int(a.table_base))
        except (ValueError, pe_utils.RvaError) as exc:
            print(f'错误：--table-base/--table-rva 无效：{exc}', file=sys.stderr)
            return EXIT_PARAM
        try:
            sec = pe.section_of_off(fixed_base)
        except pe_utils.RvaError as exc:
            print(f'错误：{exc}', file=sys.stderr)
            return EXIT_PARAM
        print(f'  使用显式表基址：文件 0x{fixed_base:X} → RVA '
              f'0x{pe.off_to_rva(fixed_base, 8):X} (段 {sec.name})')
        candidates_delta = []
        for x in aligned:
            d = (x - fixed_base) // 8 - idx0
            if d not in candidates_delta:
                candidates_delta.append(d)
        if not candidates_delta:
            print('错误：显式表基址与任何出现位置都不自洽', file=sys.stderr)
            return EXIT_UNTRUSTED
        occurrences = [(fixed_base, d) for d in sorted(set(candidates_delta))]
        window_lo = window_hi = None
    else:
        window_lo, window_hi = -a.window, a.window
        occurrences = None

    # ---- 搜索窗口：一次读进内存，避免每个 δ 都重新切片 ----
    if occurrences is None:
        need_slots = MAX_TARGET_IDX + a.window + 8
        lo_cand = min(aligned) - (idx0 + a.window) * 8
        lo_cand = max(0, lo_cand)
        lo_cand -= lo_cand % 8
        hi_cand = max(aligned) - (idx0 - a.window) * 8 + need_slots * 8
        hi_cand = min(len(pe.data), hi_cand)
        if hi_cand <= lo_cand:
            print('错误：搜索窗口为空（to_int32 指针出现位置太靠近文件末尾）', file=sys.stderr)
            return EXIT_UNTRUSTED
        span = hi_cand - lo_cand
        q = np.frombuffer(pe.data, dtype='<u8', count=span // 8, offset=lo_cand)
        print(f'  搜索 δ ∈ [{window_lo}, {window_hi}]，窗口 文件 0x{lo_cand:X}..'
              f'0x{hi_cand:X}（{span // 8} 项，一次读入）')

        solutions = {}
        for delta in range(window_lo, window_hi + 1):
            if MAX_TARGET_IDX + delta + 1 <= 0:
                continue
            for x in aligned:
                base = x - (idx0 + delta) * 8
                if base < 0 or base % 8 or base < lo_cand:
                    continue
                end_bytes = base + (MAX_TARGET_IDX + delta + 1) * 8
                if end_bytes > len(pe.data):
                    continue
                try:
                    sec = pe.section_of_off(base)
                except pe_utils.RvaError:
                    continue
                if base + (MAX_TARGET_IDX + delta + 1) * 8 > sec.raw_end:
                    continue          # 表必须整个落在同一个段的文件范围内
                pos0 = (base - lo_cand) // 8
                sc = score_solution(pe, q, base, delta, pos0, il2)
                if sc is None or sc['good_targets'] < len(TARGETS) - 1:
                    continue
                key = base
                if key not in solutions or (
                        sc['good_targets'], sc['optional_ok'], sc['data_section']) > (
                        solutions[key]['good_targets'], solutions[key]['optional_ok'],
                        solutions[key]['data_section']):
                    solutions[key] = sc
    else:
        solutions = {}
        for base, delta in occurrences:
            need_bytes = (MAX_TARGET_IDX + delta + 1) * 8
            if need_bytes <= 0 or base + need_bytes > len(pe.data):
                continue
            try:
                sec = pe.section_of_off(base)
            except pe_utils.RvaError:
                continue
            if base + need_bytes > sec.raw_end:
                continue
            pos0 = 0
            q = np.frombuffer(pe.data, dtype='<u8', offset=base, count=need_bytes // 8)
            sc = score_solution(pe, q, base, delta, pos0, il2)
            if sc is None or sc['good_targets'] < len(TARGETS) - 1:
                continue
            key = base
            if key not in solutions or (
                    sc['good_targets'], sc['optional_ok'], sc['data_section']) > (
                    solutions[key]['good_targets'], solutions[key]['optional_ok'],
                    solutions[key]['data_section']):
                solutions[key] = sc
        q = None

    if not solutions:
        print('\n❌ 无自洽解：没有任何 (出现位置, δ) 能让参照项 '
              f'{ANCHOR_INDICES} 同时落进 il2cpp/可执行节。', file=sys.stderr)
        print('   → 增大 --window？确认 --rva/--idx 是这一版 exe 的值？', file=sys.stderr)
        out['verdict'] = 'no-solution'
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_UNTRUSTED

    # ---- 选解：RVA 必须唯一；表基址/δ 天然存在「整体平移」退化 ----
    # 说明：(base, δ) 与 (base + 8k, δ - k) 读的是**同一批字节**，因此每个目标方法的 RVA
    # 完全一致，只有「表起点 + 全局索引」这一对标签不同。这是数据本身无法区分的自由度
    # （to_int32 的真实索引是 1357+δ，而 base 同步挪动，观测到的文件偏移是一样的）。
    # 所以按「目标 VA 向量」分组：只有一组 → RVA 唯一可信；多组 → 真的矛盾，报错退出。
    groups = {}
    for sc in solutions.values():
        key = tuple(d['va'] for d in sc['details'])
        groups.setdefault(key, []).append(sc)
    if len(groups) > 1:
        print(f'\n❌ 有 {len(groups)} 组互不相同的自洽解（目标 RVA 都不一样），无法判定：',
              file=sys.stderr)
        for key, fam in groups.items():
            s = fam[0]
            print(f'   文件 0x{s["base"]:X}  δ={s["delta"]:+d}  段 {s["section"]}  '
                  f'目标命中 {s["good_targets"]}/{len(TARGETS)}  '
                  f'（该组 {len(fam)} 个平移等价解）', file=sys.stderr)
        print('   → 用 --table-base/--table-rva 显式指定表基址再跑一次。', file=sys.stderr)
        out.update(verdict='ambiguous',
                   candidates=[dict(file_offset=fam[0]['base'], delta=fam[0]['delta'],
                                    section=fam[0]['section'],
                                    good_targets=fam[0]['good_targets'],
                                    equivalent=len(fam)) for fam in groups.values()])
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_UNTRUSTED

    family = next(iter(groups.values()))
    best = min(family, key=lambda s: (abs(s['delta']), s['delta']))
    deltas = sorted(s['delta'] for s in family)
    base = best['base']
    sec = pe.section_of_off(base)
    base_rva = pe.off_to_rva(base, (MAX_TARGET_IDX + best['delta'] + 1) * 8)
    print(f'\n✅ 唯一解（目标 RVA 唯一）：methodPointer 表基址 '
          f'文件偏移 0x{base:X} / RVA 0x{base_rva:X}（段 {sec.name}）  '
          f'索引平移 δ={best["delta"]:+d}（to_int32 的真实索引 {idx0 + best["delta"]}）')
    print(f'   表必须在同一个段内：段 {sec.name} 原始范围 0x{sec.raw_ptr:X}..'
          f'0x{sec.raw_end:X}')
    if len(deltas) > 1:
        print(f'   ⚠ 退化提示：δ ∈ [{deltas[0]:+d}, {deltas[-1]:+d}] 内的解读读的是同一批'
              f'字节、给出的**方法 RVA 完全相同**，只是「表起点 + 全局索引」这一对标签不同'
              f'（表基址相应在 文件 0x{min(s["base"] for s in family):X}..'
              f'0x{max(s["base"] for s in family):X} 之间滑动）。')
        print(f'      这里按 |δ| 最小取 δ={best["delta"]:+d}；要固定标签请用 '
              f'--table-base/--table-rva 显式给出表基址。')

    need_bytes = (MAX_TARGET_IDX + best['delta'] + 1) * 8
    if base + need_bytes > sec.raw_end:
        print(f'错误：表读到 0x{base + need_bytes:X}，越出段 {sec.name} 的原始范围 '
              f'0x{sec.raw_end:X}', file=sys.stderr)
        return EXIT_UNTRUSTED
    raw = pe.read_off(base, need_bytes)
    table = np.frombuffer(raw, dtype='<u8')

    out['table'] = dict(file_offset=base, rva=base_rva, section=sec.name,
                        delta=best['delta'], delta_choices=deltas,
                        delta_degenerate=len(deltas) > 1,
                        slots=int(table.size), bytes=need_bytes)
    out['verdict'] = 'ok'

    print(f'\n{"idx":>7} {"真实idx":>8}  {"RVA":>12}  {"段":<8} {"il2cpp":<6} 说明')
    required_fail = 0
    warn_fail = 0
    for d in best['details']:
        i = d['idx']
        m2 = d['shifted_idx']
        rva = d['rva']
        s = pe.section_of_rva(rva, required=False) if rva > 0 else None
        in_il2 = bool(il2 and s and il2.contains_rva(rva))
        is_anchor = i in ANCHOR_INDICES
        item = dict(idx=i, shifted_idx=m2, rva=rva, va=d['va'],
                    section=s.name if s else None, in_il2cpp=in_il2,
                    plausible=d['plausible'], anchor=is_anchor,
                    optional=i in OPTIONAL_INDICES, desc=d['desc'])
        out['targets'].append(item)
        flag = '✅' if in_il2 else ('◇' if d['plausible'] else '❌')
        note = ''
        if not d['plausible']:
            note = f'  ⚠ {d["reason"]}'
        elif not in_il2:
            note = f'  ⚠ 不在 il2cpp 段（{s.name if s else "?"}）'
        print(f'{i:>7} {m2:>8}  0x{rva:08X}  {s.name if s else "—":<8} '
              f'{flag:<6} {d["desc"]}{note}')
        if not d['plausible']:
            if is_anchor:
                required_fail += 1
            else:
                warn_fail += 1

    if not il2:
        out['warnings'].append('exe 没有 il2cpp 段，只能用「可执行节」判据')
    if required_fail:
        print(f'\n错误：{required_fail} 个**参照项**没通过校验 —— 表基址不可信',
              file=sys.stderr)
        out['verdict'] = 'reference-failed'
        if a.json:
            pe_utils.emit_json(out)
        return EXIT_UNTRUSTED
    if warn_fail:
        out['warnings'].append(f'{warn_fail} 个猜测项（新增#N ?）没落在 il2cpp/可执行节，'
                               f'已单独标注，不影响结论')
        print(f'\n警告：{warn_fail} 个猜测项没通过校验（已单独标注，不影响结论）')

    if a.json:
        pe_utils.emit_json(out)
    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
