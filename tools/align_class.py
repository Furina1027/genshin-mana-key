#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""align_class.py — 把 7.0 某个类的每个方法与 7.1 同名方法做「掩码指纹」一一对齐，
从而找出 7.1 新增（7.0 无对应）的方法。

对齐用的是**全局分配**（scipy.optimize.linear_sum_assignment，最大化总相似度），
而不是「7.1 这边各自贪心挑一个」——贪心会让一个 7.0 方法被抢走、后面的都错位。
没有 scipy 时退化为「互相最优」（双向互为最佳才算一对）。

修掉的老问题：
  · 硬编码的本机绝对路径（EXE70/EXE71/DUMP70）→ 全部改成 CLI 参数；
  · ``--idx70`` 解析了却从未使用 → 现在用来按索引区间裁剪 7.0 方法；
  · ``m70[0][0]`` 在 parse_class 返回空表时直接 IndexError → 显式报错并非 0 退出；
  · ``base71`` 不做任何校验 → 增加「多数条目能落到 il2cpp 段」的 sanity gate；
  · fp() 固定切 0x200 字节会**截断到半条指令**，且 sim() 只要求 8 个可比字节
    → 现在记录指令边界，并要求**可比指令条数**与**可比字节数**都过下限；
  · rva2off 失败被当成「7.1 新增」→ 现在单独标注「RVA 无法映射（不是新增）」；
  · 表读取越界会抛裸 ValueError → 显式校验并给可读中文错误。

用法：
  python align_class.py --dump70 <dump70.cs> --exe70 <7.0.exe> --exe71 <7.1.exe> \
      --class CriWare.CriMana.Player --base71 0x2870C78 [--idx70 83127:83230] [--json]

退出码：0=完成对齐；2=参数/IO/解析错误；3=表基址 sanity gate 不通过（结果不可信）。
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    import numpy as np
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError as exc:                       # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。安装：pip install -r tools/requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

import pe_utils

try:                                    # 可选依赖：没有 scipy 就退化为互相最优
    from scipy.optimize import linear_sum_assignment
    HAVE_SCIPY = True
except ImportError:                     # pragma: no cover - 取决于环境
    HAVE_SCIPY = False

EXIT_OK = 0
EXIT_PARAM = 2
EXIT_UNTRUSTED = 3

#: 指纹最少指令条数（低于此值不参与匹配）
MIN_INSNS = 6
#: 两条指纹最少要共同覆盖多少条「完整且无通配」的指令
MIN_FULL_INSNS = 6
#: 以及最少多少字节的可比区
MIN_COMPARABLE_BYTES = 24

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


@dataclass
class Fp:
    """一条掩码指纹。"""

    rva: int
    pat: bytes
    msk: bytes
    insns: int
    #: 每条指令的 (起始偏移, 结束偏移, 通配字节数)
    spans: tuple = ()
    error: Optional[str] = None

    @property
    def nbytes(self) -> int:
        return len(self.pat)

    def solid_spans(self) -> set:
        """完全无通配的指令跨距集合（用于断言「比较了几条完整指令」）。"""
        return {(s, e) for s, e, w in self.spans if w == 0}


@dataclass
class AlignResult:
    matched: list = field(default_factory=list)
    new_in_71: list = field(default_factory=list)
    unmappable_71: list = field(default_factory=list)
    unmatched_70: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def parse_class(path, cls):
    """从 Il2CppDumper 的 dump.cs 里抓某个类的 `方法; // idx N RVA 0x...` 列表。"""
    out = []
    inside = False
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                s = line.rstrip('\n')
                if s.startswith('// TypeDefIndex'):
                    inside = False
                elif s.startswith('class '):
                    inside = (s.strip() == 'class ' + cls)
                elif inside:
                    m = re.match(r'\s*([^;]+); // idx (\d+)\s+RVA 0x([0-9a-fA-F]+)', s)
                    if m:
                        out.append((int(m.group(2)), m.group(1).strip(),
                                    int(m.group(3), 16)))
    except OSError as exc:
        raise pe_utils.PEFormatError(f'无法读取 dump 文件 {path}：{exc}') from exc
    return out


def fp(pe: pe_utils.PEFile, rva: int, n: int = 14, window: int = 0x200) -> Fp:
    """生成 RVA 处的掩码指纹（最多 n 条指令，最多 window 字节）。"""
    try:
        off = pe.rva_to_off(rva)
    except pe_utils.RvaError as exc:
        return Fp(rva=rva, pat=b'', msk=b'', insns=0, spans=(), error=str(exc))
    pat, msk = bytearray(), bytearray()
    spans = []
    for ins in md.disasm(pe.data[off:off + window], pe.image_base + rva):
        b = ins.bytes
        m = bytearray(b'\x01' * len(b))
        if ins.imm_size:
            for j in range(ins.imm_size):
                m[ins.imm_offset + j] = 0
        if ins.disp_size:
            for j in range(ins.disp_size):
                m[ins.disp_offset + j] = 0
        start = len(pat)
        pat += b
        msk += m
        spans.append((start, len(pat), m.count(0)))
        if len(spans) >= n:
            break
    return Fp(rva=rva, pat=bytes(pat), msk=bytes(msk), insns=len(spans),
              spans=tuple(spans))


def sim(a: Fp, b: Fp):
    """相似度。返回 (score, full_insns, both_bytes)；不可比返回 (None, ...)。

    ★ 旧实现只要求 ``L >= 8``（8 个字节，也就是两条指令）就可能过 0.90 阈值，
    这里同时要求「完整且双方都无通配的指令数 >= MIN_FULL_INSNS」与
    「可比字节数 >= MIN_COMPARABLE_BYTES」，否则一律判为不可比。
    """
    if a is None or b is None or a.insns == 0 or b.insns == 0:
        return None, 0, 0
    if a.insns < MIN_INSNS or b.insns < MIN_INSNS:
        return None, 0, 0
    L = min(len(a.pat), len(b.pat))
    both = eq = 0
    for i in range(L):
        if a.msk[i] and b.msk[i]:
            both += 1
            if a.pat[i] == b.pat[i]:
                eq += 1
    a_solid = {(s, e) for s, e, w in a.spans if w == 0 and e <= L}
    b_solid = {(s, e) for s, e, w in b.spans if w == 0 and e <= L}
    full = len(a_solid & b_solid)
    if both < MIN_COMPARABLE_BYTES or full < MIN_FULL_INSNS:
        return None, full, both
    return eq / both, full, both


def read_method_table(pe: pe_utils.PEFile, base_off: int, lo: int, hi: int,
                      image_base: int) -> list:
    """按索引区间读 methodPointer 表，返回 [(idx, rva, section_name, in_il2cpp)]。

    base_off 是**文件偏移**（与 CLI 的 --base71 语义一致）。
    """
    need = (hi + 4) * 8
    try:
        blob = pe.read_off(base_off, need)
    except pe_utils.RvaError as exc:
        raise pe_utils.RvaError(
            f'方法表越界：从文件偏移 0x{base_off:X} 读 {(hi + 4)} 项（{need} B）失败：{exc}') from exc
    import numpy as np
    q = np.frombuffer(blob, dtype='<u8', count=hi + 4)

    il2 = pe.find_section('il2cpp')
    out = []
    for i in range(lo, hi + 1):
        va = int(q[i])
        if va == 0:
            continue
        rva = va - image_base
        sec = pe.section_of_rva(rva, required=False)
        out.append(dict(idx=i, va=va, rva=rva, section=sec.name if sec else None,
                        in_il2cpp=bool(il2 and il2.contains_rva(rva))))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description='按掩码指纹把上一版本某个类的方法与当前版本一一对齐')
    ap.add_argument('--dump70', required=True, help='7.0 的 dump.cs（Il2CppDumper 输出）')
    ap.add_argument('--exe70', required=True, help='7.0 的 exe')
    ap.add_argument('--exe71', required=True, help='7.1 的 exe')
    ap.add_argument('--class', dest='cls', default='CriWare.CriMana.Player')
    ap.add_argument('--idx70', default='', help='7.0 方法索引区间 lo:hi（裁剪 dump 里读到的范围）')
    ap.add_argument('--idx71', default='', help='7.1 表索引区间 lo:hi')
    ap.add_argument('--base71', default='0x2870C78',
                    help='7.1 methodPointer 表的**文件偏移**（默认 0x2870C78）')
    ap.add_argument('--base71-rva', default='', help='同上，但用 RVA 给（二选一）')
    ap.add_argument('--thr', type=float, default=0.90, help='相似度阈值')
    ap.add_argument('--sanity-frac', type=float, default=0.5,
                    help='base71 sanity gate：至少这个比例的条目要落在 il2cpp 段')
    ap.add_argument('--no-sanity', action='store_true', help='跳过 base71 sanity gate')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if not 0.0 <= a.thr <= 1.0:
        print('错误：--thr 必须在 0..1 之间', file=sys.stderr)
        return EXIT_PARAM

    try:
        m70_all = parse_class(a.dump70, a.cls)
    except pe_utils.PEFormatError as exc:
        print(f'错误：{exc}', file=sys.stderr)
        return EXIT_PARAM
    if not m70_all:
        # ★ 旧实现这里 m70[0][0] 直接 IndexError
        print(f'错误：在 {a.dump70} 里找不到类 {a.cls} 的方法条目'
              f'（--class 拼写？dump 里可能没有这个类）', file=sys.stderr)
        return EXIT_PARAM

    if a.idx70:
        try:
            lo70, hi70 = (pe_utils.parse_int(x) for x in a.idx70.split(':'))
        except ValueError as exc:
            print(f'错误：--idx70 需要 lo:hi 形式：{exc}', file=sys.stderr)
            return EXIT_PARAM
        m70 = [t for t in m70_all if lo70 <= t[0] <= hi70]
        if not m70:
            print(f'错误：--idx70 {a.idx70} 没有裁出任何方法'
                  f'（dump 里的索引范围 {m70_all[0][0]}..{m70_all[-1][0]}）', file=sys.stderr)
            return EXIT_PARAM
    else:
        m70 = m70_all

    try:
        pe70 = pe_utils.load_pe(a.exe70)
        pe71 = pe_utils.load_pe(a.exe71)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    if not a.json:
        print(f'7.0 {a.cls}: {len(m70)} 个方法（dump 里共 {len(m70_all)} 个），'
              f'idx {m70[0][0]}..{m70[-1][0]}')

    # ---- 7.1 索引区间 ----
    if a.idx71:
        try:
            lo, hi = (pe_utils.parse_int(x) for x in a.idx71.split(':'))
        except ValueError as exc:
            print(f'错误：--idx71 需要 lo:hi 形式：{exc}', file=sys.stderr)
            return EXIT_PARAM
    else:
        lo, hi = m70[0][0] - 7448, m70[-1][0] - 7446
    if hi < lo:
        print('错误：--idx71 的 hi 小于 lo', file=sys.stderr)
        return EXIT_PARAM

    try:
        base71 = pe71.rva_to_off(pe_utils.parse_int(a.base71_rva)) \
            if a.base71_rva else pe_utils.parse_int(a.base71)
    except (pe_utils.RvaError, ValueError) as exc:
        print(f'错误：--base71/--base71-rva 无效：{exc}', file=sys.stderr)
        return EXIT_PARAM

    try:
        rows = read_method_table(pe71, base71, lo, hi, pe71.image_base)
    except pe_utils.RvaError as exc:
        print(f'错误：{exc}', file=sys.stderr)
        return EXIT_PARAM

    warnings = []
    if not rows:
        print(f'错误：7.1 表 idx {lo}..{hi} 里全是空槽（base71=0x{base71:X} 可能不对）',
              file=sys.stderr)
        return EXIT_UNTRUSTED

    # ---- sanity gate：多数条目要落在 il2cpp 段 ----
    in_il2 = sum(1 for r in rows if r['in_il2cpp'])
    frac = in_il2 / len(rows)
    if not a.no_sanity and frac < a.sanity_frac:
        print(f'错误：base71 sanity gate 不通过 —— 表里只有 {in_il2}/{len(rows)} '
              f'({frac:.1%}) 的条目落在 il2cpp 段（要求 >= {a.sanity_frac:.0%}）。'
              f'base71=0x{base71:X} 很可能不是 methodPointer 表基址。', file=sys.stderr)
        return EXIT_UNTRUSTED
    if frac < a.sanity_frac:
        warnings.append(f'--no-sanity：仅 {frac:.1%} 条目在 il2cpp 段（通常应 > 50%）')
    if not a.json:
        print(f'7.1 idx {lo}..{hi}: {len(rows)} 个有效方法指针'
              f'（{in_il2}/{len(rows)} = {frac:.1%} 落在 il2cpp 段）')

    # ---- 指纹 ----
    F70, bad70 = {}, {}
    for i, sig, r in m70:
        f = fp(pe70, r)
        if f.error or f.insns < MIN_INSNS:
            bad70[i] = f.error or f'只有 {f.insns} 条指令'
        else:
            F70[i] = f
    F71, bad71 = {}, {}
    for row in rows:
        f = fp(pe71, row['rva'])
        if f.error or f.insns < MIN_INSNS:
            bad71[row['idx']] = f.error or f'只有 {f.insns} 条指令'
        else:
            F71[row['idx']] = f
    for i, why in bad70.items():
        warnings.append(f'7.0 idx {i} 指纹不可用：{why}')
    for i, why in bad71.items():
        warnings.append(f'7.1 idx {i} 指纹不可用：{why}')

    # ---- 全局分配 ----
    score = {}
    stats = {}
    for i in F71:
        for j in F70:
            s, full, both = sim(F71[i], F70[j])
            if s is not None:
                score[(i, j)] = s
                stats[(i, j)] = (full, both)

    pairs = []
    if HAVE_SCIPY and score:
        import numpy as np
        I = sorted(F71)
        J = sorted(F70)
        ii = {v: k for k, v in enumerate(I)}
        jj = {v: k for k, v in enumerate(J)}
        mat = np.zeros((len(I), len(J)), dtype=float)
        for (i, j), s in score.items():
            mat[ii[i], jj[j]] = s
        ri, cj = linear_sum_assignment(-mat)
        for r_, c_ in zip(ri, cj):
            i, j = I[r_], J[c_]
            if mat[r_, c_] >= a.thr:
                pairs.append((i, j, float(mat[r_, c_])))
    elif score:
        warnings.append('没有 scipy：退化为「互相最优」匹配（不是全局最优）')
        best_for_71 = {}
        for (i, j), s in score.items():
            if i not in best_for_71 or s > best_for_71[i][1]:
                best_for_71[i] = (j, s)
        best_for_70 = {}
        for (i, j), s in score.items():
            if j not in best_for_70 or s > best_for_70[j][1]:
                best_for_70[j] = (i, s)
        for i, (j, s) in best_for_71.items():
            if s >= a.thr and best_for_70.get(j, (None,))[0] == i:
                pairs.append((i, j, s))

    used70 = {j for _, j, _ in pairs}
    matched71 = {i for i, _, _ in pairs}
    name70 = {j: nm for j, nm, _ in m70}
    rva70 = {j: rr for j, _, rr in m70}

    res = AlignResult(warnings=warnings)
    for i, j, s in sorted(pairs):
        row = next(r for r in rows if r['idx'] == i)
        res.matched.append(dict(idx71=i, rva71=row['rva'], idx70=j, rva70=rva70[j],
                                score=round(s, 4), name70=name70[j],
                                full_insns=stats.get((i, j), (0, 0))[0],
                                comparable_bytes=stats.get((i, j), (0, 0))[1]))
    for row in rows:
        i = row['idx']
        if i in matched71:
            continue
        if i in bad71:
            # ★ RVA 映射失败 / 指纹不可用 ≠ 新增方法
            res.unmappable_71.append(dict(idx71=i, rva71=row['rva'], reason=bad71[i]))
        else:
            res.new_in_71.append(dict(idx71=i, rva71=row['rva']))
    for j, nm, rr in m70:
        if j not in used70:
            res.unmatched_70.append(dict(idx70=j, name70=nm, rva70=rr,
                                         reason=bad70.get(j, '没有达到阈值的对应方法')))

    out = dict(dump70=a.dump70, exe70=a.exe70, exe71=a.exe71, cls=a.cls,
               base71_file_offset=base71, range71=[lo, hi],
               methods70=len(m70), methods71=len(rows),
               in_il2cpp=in_il2, in_il2cpp_frac=round(frac, 4),
               matcher='scipy.linear_sum_assignment' if HAVE_SCIPY else 'mutual-best',
               threshold=a.thr, matched=res.matched, new_in_71=res.new_in_71,
               unmappable_71=res.unmappable_71, unmatched_70=res.unmatched_70,
               warnings=res.warnings)

    if a.json:
        pe_utils.emit_json(out)
    else:
        for w in res.warnings:
            print(f'  ⚠ {w}')
        print(f'\n匹配器: {out["matcher"]}    阈值 {a.thr}')
        print(f'{"7.1 idx":>9} {"RVA71":>12}  {"7.0 idx":>9} {"RVA70":>12}  相似度  名称')
        for m in res.matched:
            print(f'{m["idx71"]:>9} 0x{m["rva71"]:08X}  {m["idx70"]:>9} '
                  f'0x{m["rva70"]:08X}  {m["score"]:.2f}   {m["name70"]}')
        if res.new_in_71:
            print(f'\n7.1 未见对应（疑似新增，{len(res.new_in_71)} 个）:')
            for m in res.new_in_71:
                print(f'   {m["idx71"]:>6}  RVA 0x{m["rva71"]:08X}')
        if res.unmappable_71:
            print(f'\n7.1 无法判定（RVA 无法映射/指纹不可用，**不是**新增，{len(res.unmappable_71)} 个）:')
            for m in res.unmappable_71:
                print(f'   {m["idx71"]:>6}  VA 0x{m["rva71"]:08X}  {m["reason"]}')
        print(f'\n7.0 未被匹配上的方法（{len(res.unmatched_70)} 个，可能是被删/改/指纹不可比）:')
        for m in res.unmatched_70:
            print(f'   {m["idx70"]:>6}  {m["name70"]}   [{m["reason"]}]')

    return EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
