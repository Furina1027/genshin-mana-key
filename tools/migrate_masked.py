#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migrate_masked.py — 跨版本/跨服迁移函数 RVA（掩码指纹匹配版）。

为什么需要掩码：相邻版本编译同一份源码，指令序列几乎一致，但
  · call rel32 / jmp rel32 的相对位移
  · rip-relative 的 disp32
会随模块布局整体平移而改变。把它们标为通配后，其余字节（opcode + ModRM + 小立即数）
构成高特异性的指纹。

流程：
  1. 反汇编源 exe 在给定 RVA 处的 N 条指令，生成 (bytes, mask)
     —— **按 .pdata 的函数边界截断**，指纹绝不跨到下一个函数里去
  2. 取 mask 中最长的连续非通配 run（≥MIN_ANCHOR）作为锚
  3. 在目标 exe 里搜锚 → 候选偏移 → 按掩码验证整段
  4. 输出通过验证的候选 RVA：**必须唯一**才采信；0 个或 ≥2 个都算失败（非 0 退出）

用法：
  python migrate_masked.py --src <旧exe> --dst <新exe> \
      --rva name=0x188EBA80 [--rva ...] [--n 28] [--anchor 6] [--dis] [--json]

退出码：0=全部函数都唯一命中；1=有函数命中 0 个或多个候选（迁移不成立）；
        2=参数/IO/PE 错误。
"""
from __future__ import annotations

import argparse
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    import numpy as np
except ImportError as exc:                       # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。安装：pip install -r tools/requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

import pdata
import pe_utils

EXIT_OK = 0
EXIT_AMBIGUOUS = 1
EXIT_PARAM = 2

#: 指纹最少要有多少条指令（旧实现只靠 sim() 里的 L >= 8 字节兜底，
#: 结果是「2 条指令」也能过阈值）
MIN_INSNS = 6


def build_mask_acc(md, code, va, n, maxbytes):
    """按指令累积 (bytes, mask)，通配 imm/disp。返回 (pat, msk, cnt, consumed)。"""
    pat, msk = bytearray(), bytearray()
    cnt = 0
    consumed = 0
    for ins in md.disasm(code[:maxbytes], va):
        b = ins.bytes
        m = bytearray(b'\x01' * len(b))
        if ins.imm_size:
            for k in range(ins.imm_size):
                m[ins.imm_offset + k] = 0
        if ins.disp_size:
            for k in range(ins.disp_size):
                m[ins.disp_offset + k] = 0
        pat += b
        msk += m
        cnt += 1
        consumed += len(b)
        if cnt >= n:
            break
    return bytes(pat), bytes(msk), cnt, consumed


def longest_run(msk, minimum):
    best = (0, 0)
    i = 0
    while i < len(msk):
        if msk[i]:
            j = i
            while j < len(msk) and msk[j]:
                j += 1
            if j - i > best[1] - best[0]:
                best = (i, j)
            i = j
        else:
            i += 1
    return best if best[1] - best[0] >= minimum else None


def verify(target, pos, pat, msk):
    if pos < 0 or pos + len(pat) > len(target):
        return False
    for i in range(len(pat)):
        if msk[i] and target[pos + i] != pat[i]:
            return False
    return True


def migrate_one(md, spe, sdata, sbase, sbounds, ddata, dsecs_pe, dbounds, name, rva,
                n, anchor, max_hits, no_pdata):
    """迁移一个函数，返回结果 dict（status: ok/ambiguous/not-found/no-fingerprint/error）。"""
    res = dict(name=name, src_rva=rva, status='error', hits=[], reason='',
               insns=0, fingerprint_bytes=0, wildcard_bytes=0, anchor_len=0,
               boundary=None, delta=None)
    try:
        so = spe.rva_to_off(rva)
    except pe_utils.RvaError as exc:
        res.update(status='error', reason=f'src RVA 无法映射到文件偏移：{exc}')
        return res

    # ★ 按函数边界截断（.pdata 已知该函数在哪结束）
    want = 0x400
    bound = sbounds.containing(rva) if sbounds else None
    if bound is not None and bound.start != rva:
        res['boundary'] = (bound.start, bound.end)
        res['reason'] = (f'注意：RVA 0x{rva:X} 不是函数起点（该函数起点 0x{bound.start:X}）')
    limit = sbounds.slice_limit(rva, want) if sbounds else want
    res['fingerprint_limited_to'] = limit
    if not no_pdata and sbounds is None:
        res['pdata_missing'] = True

    pat, msk, cnt, consumed = build_mask_acc(md, sdata[so:so + limit], sbase + rva, n, limit)
    res['insns'] = cnt
    res['fingerprint_bytes'] = len(msk)
    res['wildcard_bytes'] = msk.count(0)
    if cnt < MIN_INSNS:
        res.update(status='no-fingerprint',
                   reason=f'函数边界内只反汇编出 {cnt} 条指令（< {MIN_INSNS}），指纹不可靠')
        return res
    if cnt < n:
        res['insns_short'] = True

    run = longest_run(msk, anchor)
    if run is None:
        res.update(status='no-fingerprint',
                   reason=f'无法生成锚（没有 ≥{anchor} 字节的连续非通配区）')
        return res
    r0, r1 = run
    anchor_bytes = pat[r0:r1]
    res['anchor_len'] = r1 - r0
    res['anchor_offset_in_fingerprint'] = r0

    hits = []
    i = ddata.find(anchor_bytes)
    while i >= 0:
        start = i - r0
        if verify(ddata, start, pat, msk):
            try:
                rv = dsecs_pe.off_to_rva(start)
            except pe_utils.RvaError:
                rv = None
            if rv is not None:
                entry = dict(rva=rv, delta=rv - rva)
                if dbounds is not None:
                    b = dbounds.containing(rv)
                    entry['dst_function_start'] = b.start if b else None
                hits.append(entry)
        i = ddata.find(anchor_bytes, i + 1)
    uniq = {}
    for h in hits:
        uniq.setdefault(h['rva'], h)
    hits = [uniq[k] for k in sorted(uniq)]
    res['hits'] = hits[:max_hits]
    res['hit_count'] = len(hits)

    if len(hits) == 1:
        res.update(status='ok', delta=hits[0]['delta'])
        if res['reason'].startswith('注意'):
            res['reason'] += '（但指纹唯一命中，结果仍可用）'
        else:
            res['reason'] = '唯一命中'
    elif not hits:
        res.update(status='not-found', reason='在目标 exe 里没有任何候选通过验证')
    else:
        res.update(status='ambiguous',
                   reason=f'有 {len(hits)} 个候选通过验证 —— 不唯一，不能当作迁移结果')
    return res


def main() -> int:
    ap = argparse.ArgumentParser(
        description='跨版本迁移函数 RVA（掩码指纹 + .pdata 函数边界）')
    ap.add_argument('--src', required=True, help='旧 exe')
    ap.add_argument('--dst', required=True, help='新 exe')
    ap.add_argument('--rva', action='append', required=True, help='name=0xRVA')
    ap.add_argument('--n', type=int, default=28, help='源函数取多少条指令做指纹')
    ap.add_argument('--anchor', type=int, default=6, help='锚最小长度（字节）')
    ap.add_argument('--max', type=int, default=6, help='最多打印几个候选')
    ap.add_argument('--dis', action='store_true', help='打印源函数反汇编')
    ap.add_argument('--no-pdata', action='store_true',
                    help='不按 .pdata 函数边界截断指纹（默认会截断；缺 .pdata 时会警告）')
    ap.add_argument('--min-insns', type=int, default=MIN_INSNS)
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()

    if a.n < 1 or a.anchor < 1 or a.max < 1 or a.min_insns < 1:
        print('错误：--n / --anchor / --max / --min-insns 都必须 >= 1', file=sys.stderr)
        return EXIT_PARAM

    try:
        spe = pe_utils.load_pe(a.src)
        dpe = pe_utils.load_pe(a.dst)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM

    sbounds = None if a.no_pdata else pdata.load_function_bounds(spe)
    dbounds = None if a.no_pdata else pdata.load_function_bounds(dpe)
    sbounds_warn = None if (a.no_pdata or sbounds is not None) else (
        f'{a.src} 没有 .pdata 段 → 指纹不会按函数边界截断（结果可能跨函数误匹配）')
    dbounds_warn = None if (a.no_pdata or dbounds is not None) else (
        f'{a.dst} 没有 .pdata 段 → 只做了字节级验证，未做函数归属检查')

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    results = []
    if not a.json:
        print(f'src = {a.src}\ndst = {a.dst}')
        if sbounds is not None:
            print(f'  src 函数边界[{sbounds.info.get("source", "?")}]: {len(sbounds):,} 个')
        if dbounds is not None:
            print(f'  dst 函数边界[{dbounds.info.get("source", "?")}]: {len(dbounds):,} 个')
        # 边界来源不可信时（.pdata 诱饵）必须让人看见 —— 否则指纹会按错的函数尾截断。
        # src==dst 时两边警告完全相同，去重打印。
        seen_warn = set()
        for bounds in (sbounds, dbounds):
            if bounds is None:
                continue
            for w in bounds.warnings:
                if w not in seen_warn:
                    seen_warn.add(w)
                    print(f'  ⚠ {w}')
        for w in (sbounds_warn, dbounds_warn):
            if w and w not in seen_warn:
                seen_warn.add(w)
                print(f'  ⚠ {w}')
        print()

    for item in a.rva:
        if '=' not in item:
            print(f'错误：--rva 需要 name=0xRVA 形式，收到 {item!r}', file=sys.stderr)
            return EXIT_PARAM
        name, hs = item.split('=', 1)
        try:
            rva = pe_utils.parse_int(hs)
        except ValueError as exc:
            print(f'错误：{exc}', file=sys.stderr)
            return EXIT_PARAM
        res = migrate_one(md, spe, spe.data, spe.image_base, sbounds,
                          dpe.data, dpe, dbounds, name, rva, a.n, a.anchor, a.max,
                          a.no_pdata)
        if res.get('insns', 0) < a.min_insns and res['status'] == 'ok':
            res.update(status='no-fingerprint',
                       reason=f'只有 {res["insns"]} 条指令（< --min-insns {a.min_insns}），'
                              f'指纹太短，不采信')
        results.append(res)

        if not a.json:
            flag = {'ok': '✅ 唯一', 'ambiguous': '❌ 不唯一', 'not-found': '❌ 未找到',
                    'no-fingerprint': '⚠ 指纹不可靠', 'error': '⚠ 错误'}[res['status']]
            print(f'[{name}] src RVA 0x{rva:X}  指纹 {res["insns"]} 指令 / '
                  f'{res["fingerprint_bytes"]}B（通配 {res["wildcard_bytes"]}B）'
                  f'  锚 {res["anchor_len"]}B  → {flag}')
            if res['reason']:
                print(f'    {res["reason"]}')
            for h in res.get('hits', [])[:a.max]:
                extra = ''
                if h.get('dst_function_start') is not None and \
                        h['dst_function_start'] != h['rva']:
                    extra = f'  (所在函数起点 0x{h["dst_function_start"]:X})'
                print(f'    -> 新 RVA 0x{h["rva"]:X}   (delta = {h["delta"]:+d}){extra}')
            if a.dis and res['status'] != 'error':
                try:
                    so = spe.rva_to_off(rva)
                except pe_utils.RvaError:
                    so = None
                if so is not None:
                    print('    —— 源函数 ——')
                    k = 0
                    for ins in md.disasm(spe.data[so:so + 0x120], spe.image_base + rva):
                        print(f'       0x{ins.address:X}: {ins.mnemonic} {ins.op_str}')
                        k += 1
                        if k >= 18:
                            break
            print()

    ok = [r for r in results if r['status'] == 'ok']
    out = dict(src=a.src, dst=a.dst,
               src_bounds=len(sbounds) if sbounds is not None else None,
               dst_bounds=len(dbounds) if dbounds is not None else None,
               warnings=[w for w in (sbounds_warn, dbounds_warn) if w],
               results=results,
               resolved={r['name']: r['hits'][0]['rva'] for r in ok})
    if a.json:
        pe_utils.emit_json(out)
    else:
        print('=== 迁移结果 ===')
        for r in results:
            if r['status'] == 'ok':
                print(f'  {r["name"]:24} 0x{r["hits"][0]["rva"]:X}  '
                      f'({r["hits"][0]["rva"]})  delta {r["delta"]:+d}')
            else:
                print(f'  {r["name"]:24} ✗ {r["status"]}: {r["reason"]}')
        print(f'\n{len(ok)}/{len(results)} 个函数唯一命中')

    return EXIT_OK if len(ok) == len(results) else EXIT_AMBIGUOUS


if __name__ == '__main__':
    raise SystemExit(main())
