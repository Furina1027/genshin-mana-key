#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gia_rva_migrate_masked.py — 跨版本迁移函数 RVA（掩码指纹匹配版）。

为什么需要掩码：相邻版本编译同一份源码，指令序列几乎一致，但
  · call rel32 / jmp rel32 的相对位移
  · rip-relative 的 disp32
会随模块布局整体平移而改变。把它们标为通配后，其余字节（opcode + ModRM + 小立即数）
构成高特异性的指纹。

流程：
  1. 反汇编源 exe 在给定 RVA 处的 N 条指令，生成 (bytes, mask)
  2. 取 mask 中最长的连续非通配 run（≥MIN_ANCHOR）作为锚
  3. 在目标 exe 里搜锚 → 候选偏移 → 按掩码验证整段
  4. 输出通过验证的候选 RVA（通常唯一）

用法：
  python gia_rva_migrate_masked.py --src <旧exe> --dst <新exe> \
      --rva name=0x188EBA80 [--rva ...] [--n 28] [--anchor 6] [--dis]
"""
from __future__ import annotations
import argparse
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def load(path):
    data = open(path, 'rb').read()
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [(s.Name.rstrip(b'\x00').decode('latin1'), s.VirtualAddress,
             s.Misc_VirtualSize, s.SizeOfRawData, s.PointerToRawData) for s in pe.sections]
    return data, base, secs


def rva2off(secs, rva):
    for nm, va, vsz, rsz, ro in secs:
        if va <= rva < va + max(vsz, rsz):
            return ro + (rva - va)
    return None


def off2rva(secs, off):
    for nm, va, vsz, rsz, ro in secs:
        if ro <= off < ro + rsz:
            return va + (off - ro)
    return None


def build_mask_acc(md, code, va, n, maxbytes):
    """按指令累积 (bytes, mask)，通配 imm/disp。"""
    pat = bytearray()
    msk = bytearray()
    cnt = 0
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
        if cnt >= n:
            break
    return bytes(pat), bytes(msk), cnt


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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', required=True)
    ap.add_argument('--dst', required=True)
    ap.add_argument('--rva', action='append', required=True, help='name=0xRVA')
    ap.add_argument('--n', type=int, default=28, help='源函数取多少条指令做指纹')
    ap.add_argument('--anchor', type=int, default=6, help='锚最小长度')
    ap.add_argument('--max', type=int, default=6, help='最多打印几个候选')
    ap.add_argument('--dis', action='store_true')
    a = ap.parse_args()

    sd, sbase, ssecs = load(a.src)
    dd, dbase, dsecs = load(a.dst)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"src = {a.src}\ndst = {a.dst}\n")
    results = {}
    for item in a.rva:
        name, hs = item.split('=')
        rva = int(hs, 0)
        so = rva2off(ssecs, rva)
        if so is None:
            print(f"[{name}] RVA 0x{rva:X} 不在段内")
            continue
        pat, msk, cnt = build_mask_acc(md, sd[so:so + 0x400], sbase + rva, a.n, 0x400)
        run = longest_run(msk, a.anchor)
        tot = len(msk)
        wild = msk.count(0)
        if run is None:
            print(f"[{name}] 无法生成锚（无 ≥{a.anchor} 字节连续非通配）")
            continue
        r0, r1 = run
        anchor = pat[r0:r1]
        print(f"[{name}] src RVA 0x{rva:X}  指纹 {cnt} 指令 / {tot}B（通配 {wild}B）"
              f"  锚 {r1 - r0}B @pat+{r0}")
        hits = []
        i = dd.find(anchor)
        while i >= 0:
            start = i - r0
            if verify(dd, start, pat, msk):
                rv = off2rva(dsecs, start)
                if rv is not None:
                    hits.append(rv)
            i = dd.find(anchor, i + 1)
        hits = sorted(set(hits))
        print(f"    验证通过候选 {len(hits)}" + ("（唯一 ✅）" if len(hits) == 1 else ""))
        for h in hits[:a.max]:
            print(f"    -> 新 RVA 0x{h:X}   (delta = {h - rva:+d})")
        if len(hits) == 1:
            results[name] = hits[0]
        if a.dis:
            print("    —— 源函数 ——")
            k = 0
            for ins in md.disasm(sd[so:so + 0x120], sbase + rva):
                print(f"       0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
                k += 1
                if k >= 18:
                    break
        print()
    if results:
        print("=== 迁移结果 ===")
        for k, v in results.items():
            print(f"  {k:22} 0x{v:X}  ({v})")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
