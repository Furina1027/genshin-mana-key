#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""update_rva.py — 游戏更新后，把钩子 RVA 自动迁移到新 exe 并写回源码。

双击 `update_rva.cmd` 就会调用本脚本。它做的事：

  1. 找**新 exe**：命令行参数 / `run\\game_path.txt` / 常见安装路径（可把新 exe 拖到 cmd 上）；
  2. 找**旧 exe**：命令行参数 / `rva_cache\\<exe名>`（脚本每次成功后会自动缓存一份）；
  3. 从 `inject/src/Application.cs` 读出当前常量（`Cn` / `Gl` 常量集），当作"旧 RVA"；
  4. 用 `tools/migrate_masked.py` 的掩码指纹迁移，把这些函数迁到新 exe —— 地址平移、
     编译器微调都不影响，**只采信唯一命中**；
  5. 多个候选时，用"同一个类整体平移量一致"消歧（只有和 NF 的位移差在 ±0x20000 内才认）；
  6. 表格确认后写回源码（自动备份 `Application.cs`），可选接着跑 `build.bat`；
  7. 把新 exe 缓存到 `rva_cache\\`，下次更新就有"旧 exe"可用。

v20 起源码里只剩 1 个 il2cpp RVA（NativeSetFile，文件名来源）——诊断钩子已随
2026-10 的清理一起删除，本脚本的迁移清单也缩到 1 项。

提示：NF 的真名是 `CriWare.CriMana.Player.NativeMethods_SetFile`（CRI 包装类不受
混淆影响）。genshin-metadata 项目的 `cn/out/methods.csv` 有全量 名字→RVA 表，
可以直接按名直读新版本的 RVA，再用本脚本的结果做交叉校验。

用法：
  python tools\\update_rva.py                      # 交互（双击 cmd 就是这个）
  python tools\\update_rva.py --new <新exe> --old <旧exe>
  python tools\\update_rva.py --new <新exe> --yes   # 不问直接写
  python tools\\update_rva.py --new <新exe> --dry-run   # 只看结果不写
  python tools\\update_rva.py --new <新exe> --build    # 写完后跑 build.bat

退出码：0=成功（已写或 --dry-run 成功）；1=有函数没迁移成功（未写源码）；2=参数/环境错误。
"""
from __future__ import annotations

import argparse
import os
import re
import hashlib
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

try:
    import pe_utils            # noqa: E402
    import pdata               # noqa: E402
    import migrate_masked      # noqa: E402
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64   # noqa: E402
except ImportError as exc:     # pragma: no cover - 取决于运行环境
    print(f'错误：缺少第三方依赖（{exc}）。先运行：pip install -r tools\\requirements.txt',
          file=sys.stderr)
    raise SystemExit(2)

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_PARAM = 2

SOURCE = os.path.join(ROOT, 'inject', 'src', 'Application.cs')
CACHE_DIR = os.path.join(ROOT, 'rva_cache')
GAME_PATH_FILE = os.path.join(ROOT, 'run', 'game_path.txt')

# 迁移时取的指纹指令数（与 migrate_masked 默认一致）
FINGERPRINT_INSNS = 28
MIN_ANCHOR = 6
MAX_HITS = 12

# v20 起源码里只剩这一个 il2cpp RVA（诊断钩子已删除）。保留列表形式：
# 以后若新增钩子，往这里加名字（必须与 Application.cs RvaSet 的字段名一致）即可。
FUNCTION_ORDER = ['NativeSetFile']

BLOCK_RE = re.compile(
    r'(?s)(private static readonly RvaSet (?P<which>Cn|Gl) = new\(\) \{)(?P<body>.*?)(\n    \};)')
FIELD_RE = re.compile(r'(?m)^(?P<indent>\s+)(?P<name>\w+) = 0x(?P<rva>[0-9A-Fa-f]+)(?P<tail>,.*)$')


def _rel(path: str) -> str:
    """尽量显示成相对仓库根的路径；跨盘符等无法相对化时退回文件名。"""
    try:
        return os.path.relpath(path, ROOT)
    except ValueError:
        return os.path.basename(path)


def is_pe(path: str) -> bool:
    try:
        with open(path, 'rb') as fh:
            return fh.read(2) == b'MZ'
    except OSError:
        return False


def detect_server(exe: str) -> str:
    name = os.path.basename(exe).lower()
    return 'Gl' if 'genshinimpact' in name else 'Cn'


def read_game_dir() -> str | None:
    """从 run\\game_path.txt 读游戏目录（允许 # 注释与空行）。"""
    try:
        with open(GAME_PATH_FILE, 'r', encoding='utf-8') as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith('#'):
                    return line
    except OSError:
        return None
    return None


def find_new_exe(argv_path: str | None) -> str | None:
    if argv_path:
        return os.path.abspath(argv_path) if is_pe(argv_path) else None
    base = read_game_dir()
    if base:
        cands = [base]
        if os.path.isdir(base):
            for nm in ('YuanShen.exe', 'GenshinImpact.exe'):
                cands.append(os.path.join(base, nm))
        for c in cands:
            if os.path.isfile(c) and is_pe(c):
                return os.path.abspath(c)
    return None


def find_old_exe(new_exe: str, argv_path: str | None) -> str | None:
    if argv_path:
        return os.path.abspath(argv_path) if is_pe(argv_path) else None
    name = os.path.basename(new_exe)
    cached = os.path.join(CACHE_DIR, name)
    if os.path.isfile(cached) and is_pe(cached):
        return cached
    return None


def read_constants(path: str, which: str) -> dict:
    """从 Application.cs 读某个常量集里的 名字 -> RVA（int）。"""
    with open(path, 'r', encoding='utf-8') as fh:
        text = fh.read()
    for m in BLOCK_RE.finditer(text):
        if m.group('which') != which:
            continue
        out = {}
        for f in FIELD_RE.finditer(m.group('body')):
            out[f.group('name')] = int(f.group('rva'), 16)
        return out
    raise SystemExit(f'错误：在 {path} 里找不到 RvaSet {which} 块')


def ask(prompt: str, default: bool = False) -> bool:
    try:
        ans = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not ans:
        return default
    return ans in ('y', 'yes', '是', '好', '确定')


def migrate(md, spe, dpe, sbounds, dbounds, name: str, rva: int) -> dict:
    return migrate_masked.migrate_one(
        md, spe, spe.data, spe.image_base, sbounds,
        dpe.data, dpe, dbounds, name, rva,
        FINGERPRINT_INSNS, MIN_ANCHOR, MAX_HITS, False)


def pick(res: dict) -> tuple[int | None, str]:
    """只采信"唯一命中"。不唯一时**绝不自动猜** —— 交给 candidates() 让用户选。"""
    if res['status'] == 'ok':
        return res['hits'][0]['rva'], '唯一命中'
    if res['status'] == 'ambiguous':
        return None, f'不唯一（{res.get("hit_count", len(res.get("hits", [])))} 个候选，需手选）'
    return None, res.get('reason', res['status'])


def candidates(res: dict, anchor_delta: int | None) -> list:
    """把候选整理成 [(rva, delta, 与锚位移差)]，按"离锚越近越靠前"排序。

    位移差只用来**提示**（同一个类的函数在二进制里挨得很近），不作为自动判断依据：
    实测 7.0↔7.1 时正确与错误候选的位移差只有 1 KB 量级，机器分不出来。
    """
    out = []
    for h in res.get('hits', []):
        diff = None if anchor_delta is None else h['delta'] - anchor_delta
        out.append((h['rva'], h['delta'], diff))
    out.sort(key=lambda t: abs(t[2]) if t[2] is not None else 0)
    return out


def write_constants(path: str, which: str, updates: dict) -> tuple[list, str | None]:
    """把 updates 里的 名字->新RVA 写回源码；返回 (实际改动列表, 备份路径)。"""
    with open(path, 'r', encoding='utf-8') as fh:
        text = fh.read()
    changed = []
    out_parts = []
    last = 0
    for m in BLOCK_RE.finditer(text):
        if m.group('which') != which:
            continue
        body = m.group('body')
        new_body = []
        pos = 0
        for f in FIELD_RE.finditer(body):
            new_body.append(body[pos:f.start('rva')])
            old = int(f.group('rva'), 16)
            new = updates.get(f.group('name'))
            if new is not None and new != old:
                changed.append((f.group('name'), old, new))
                new_body.append(f'{new:08X}')
            else:
                new_body.append(f.group('rva'))
            pos = f.end('rva')
        new_body.append(body[pos:])
        out_parts.append(text[last:m.start('body')])
        out_parts.append(''.join(new_body))
        last = m.end('body')
    if not changed:
        return [], None
    out_parts.append(text[last:])
    backup = f'{path}.bak-{time.strftime("%Y%m%d-%H%M%S")}'
    shutil.copy2(path, backup)
    with open(path, 'w', encoding='utf-8', newline='') as fh:
        fh.write(''.join(out_parts))
    return changed, backup


def main() -> int:
    ap = argparse.ArgumentParser(description='游戏更新后自动迁移钩子 RVA')
    ap.add_argument('new_exe', nargs='?', help='新 exe（也可把 exe 拖到 cmd 上）')
    ap.add_argument('--new', dest='new_opt', help='新 exe 路径')
    ap.add_argument('--old', dest='old_opt', help='旧 exe 路径（默认 rva_cache\\<exe名>）')
    ap.add_argument('--yes', action='store_true', help='不问，直接写回源码')
    ap.add_argument('--dry-run', action='store_true', help='只显示结果，不写源码')
    ap.add_argument('--build', action='store_true', help='写回后运行 build.bat')
    ap.add_argument('--force', action='store_true',
                    help='新 exe 与缓存的旧 exe 完全相同时也照跑（默认认为没更新，直接退出）')
    a = ap.parse_args()

    new_exe = find_new_exe(a.new_opt or a.new_exe)
    if not new_exe:
        print('错误：找不到新 exe。三选一：')
        print('  · 把新 exe 拖到 update_rva.cmd 上；')
        print('  · 命令行：python tools\\update_rva.py --new <新exe>；')
        print(f'  · 或把游戏目录写进 {GAME_PATH_FILE}')
        return EXIT_PARAM
    old_exe = find_old_exe(new_exe, a.old_opt)
    if not old_exe:
        print('错误：找不到旧 exe（指纹迁移必须有旧版本做参照）。')
        print(f'  把上一版的 exe 复制到：{os.path.join(CACHE_DIR, os.path.basename(new_exe))}')
        print('  或者：python tools\\update_rva.py --new <新exe> --old <旧exe>')
        print('  ⚠ 本脚本每次成功后会自动缓存一份新 exe，供下次更新使用。')
        return EXIT_PARAM
    if os.path.abspath(old_exe) == os.path.abspath(new_exe):
        print('错误：旧 exe 和新 exe 是同一个文件 —— 版本更新后必须保留一份旧 exe。')
        return EXIT_PARAM

    def sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()

    if not a.force:
        try:
            if sha256(old_exe) == sha256(new_exe):
                print('新旧 exe 内容完全相同 —— 版本没变，不需要更新（要强制跑加 --force）。')
                return EXIT_OK
        except OSError as exc:
            print(f'  ⚠ 计算 exe 哈希失败（继续）：{exc}')

    which = detect_server(new_exe)
    label = '国服 YuanShen.exe' if which == 'Cn' else '国际服 GenshinImpact.exe'
    print('=' * 66)
    print('GenshinManaKey RVA 更新')
    print(f'  新 exe: {new_exe}')
    print(f'  旧 exe: {old_exe}')
    print(f'  常量集: {which}（{label}）')
    print('=' * 66)

    try:
        consts = read_constants(SOURCE, which)
        spe = pe_utils.load_pe(old_exe)
        dpe = pe_utils.load_pe(new_exe)
    except (pe_utils.PEFormatError, OSError) as exc:
        print(f'错误：无法加载 PE：{exc}', file=sys.stderr)
        return EXIT_PARAM
    sbounds = pdata.load_function_bounds(spe)
    dbounds = pdata.load_function_bounds(dpe)
    seen_warn = set()          # 新旧 exe 往往同源，两份 warning 一模一样，去重
    for bounds in (sbounds, dbounds):
        if bounds is not None:
            for w in bounds.warnings:
                if w not in seen_warn:
                    seen_warn.add(w)
                    print(f'  ⚠ {w}')
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    todo = [n for n in FUNCTION_ORDER if consts.get(n)]
    print(f'\n待迁移 {len(todo)} 个常量（按 {os.path.basename(SOURCE)} 里的现值当"旧 RVA"）\n')

    rows = []
    anchor_delta = None
    for name in todo:
        old_rva = consts[name]
        res = migrate(md, spe, dpe, sbounds, dbounds, name, old_rva)
        new_rva, why = pick(res)
        row = dict(name=name, old=old_rva, new=new_rva, why=why, res=res)
        if name == 'NativeSetFile' and new_rva is not None:
            anchor_delta = new_rva - old_rva
        rows.append(row)

    # 不唯一的：把候选列出来让人选（脚本绝不自动猜；--yes / --dry-run 下一律跳过）
    if not a.yes and not a.dry_run:
        for row in rows:
            if row['new'] is not None or row['res']['status'] != 'ambiguous':
                continue
            cands = candidates(row['res'], anchor_delta)
            print(f"[{row['name']}] 旧 RVA 0x{row['old']:08X} —— 指纹命中 {len(cands)} 处，需要你选：")
            for i, (rva, delta, diff) in enumerate(cands, 1):
                near = '' if diff is None else f'（与 NF 位移差 {diff:+#x}）'
                print(f'  {i}) 0x{rva:08X}   Δ={delta:+#x}{near}')
            try:
                sel = input('  选哪个？直接回车 = 跳过：').strip()
            except (EOFError, KeyboardInterrupt):
                sel = ''
            if sel.isdigit() and 1 <= int(sel) <= len(cands):
                row['new'] = cands[int(sel) - 1][0]
                row['why'] = f'手动选定（候选 {sel}/{len(cands)}）'
            print()

    updates, failures = {}, []
    for row in rows:
        new_rva = row['new']
        if new_rva is not None and dbounds is not None:
            b = dbounds.containing(new_rva)
            row['start'] = b.start == new_rva if b is not None else False
            row['size'] = b.size if b is not None else 0
        else:
            row['start'], row['size'] = False, 0
        if new_rva is None or not row['start']:
            failures.append((row['name'],
                             row['why'] if new_rva is None else '新地址不是函数起点'))
            continue
        updates[row['name']] = new_rva

    # ★ 没迁上的常量一律写 0，不能留着旧值：
    #   C# 侧对 0 的语义是"该服务器未定位此钩子 → 跳过并打日志"（RvaSet 的约定），
    #   而留着旧 RVA 更危险 —— 版本更新后它仍可能通过"可执行节+可读+序言"三项校验，
    #   于是把补丁打到**别的函数**上（错得不声不响）。NF 例外：它没迁上就不写任何东西，
    #   让脚本以非 0 退出，避免把唯一的文件名来源关掉。
    zeroed = []
    for name, _why in failures:
        if name != 'NativeSetFile':
            updates[name] = 0
            zeroed.append(name)

    print(f'{"常量":<26}{"旧 RVA":<12}{"新 RVA":<12}{"大小":>7}  说明')
    print('-' * 96)
    for row in rows:
        if row['name'] in zeroed:
            new_txt = '0（跳过）'
        elif row['new'] is not None:
            new_txt = f"0x{row['new']:08X}"
        else:
            new_txt = '—'
        mark = '' if row.get('start') else '  ✗'
        sz = f"{row['size']}" if row.get('size') else ''
        print(f"{row['name']:<26}0x{row['old']:08X}  {new_txt:<12}{sz:>7}  {row['why']}{mark}")

    print()
    if failures:
        print(f'⚠ {len(failures)} 个常量没迁移成功：')
        for name, why in failures:
            print(f'    · {name}: {why}')
        if zeroed:
            print(f'  这 {len(zeroed)} 项会写成 0 = 运行时"未定位 → 跳过"（不会打下错的补丁）。')
            print('  想手工救：看 .bak-<时间戳> 备份里的旧值，或用 tools\\align_class.py 整类对齐。')
        print('  只用到 NativeSetFile 的话，它迁移成功就够了。')
    if not updates:
        print('没有可写回的常量，退出。')
        return EXIT_PARTIAL

    # 只有"文件名的那个钩子"（NF）是默认运行的关键；它失败才算硬失败。
    # 诊断类常量没迁上只给警告 —— 双击场景下不该因为 GMK_FULL 的诊断项变红。
    critical = any(name == 'NativeSetFile' for name, _why in failures)
    if a.dry_run:
        print('\n--dry-run：不写源码。')
        return EXIT_PARTIAL if critical else EXIT_OK

    if not a.yes and not ask(f'把上面 {len(updates)} 项写回 {_rel(SOURCE)}？[y/N] '):
        print('已取消（未改动源码）。')
        return EXIT_PARTIAL

    changed, backup = write_constants(SOURCE, which, updates)
    for name, old, new in changed:
        print(f'  {name:<26} 0x{old:08X} -> 0x{new:08X}')
    if backup:
        print(f'  已写回 {_rel(SOURCE)}（备份：{os.path.basename(backup)}）')
    elif not changed:
        print('  源码里的常量本来就等于新值，未改动。')

    # 缓存新 exe，供下次更新当"旧 exe"
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        cached = os.path.join(CACHE_DIR, os.path.basename(new_exe))
        shutil.copy2(new_exe, cached)
        print(f'  已缓存新 exe 到 {_rel(cached)}（下次更新用它当旧版）')
    except OSError as exc:
        print(f'  ⚠ 缓存新 exe 失败：{exc}')

    print('\n下一步：')
    if a.build:
        print('  运行 build.bat …')
        rc = subprocess.call([os.path.join(ROOT, 'build.bat')], cwd=ROOT, shell=True)
        print(f'  build.bat 退出码：{rc}' + ('（成功）' if rc == 0 else '（失败，看上面输出）'))
        if rc != 0:
            return EXIT_PARTIAL
    else:
        print('  双击 build.bat 重新编译部署（或下次更新加 --build 自动跑）。')
    print('  实跑一轮验证：日志里应只有 1 行 hook NativeMethods_SetFile，播放能看到 ★★ 已配对。')
    return EXIT_PARTIAL if critical else EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
