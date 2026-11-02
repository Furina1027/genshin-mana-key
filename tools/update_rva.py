#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""update_rva.py — 游戏更新后，把钩子 RVA 自动迁移到新 exe 并写回源码。

双击 `update_rva.cmd` 就会调用本脚本。它做的事：

  1. 找**新 exe**：命令行参数 / `run\\game_path.txt` / 常见安装路径（可把新 exe 拖到 cmd 上）；
  2. 找**旧 exe**：命令行参数 / `rva_cache\\<exe名>`（脚本每次成功后会自动缓存一份）；
  3. 从 `inject/src/Application.cs` 读出当前常量（`Cn` / `Gl` 常量集），当作"旧 RVA"；
     **源码里某个常量是 0（上次迁移留下的"未定位"）时不再静默跳过** —— 要么显式警告
     并给恢复办法，要么用 `--old-rva NAME=0x…` 手给一个旧地址；
  4. 用 `tools/migrate_masked.py` 的掩码指纹迁移，把这些函数迁到新 exe —— 地址平移、
     编译器微调都不影响，**只采信唯一命中**；
  5. 多个候选时，用"同一个类整体平移量一致"消歧（只有和 NF 的位移差在 ±0x20000 内才认）；
  6. 表格确认后写回源码（自动备份 `Application.cs`），可选接着跑 `build.bat`；
  7. 把新 exe 缓存到 `rva_cache\\`，下次更新就有"旧 exe"可用；
  8. 把新 exe **头部 SizeOfHeaders 字节的 CRC32（zlib 口径）** 写回源码的 `Fingerprint`。
     口径必须是 `[0, SizeOfHeaders)`：只有这一段在文件与内存镜像里逐字节一致（固定 64KB 会
     把 `.text` 的原始数据算进去，而 DLL 运行时看到的是 0 填充 → 永远不匹配）。它是
     "源码里这些 RVA 属于这一版 exe"的断言，所以只在全部常量都迁移成功时才写 —— 有任何一个
     没迁上还写它，下一版就会拿到"版本对得上、地址却过期"的假绿灯（C# 侧挡不住）。

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
  python tools\\update_rva.py --new <新exe> --old-rva NativeSetFile=0x070538C0
      # 源码里该常量是 0（上次迁移失败）时，用它指定旧 RVA

退出码：0=成功（已写或 --dry-run 成功）；
        1=有函数没迁移成功（未写源码）或用户取消；
        2=参数/环境/PE 错误；
        3=**源码已写回**但 build.bat 失败（备份文件名会打印出来，别重跑迁移）。
"""
from __future__ import annotations

import argparse
import os
import re
import hashlib
import shutil
import subprocess
import struct
import sys
import time
import zlib

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
#: 源码已改、只是编译失败。与 EXIT_PARTIAL 分开，否则 cmd 会把"已写回"说成"未改动"，
#: 用户会以为源码没事而重跑迁移（那时旧 RVA 已经变成新值，指纹会拿新值去当旧 RVA）。
EXIT_BUILD_FAILED = 3

SOURCE = os.path.join(ROOT, 'inject', 'src', 'Application.cs')
CACHE_DIR = os.path.join(ROOT, 'rva_cache')
GAME_PATH_FILE = os.path.join(ROOT, 'run', 'game_path.txt')

# 迁移时取的指纹指令数（与 migrate_masked 默认一致）
FINGERPRINT_INSNS = 28
MIN_ANCHOR = 6
MAX_HITS = 12

#: ★ 指纹 = CRC32(exe 头部 **SizeOfHeaders** 字节)，不是"固定 64KB"，也不是整文件。
#:   原因（实测 7.1 国服）：FileAlignment=0x200 / SectionAlignment=0x1000，加载器只把文件
#:   开头 SizeOfHeaders 字节原样映射到模块基址，`[SizeOfHeaders, 0x1000)` 在内存镜像里是 0
#:   填充、在文件里是 .text 的原始数据 —— 于是"文件头 64KB"和"内存镜像头 64KB"不是同一段
#:   字节，DLL 运行时按镜像算出来的值永远对不上，每次启动都报"指纹不匹配"，比不做还糟。
#:   只有 `[0, SizeOfHeaders)` 这一段在文件与内存镜像里逐字节一致，所以口径取它。
#:   （7.1 国服：SizeOfHeaders=0x400 → 0xC66689B9；文件头 64KB 是 0xE597A764，两者不同。）
FINGERPRINT_MAX_BYTES = 0x10000        # 上限：防畸形 SizeOfHeaders 把整个 exe 读进来
FINGERPRINT_MIN_BYTES = 0x200          # 下限：比一个文件对齐还小就不可能装下 PE 头
FINGERPRINT_FALLBACK_BYTES = 0x400     # 头部自解析不可信时的兜底长度（= 典型 SizeOfHeaders）

# v20 起源码里只剩这一个 il2cpp RVA（诊断钩子已删除）。保留列表形式：
# 以后若新增钩子，往这里加名字（必须与 Application.cs RvaSet 的字段名一致）即可。
FUNCTION_ORDER = ['NativeSetFile']

BLOCK_RE = re.compile(
    r'(?s)(private static readonly RvaSet (?P<which>Cn|Gl) = new\(\) \{)(?P<body>.*?)(\n    \};)')
# ★ 值只认 0x 字面量（Application.cs 那边配合：未登记的指纹也写成 `0x00000000`，不写裸 0）。
#   别把这里放宽成"0x+十进制都能收"：写回格式是 0x%08X，混着来会让 diff 与注释对不上。
FIELD_RE = re.compile(r'(?m)^(?P<indent>\s+)(?P<name>\w+) = 0x(?P<rva>[0-9A-Fa-f]+)(?P<tail>,.*)$')
#: --old-rva 的 NAME=值（值交给 pe_utils.parse_int，接受 0x/十进制/裸十六进制）
OLD_RVA_RE = re.compile(r'^(?P<name>[A-Za-z_]\w*)=(?P<val>\S+)$')


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


def fingerprint_length(data: bytes) -> int:
    """头部指纹长度 = PE 的 **SizeOfHeaders**（与 C# VersionGuard.FingerprintLength 同一套判据）。

    为什么不是固定 64KB：加载器只把文件开头 SizeOfHeaders 字节原样映射到模块基址，
    之后的 `[SizeOfHeaders, SectionAlignment)` 在内存里是 0 填充、在文件里是段数据。
    DLL 在运行时读的是镜像，所以只有 `[0, SizeOfHeaders)` 两边逐字节一致。

    判据（任何一步不可信就退回 FINGERPRINT_FALLBACK_BYTES，绝不靠猜）：
      1) `len(data) < 0x40` —— 连 DOS 头都没有；
      2) `e_lfanew = u32@0x3C` 必须在 `[0x40, 0x1000]`；
      3) `u32@e_lfanew == 0x4550`（`PE\\0\\0`）；
      4) `SizeOfHeaders = u32@(e_lfanew + 0x18 + 0x3C)`（可选头起 + 0x3C，PE32/PE32+ 同偏移）；
      5) 它必须落在 `[MIN, MAX]`，否则退回兜底；合法时**原样返回**（不夹到 `len(data)`）。

    ★ 不夹的理由：声明比实际可读字节多，说明这份文件/镜像的头部不完整，两边算不出同一个
      数。夹一下凑出一个 CRC 只会变成假绿灯或永久误报 —— 交给 :func:`exe_fingerprint`
      判"算不出来（None）"，与 C# 侧"跳过校验 + 打日志"同语义。
    """
    if len(data) < 0x40:
        return FINGERPRINT_FALLBACK_BYTES
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if not 0x40 <= e_lfanew <= 0x1000:
        return FINGERPRINT_FALLBACK_BYTES
    if len(data) < e_lfanew + 0x58:            # 4 字节签名 + 20 文件头 + 可选头 0x3C..0x40
        return FINGERPRINT_FALLBACK_BYTES
    if struct.unpack_from('<I', data, e_lfanew)[0] != 0x4550:
        return FINGERPRINT_FALLBACK_BYTES
    size_of_headers = struct.unpack_from('<I', data, e_lfanew + 0x18 + 0x3C)[0]
    if not FINGERPRINT_MIN_BYTES <= size_of_headers <= FINGERPRINT_MAX_BYTES:
        return FINGERPRINT_FALLBACK_BYTES
    return size_of_headers


def head_span(path: str) -> tuple[int, int]:
    """返回 (声明的头部长度, 实际读到多少字节)，只给"跳过指纹登记"的提示文案用。"""
    with open(path, 'rb') as fh:
        head = fh.read(FINGERPRINT_MAX_BYTES)
    return fingerprint_length(head), len(head)


def exe_fingerprint(path: str) -> int | None:
    """CRC32(exe 头部 SizeOfHeaders 字节)，与 C# 侧 VersionGuard 的登记值同一口径。

    只读头部最多 `FINGERPRINT_MAX_BYTES`（实际只算 SizeOfHeaders 个字节）：这几百字节里有
    PE 头、节表、入口点这些"每次构建都变"的东西，而 400MB 的 il2cpp 代码段不进 CRC ——
    424MB 的 exe 也一样是毫秒级。

    返回 **None** 表示"这段字节凑不齐，算不出可信指纹"（声明的 SizeOfHeaders 大于实际可读
    字节）。这时**不许**退化成"夹到可读长度照算"：指纹的全部意义是"两边算出同一个数"，
    凑出来的值只会在 DLL 侧变成每次都报"版本指纹不匹配"，或更糟——变成一张假绿灯。
    """
    with open(path, 'rb') as fh:
        head = fh.read(FINGERPRINT_MAX_BYTES)
    length = fingerprint_length(head)
    if length > len(head):
        return None
    return zlib.crc32(head[:length]) & 0xFFFFFFFF


def parse_old_rva(entries: list[str]) -> dict:
    """解析可重复的 `--old-rva NAME=0xHEX`，返回 {名字: RVA}。

    用途：源码里某个常量是 0（上一轮迁移失败、C# 侧按"未定位"跳过）时，正常路径拿不到
    旧 RVA，整条迁移链就断了。这时用 `--old-rva NativeSetFile=0x070538C0` 手给一个旧地址，
    从 `Application.cs.bak-<时间戳>` 或 git 里抄。

    非法输入一律 `SystemExit`（与 read_constants 同风格）：这是参数错误，不写源码、
    也不该让后面的迁移带着半个清单跑。
    """
    out = {}
    for item in (entries or []):
        m = OLD_RVA_RE.match(str(item).strip())
        if not m:
            raise SystemExit(f'错误：--old-rva 需要 NAME=0xRVA 形式，收到 {item!r}')
        name = m.group('name')
        try:
            value = pe_utils.parse_int(m.group('val'))
        except ValueError:
            raise SystemExit(
                f'错误：--old-rva {name} 的地址无法解析：{m.group("val")!r}'
                f'（要 0x 前缀或十进制）')
        if value <= 0:
            raise SystemExit(
                f'错误：--old-rva {name} 必须是正数，收到 {value}'
                f'（0 = "该服务器未定位"，拿它当旧 RVA 没有意义）')
        out[name] = value
    return out


def plan_fingerprint(consts: dict, failures: list, todo: list,
                     new_exe: str) -> tuple[int | None, str]:
    """决定这次要不要把新 exe 的指纹写回源码：返回 (值或 None, 一句给人看的原因)。

    ★ 只在**全部常量都迁移成功**时才登记。Fingerprint 的语义是"源码里这些 RVA 属于这一版
      exe"；有任何一个没迁上还写它，下一版拿到的是"版本对得上、地址却过期"的假绿灯 ——
      比不登记危险得多（C# 侧只剩序言校验能兜，而那是最不可靠的一环）。
    """
    if 'Fingerprint' not in consts:
        return None, '· 源码是旧格式（RvaSet 里没有 Fingerprint 字段），跳过指纹登记'
    if failures or not todo:
        return None, '· 有常量没迁移成功，本次不写回 Fingerprint（避免登记成假绿灯）'
    try:
        fingerprint = exe_fingerprint(new_exe)
        if fingerprint is None:
            declared, actual = head_span(new_exe)
            return None, (f'⚠ 头部声明 SizeOfHeaders={declared} > 实际可读 {actual} 字节，'
                          f'跳过指纹登记（RVA 仍然照常迁移）')
    except OSError as exc:
        return None, f'⚠ 算新 exe 指纹失败（本次不写 Fingerprint）：{exc}'
    return fingerprint, ''


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
    ap.add_argument('--old-rva', dest='old_rva', action='append', default=[],
                    metavar='NAME=0xHEX',
                    help='手给某个常量的旧 RVA（可重复）。源码里该常量是 0（上次迁移失败、'
                         'C# 侧按"未定位"跳过）时用它，否则这一项没有可迁移的起点；'
                         '旧值可从 Application.cs.bak-<时间戳> 或 git 里抄。'
                         '例：--old-rva NativeSetFile=0x070538C0')
    a = ap.parse_args()

    # 参数错误要在解析几百 MB 的 exe 之前就报出来（也保证退出码是 2 而不是 1）。
    try:
        overrides = parse_old_rva(a.old_rva)
    except SystemExit as exc:
        print(str(exc) or '错误：--old-rva 参数非法', file=sys.stderr)
        return EXIT_PARAM

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

    # 参照 exe 的身份核对：源码登记的 Fingerprint 应该是**旧 exe**（迁移参照）的指纹。
    # 对不上 = 拿错了参照（例如 rva_cache 里已经是上一版），此时"旧 RVA"和参照二进制不是
    # 同一份，迁移出的地址没有意义 —— 必须说清楚，不能让它悄悄跑完。
    registered = consts.get('Fingerprint', 0)
    old_fp, old_fp_readable = None, True
    try:
        old_fp = exe_fingerprint(old_exe)
    except OSError as exc:
        old_fp_readable = False
        print(f'  ⚠ 读旧 exe 指纹失败（继续）：{exc}')
    if old_fp is None and old_fp_readable:
        # 与 plan_fingerprint 同一句话：算出来的数两边不可能一致，那就不算（不许凑）。
        declared, actual = head_span(old_exe)
        print(f'  ⚠ 头部声明 SizeOfHeaders={declared} > 实际可读 {actual} 字节，'
              f'跳过指纹登记（RVA 仍然照常迁移）')
    elif old_fp is not None:
        if not registered:
            print(f'  · {which}.Fingerprint 未登记（0）：跳过参照核对，旧 exe 指纹 '
                  f'0x{old_fp:08X}')
        elif registered != old_fp:
            print(f'  ⚠ {which}.Fingerprint = 0x{registered:08X}，但旧 exe 实际是 '
                  f'0x{old_fp:08X} —— 参照 exe 与源码登记的不是同一版，迁移结果可能对不上'
                  f'源码里的 RVA（先确认 --old / rva_cache 里放的是不是上一版）')

    for name in overrides:
        if name not in FUNCTION_ORDER:
            print(f'  ⚠ --old-rva 里的 {name} 不在迁移清单 {FUNCTION_ORDER} 里，忽略')

    # 逐个常量决定"拿什么当旧 RVA"。源码里是 0 的项不再静默跳过：那是上一轮迁移的
    # 失败痕迹，静默跳过等于把"这一版没钩子"当成结论。
    todo = []
    for name in FUNCTION_ORDER:
        cur = consts.get(name, 0)
        if name in overrides:
            if cur and overrides[name] != cur:
                print(f'  ⚠ {name}: 源码 0x{cur:08X} 与 --old-rva 0x{overrides[name]:08X} '
                      f'不一致 → 按 --old-rva 迁移')
            elif not cur:
                print(f'  · {name}: 源码里是 0（上次迁移未定位）→ 用 --old-rva '
                      f'0x{overrides[name]:08X} 当旧 RVA')
            todo.append(name)
        elif cur:
            todo.append(name)
        else:
            print(f'  ⚠ {name}: 源码里 RVA = 0（"该服务器未定位此钩子"），没有可用的旧地址 → 跳过')
            print(f'     恢复办法：从 {os.path.basename(SOURCE)}.bak-<时间戳> 或 git 里抄回'
                  f'上一版的值，再用 --old-rva {name}=0x<旧RVA> 重跑本脚本')
    print(f'\n待迁移 {len(todo)} 个常量（源码现值或 --old-rva 当"旧 RVA"）\n')

    rows = []
    anchor_delta = None
    for name in todo:
        old_rva = overrides.get(name) or consts[name]
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
            print('  想手工救：从 Application.cs.bak-<时间戳> 或 git 里抄回旧 RVA，'
                  '再用 --old-rva <名字>=0x<旧RVA> 重跑本脚本。')
        print('  只用到 NativeSetFile 的话，它迁移成功就够了。')
    if not updates:
        # ★ 这个早退必须在"登记指纹"之前判断：否则 NF 失败、只有 Fingerprint 可写时，
        #   脚本会写成一次"成功"，而地址其实没迁上（下次就靠这个假指纹骗过版本核对）。
        print('没有可写回的常量，退出。')
        return EXIT_PARTIAL

    # Fingerprint 是"源码里这些 RVA 属于这一版 exe"的断言，所以只在**全部常量都迁移成功**
    # 时才登记；有任何一个没迁上还写它，下一版拿到的是"版本对得上、地址却过期"的假绿灯。
    fp_written, fp_why = plan_fingerprint(consts, failures, todo, new_exe)
    if fp_why:
        print(f'  {fp_why}')          # 原因自带 · / ⚠ 前缀，别在这里再加一层
    if fp_written is not None:
        updates['Fingerprint'] = fp_written
        print(f'  指纹：{which}.Fingerprint 0x{consts.get("Fingerprint", 0):08X} → '
              f'0x{fp_written:08X}（新 exe 头部 SizeOfHeaders 字节的 CRC32）')

    # 只有"文件名的那个钩子"（NF）是默认运行的关键；它失败才算硬失败。
    # 诊断类常量没迁上只给警告 —— 双击场景下不该因为 GMK_FULL 的诊断项变红。
    critical = any(name == 'NativeSetFile' for name, _why in failures)
    if a.dry_run:
        print('\n--dry-run：不写源码。')
        return EXIT_PARTIAL if critical else EXIT_OK

    if not a.yes and not ask(f'把上面 {len(updates)} 项'
                             f'{"（含 Fingerprint 指纹登记）" if fp_written is not None else ""}'
                             f'写回 {_rel(SOURCE)}？[y/N] '):
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
            # 这里源码**已经写回**了：报 EXIT_PARTIAL 会让 cmd 说"源码未改动"，
            # 用户带着旧认知重跑迁移，而此时的"旧 RVA"已经是刚写进去的新值。
            print(f'  注意：源码**已写回**（备份 '
                  f'{os.path.basename(backup) if backup else "无（本次值没变）"}），'
                  f'只是编译失败 —— 先按上面的错误修 build，别重跑迁移。')
            return EXIT_BUILD_FAILED
    else:
        print('  双击 build.bat 重新编译部署（或下次更新加 --build 自动跑）。')
    print('  实跑一轮验证：日志里应只有 1 行 hook NativeMethods_SetFile，播放能看到 ★★ 已配对。')
    return EXIT_PARTIAL if critical else EXIT_OK


if __name__ == '__main__':
    raise SystemExit(main())
