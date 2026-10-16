# GenshinManaKey — 原神 7.1 过场动画（USM / CRI Mana）解密密钥截获工具

Hook 游戏内 CRI Mana 播放器的**设 key API**，在过场动画真正播放时截获**最终解密密钥**，
并按"正在播放的文件"自动配对，直接产出可并入 key 库的 JSON。

结构仿照崩铁的 `mana_key_stable`（本身就是仿 `YaeAchievement` 的注入框架）。

## 为什么原神 7.1 需要它

| 版本 | 视频加密体系 | 密钥来源 |
|---|---|---|
| ≤ 7.0 | 旧体系（56 位 vkey 掩码），`finalKey = (vk + hash(文件名)) & 0xFFFFFFFFFFFFFF` | **离线可推**（内容组 → vk，见 `OBHJLPCPECM_field11_12.json`） |
| **7.1** | **AES_HCA / method2**：AES-128-CTR，nonce 在文件 `VIDEO_HDRINFO` 里，加密区 `payload[0x40:]` | **服务器按需下发**，离线推不出来 |

证据链（都是静态实证，不是猜的）：

1. **7.0 的 `CriWare.CriMana.Player` 里根本没有设 key 的方法**（dump70.cs 全类 104 个方法逐个看完）。
2. 7.1 的 metadata 字符串池里，该类**新增**了这些名字：
   `videoKey` / `audioKey` / `SetVideoAudioDecryptionKeys` / `videoAesKey` /
   `SetVideoAesKeyAudioDecryptionKey` + 对应的 `video_key` / `audio_key` /
   `NativeMethods_SetVideoAudioDecryptionKeys` / `video_aes_key` /
   `NativeMethods_SetVideoAesKeyAudioDecryptionKey2`。
3. 用 7.0↔7.1 的方法指纹序列对齐，该类**净新增 4 个方法**，全部落在这两组 P/Invoke 上。
4. 两个原生包装的 P/Invoke 描述符里写着模块名与入口名：
   `cri_ware_unity!CRIWARE948D1068`（video+audio 两个 ulong）与
   `cri_ware_unity!CRIWARE1E4885A8`（AES byte[] + audio ulong）。
5. 7.1 客户端里**搜不到**崩铁那套 `VideoAES_Seed` / `VideoAES_yzt89k1huq` 之类的种子/盐字面量
   → 原神**不走**"字面量 PBKDF2 离线派生"，只能运行时截获或抓服务器包。

⇒ 这 11 个 method2 文件用旧体系解不开**不是方法问题，是体系换代**。

## Hook 一览（RVA 相对 exe 基址，均已双服交叉验证）

| 钩子 | 方法 | 国服 YuanShen.exe | 国际服 GenshinImpact.exe |
|---|---|---|---|
| S2 | `SetVideoAudioDecryptionKeys(ulong videoKey, ulong audioKey)` | `0x070546F0` | `0x070515D0` |
| S3 | `SetVideoAesKeyAudioDecryptionKey(byte[] aesKey, ulong audioKey)` | `0x07054B80` | `0x07051A60` |
| N2 | `NativeMethods_SetVideoAudioDecryptionKeys(int, ulong, ulong)` | `0x070547F0` | `0x070516D0` |
| N3 | `NativeMethods_SetVideoAesKeyAudioDecryptionKey2(int, byte[], ulong)` | `0x07054A70` | `0x07051950` |
| NF | `NativeMethods_SetFile(int, IntPtr binder, string path)` → **文件名** | `0x070538C0` | `0x070507A0` |

> ⚠️ 与崩铁的关键差异：原神的 IL2CPP 代码**在 exe 里**（`il2cpp` 段），
> **没有 GameAssembly.dll**；而且 exe **不导出任何 il2cpp_\* API**（只有 4 个导出）。
> 所以只能走 RVA 路线，不能运行时按类名反射找方法。

> 📌 两套 RVA 已内置在 `inject/src/Application.cs` 的 `Cn` / `Gl` 常量集里，按主模块名
> （`YuanShen.exe` / `GenshinImpact.exe`）自动选择，日志会打印「生效 RVA 常量集 = …」。
> **国际服只有上表这 5 个核心钩子有 RVA**；其余诊断项没有交叉验证过的值，一律写 0 并跳过
> （日志里是 `[skip] … RVA=0（按设计跳过）`）—— 不拿猜测值去挂钩。
>
> 挂钩前会用 exe 自己的 PE 节表校验 RVA 落在**可执行节**内、地址可读、序言合法；
> 任一步不过就跳过并打印「RVA 可能已过期」。游戏更新后 RVA 失效时，是"少挂钩"而不是"崩游戏"。

## 钩子开关（默认只挂核心，诊断要显式打开）

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `GMK_FULL=1` | 关 | 挂 9 个诊断钩子（含托管 `SetFile`、`CriWareDecrypter`、`CriManaPlugin`、`KeyFeed`）。**会显著扩大 il2cpp 代码补丁面积**；v3 实测大面积补丁会导致视频放不出来，只在定位新密钥来源时开 |
| `GMK_BC=0` | 开 | 关掉 `bcrypt.dll`（系统库）钩子。默认运行**唯一真正产出密钥**的就是这条路径，所以它不跟诊断钩子一起门控 —— 除非事实证明系统库补丁也影响播放，否则不要关 |
| `GMK_FS=1` | 关 | 启动 CRI FS 侦察线程。实测该线程会让视频无法播放，仅用于调查 |
| `GMK_REUSE=1` | 关 | 打开「跨视频复用密钥」的补报。实测每个视频都会自己重建密钥对象并报 `BCKEY`（自带文件名），补报只会在换新钥匙时抢跑误报，仅当某个视频一条 `BCKEY` 都没有时才需要它（见下面「同一把密钥可能覆盖多个视频」） |

默认运行 = **5 个核心 il2cpp 补丁 + 1 个 bcrypt 系统库补丁**。

## 使用（需要管理员，游戏必须已关闭）

```
cd run
ManaKeyDumper.exe                          # 按下面的顺序找游戏
ManaKeyDumper.exe <游戏目录 或 exe 全路径>   # 显式指定（优先级最高）
```

**推荐：直接双击 `run\ManaKeyDumper.exe`**（它自己会弹 UAC）。找游戏的顺序：

1. 第一个命令行参数 —— **游戏目录**或 exe 全路径都行；
2. `run\game_path.txt` —— 双击没法传参数，所以把路径写在这个**本地文件**里（支持 `#` 注释与空行）；
3. 通用默认安装路径（`C:\` / `D:\` 的国服/国际服）。

> `game_path.txt` **不会进仓库**（`run\` 整体被 `.gitignore` 覆盖，文件名也单独列了一条）——
> 个人安装路径不该提交到公开仓库。启动日志会写明这次用的是哪个来源（`来源：game_path.txt` 之类）；
> 显式来源一旦给出就以它为准，解析不出来直接报错，不会静默换成别的路径。

进游戏播放加密过场动画（例：内容组 3003 的 300317-300321）。实时输出两份文件：

- `run\mana_keys.log` — 原始事件（`MANAKEY*` / `MANAFILE*` 行，去重后落盘）
- `run\paired_keys.json` — **按文件名配对**的密钥（累积写入，可直接并入 key 库）：
  `{ "文件名": {"aes": "<32hex>", "audio": "<16hex>"} }`

四个产物（`mana_keys.log` / `paired_keys.json` / `dumper.log` / `dump\`）全部锚定在 **exe 所在目录**，
不管从哪个工作目录启动都一样。

几个可靠性细节（都是踩过的坑）：

- `paired_keys.json` 是**原子写**（同目录临时文件 → 落盘 → 原子替换）。直接截断重写时，
  进程/游戏在写入中途挂掉就会把累积了整场会话的密钥库一次清零。
- 密钥**先于**文件名到达时会排队而不是覆盖（旧实现只有一个暂存槽，第二把密钥一到就把第一把
  静默丢掉，表现为某些视频永远配不上 key 且毫无报错）。
- `MANAFILE` 报来的是 il2cpp 字符串解析失败哨兵（`(null)` / `(unreadable)` …）时会被拒绝，
  不会把 `"(null)"` 这种脏键写进密钥库。
- `paired_keys.json` 若被外部改坏，读到时会把原文件备份成 `paired_keys.json.corrupt-<时间戳>`
  再从空表继续 —— 宁可少几条，绝不覆盖。
- **同一把密钥可能覆盖多个视频**：CRI 的 cipher 是全局单例，实测确实存在同钥的视频
  （`Cs_ZD_AQ70201201_SLT` 与 `Cs_ZD_AQ70201101_RTF_Girl` 都是 `F5AC17FF…`，
  后者的 BCENC 密钥流用这把钥匙能逐字节对上）。但**每个视频开始播放时 CRI 都会重建一次密钥对象**，
  `BCKEY` 那行自带文件名，所以上报口径是「**文件名 + 密钥**」：同钥的另一个视频照样会自己报一条。
- 因此**"跨视频同钥补报"（`BCKEY reuse#N … reuse=1` 那行）默认关闭**。它会在换视频的瞬间把
  **上一个视频的**钥匙顶着新文件名报出去：实测 2026-10-16 23:35 的 `Cs_ZD_AQ70171401_UR_Girl`
  先报了 `F5AC17FF…`（错，抢跑）、同一秒再报 `F9E9E1C5…`（对），前台因此多出一条错误的"已配对"
  （`paired_keys.json` 按文件名覆盖，最终留下的仍是正确值；但真钥匙若恰好没到，错误条目会永久留下）。
  要启用这个兜底（万一某个视频一条 `BCKEY` 都没有）设 `GMK_REUSE=1`。

每个视频记录一次 key（launcher 侧按「文件 + 密钥」去重）。

## 前台显示：游戏窗口左下角的实时日志遮罩

默认开启。启动器是 **GUI 子系统（WinExe）**，所以双击 exe 或走 `run_genshin_mana_key.cmd`
**都不会出现任何控制台/命令行窗口**（那个 cmd 现在是启动完立刻自行退出）。
实时日志显示在游戏窗口左下角的遮罩里，**只显示配对成功那一行**：

```
[23:00:33 INF] ★★ 已配对(掩码) Cs_ZD_AQ70201201_SLT → paired_keys.json (F5AC17FFE4B4B430553AE073EB8A8A1D)
```

**显示规则就两条**：

1. **只有 `Log.Pair` 那一行会上遮罩**（即"★★ 已配对…"）。其余日志 —— 管道诊断、注入过程、
   未采纳/未配对、错误 —— 一律只进 `dumper.log`，**碰不到屏幕**。
   理由：遮罩贴在游戏画面上，那几十行诊断没人会看，真正要一眼确认的只有
   "这个视频配上密钥了没有"。（致命错误另有 MessageBox 兜底，不会因为不上遮罩而看不见。）
2. **10 秒没有新的配对行 → 遮罩自动隐藏并清空**。像一条会自己消失的提示，不长期占着游戏画面；
   下次配对会重新出现，而且**只有新那一条**（上一条在隐藏时已清掉）。

格式照 BetterGI 的日志遮罩（也就是它 Serilog 输出模板的 `[{Timestamp:HH:mm:ss} {Level:u3}] {Message}`）：
`[时:分:秒 级别] 消息`。级别三档 `INF` / `WRN` / `ERR` 都在代码里实现了，只是按上面的规则
当前只有 `INF` 的配对行会出现在屏幕上。

> **后台 `dumper.log` 与它无关**：那边仍然是 `[MM-dd HH:mm:ss] 消息`，**所有**日志一行不少，
> 既没有级别字段也没有任何其它变化。两条路刻意不同：文件是追加写的、必须带日期才分得清两次运行，
> 而且是排障用的全量记录；屏幕上只要那一条结论。

样式照 BetterGI 的「日志遮罩」取（已对照其源码逐个核对），但**字号是 BGI 默认的两倍**
（BGI 的 `LogFontSize` 默认 12 DIP，这里是 24 DIP → 1080p 下 GDI 字符高度 19px）：字重 Normal、
文字 `LightGray`、深灰投影、左下角区域左上角锚定在 `20/1920` 与 `822/1080`、
有内容才显示（没内容时窗口直接收起）、行数增加时向下生长、最多 7 行。

> 字号翻倍会连带改两个上限，否则会真出问题：
> · **宽度上限 900 → 1500**：配对行在 19px 下要 ~1170px，还按 900 卡就会把密钥截掉（截掉等于提示白给）；
>   而且宽度现在还会被"窗口右沿 − 左边距 − 8px"二次约束，保证不会画到屏幕外。
> · **行数上限 11 → 7**：行距随字号变成 ~25px，从 y=822 往下只有 258px 可用，11 行会顶出屏幕下沿。

三个 GDI 专有的处理（WPF 会自动做，GDI 不会）：

- **逐字形回退 → 手工切段**：BGI 的字体链是 `Cascadia Mono, …, MiSans`，WPF 对**每个字形**
  依次尝试（拉丁命中 Cascadia Mono、中文落到 MiSans）。GDI 没这个机制，所以按"ASCII 段 / 非 ASCII 段"
  切成若干段、分别用两条链画 —— 于是 `★★ 已配对 Cs_ZD_… → paired_keys.json (F5AC…)` 里
  密钥与文件名仍然是等宽的（对得齐、方便肉眼核对），只有中文那几段换字体。
- **不按级别着色**：所有级别共用同一个颜色。这不是省略 —— BGI 的日志遮罩本身也不按级别着色
  （它的 sink 有 `theme` 参数可以按级别配色，但默认没启用），级别只体现为前缀的三个字母。
- **投影不是纯黑**：本遮罩的 alpha 是"亮度"算出来的，纯黑亮度 0 → alpha 0 → 全透明，
  等于没有投影。所以投影用 `#585858`：它 88 的亮度既是 alpha、也是它变暗的来源。
  想更重就调 `GMK_OVERLAY_SHADOW_COLOR`（`#6E6E6E` 更实、`#484848` 更轻），**不要往黑里调**。

### 想让字体与 BGI 完全一致（MiSans）

BGI 的中文用的是它**随包分发的 MiSans**，而 MiSans 在绝大多数机器上并没有安装。
启动器不打包字体（要保持单文件），但会在**启动时私有加载**一份字体文件
（`AddFontResourceExW` + `FR_PRIVATE`：只对本进程可见、不装进系统、不影响别的程序）：

```bat
rem 把 BGI 的字体拷到 exe 旁边就行，文件名不用改
copy "BetterGenshinImpact\Resources\Fonts\MiSans-Regular.ttf" run\
```

启动日志会显示 `已私有加载字体 MiSans-Regular.ttf（2 个字体，未安装到系统）` 与 `中文正文=MiSans`。
不拷也能用，中文自动退到系统雅黑。字体放在别处就用 `GMK_OVERLAY_FONT_FILE` 指过去；
若你的字体族名不是 `MiSans`，用 `GMK_OVERLAY_CJK_FONT` 指定族名。

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `GMK_OVERLAY=0` | 遮罩开 | 关掉遮罩；日志只在 `dumper.log` 里（要控制台再配 `GMK_CONSOLE=1`） |
| `GMK_CONSOLE=1` | 关 | **临时分配一个控制台窗口**并输出全量日志（排障用；文件日志一直不变） |
| `GMK_OVERLAY_SELFTEST=1` | 关 | **不启动游戏、不注入**，只在桌面左下角跑 30 秒：推两条配对 → 再推两条**普通日志**（验证它们不上屏）→ 10 秒后应自动隐藏 → 再推一条配对（验证只显示新那条）。用来确认位置/穿透/Alt+Tab/字体/两条显示规则 |
| `GMK_OVERLAY_TEXT_COLOR` | `LightGray` | 正文颜色：`#RRGGBB` / `#AARRGGBB` / 颜色名（`Silver`、`White`、`LightGreen`…）。`#AARRGGBB` 的 AA 折进 RGB 当"淡一档"用 |
| `GMK_OVERLAY_SHADOW_COLOR` | `#585858` | 投影颜色（往黑里调会**变透明**，见上） |
| `GMK_OVERLAY_MONO_FONT` | `Cascadia Mono,Consolas,Courier New` | 前缀与 ASCII 段的等宽候选链 |
| `GMK_OVERLAY_CJK_FONT` | `MiSans,Microsoft YaHei UI,Microsoft YaHei,SimSun` | 中文段的候选链（第一个被 GDI 真选中的生效） |
| `GMK_OVERLAY_FONT_FILE` | exe 旁边的 `MiSans-Regular.ttf` | 私有加载的字体文件，不装进系统 |

> **颜色这一路修过一个坑**：`UpdateLayeredWindow` + `AC_SRC_ALPHA` 要求源位图是 **预乘 alpha**
> 的，只写 alpha 而不把 RGB 乘上去的话，文字会比配置的颜色亮一大截 ——
> `LightGray` 在亮背景上会合成到 245 左右（就是一眼看去的"刺眼纯白"），
> 而且投影也被一起抬亮、暗边消失、整块糊成一片。现在 RGB 按 alpha 预乘，
> 正文才是真正的 `LightGray`，暗边也回来了（最亮像素 211 → 175 就是这一步的差别）。

实现要点：纯 Win32 分层窗口 + GDI（`LAYERED | TRANSPARENT | NOACTIVATE | TOOLWINDOW`，
**刻意不用 `TOPMOST`**），逐像素 alpha 由"亮度→alpha"合成；不引入 WPF/WinForms ——
WPF 不支持 NativeAOT，而这个启动器要保持单个自包含 exe。

**只出现在原神窗口上**（不会悬浮在别的程序之上）：把游戏窗口设为它的 owner，
并且只在**前台窗口是游戏**时才显示 —— 切到浏览器/桌面它会跟着消失，回到游戏 250ms 内自动回来。
位置每 250ms 校正一次跟随游戏窗口；日志的前台/后台分流在 `Log`
（`Write`/`Warn`/`Error` 只进后台，`Pair` 才上屏），
几何与字号换算是纯函数 `OverlayLayout`（可单测），显示内容、格式与空闲判定是纯函数 `OverlayLines`（可单测），
像素合成走 `OverlayAlpha`。

> 独占全屏（exclusive fullscreen）下分层窗口不可见，这是 D3D 的机制限制（BetterGI 的遮罩同理）。
> 那种模式请用 `GMK_CONSOLE=1` 看日志，或者把游戏改成窗口化/无边框窗口。

## 构建与测试

```
build.bat    # dotnet publish ×2 并部署到 run\（纯 ASCII，避免 GBK 控制台乱码）
             # 每一步都检查退出码与产物是否存在；失败时直接提示下面的 LIB 设置
```

单元测试（纯逻辑，不需要游戏、不注入任何进程）：

```
dotnet test tests\ManaKeyDumper.Tests\ManaKeyDumper.Tests.csproj
python -m unittest discover -s tools/tests -v
```

CI 见 `.github/workflows/ci.yml`：两个项目要求 **0 警告**构建、跑上面的单测，
并对 `tools/` 做依赖固定安装 + 逐脚本 `--help` 冒烟。

NativeAOT 编译若报 `LNK1181 ... .lib`，是 MSVC 库路径没进环境变量，需显式：

```
set LIB=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<ver>\lib\x64;^
        C:\Program Files (x86)\Windows Kits\10\Lib\<sdk>\um\x64;^
        C:\Program Files (x86)\Windows Kits\10\Lib\<sdk>\ucrt\x64
```

## 游戏版本更新后怎么重新定位 RVA

**不要**靠 dump.cs（米哈游的混淆 metadata 让 Il2CppDumper 直接报
`Metadata file not found or encrypted`）。用 `tools/` 里的自研链：

1. `tools/locate_hooks.py` — 由 CDN 下发的 `to_int32` RVA 反推 **methodPointer 表基址**
   （`表基址 = to_int32 指针所在文件偏移 − 1357×8`，1357 是 `ToInt32` 的全局方法索引），
   然后按索引直接读表拿 RVA。**索引会平移**，所以它会用多个已知参照项交叉验证候选基址
   （`--window` 搜索平移量），自洽解不唯一时报错退出，不会给出"看着合理其实是错的"RVA。
2. `tools/align_class.py` — 把上一版本的某个类**逐方法做掩码指纹对齐**，
   找出新版本新增的槽位（新增的就是新钩子）。
3. `tools/migrate_masked.py` — 单函数跨版本/跨服迁移（掩码指纹，`call/disp/imm` 通配），
   用来双服交叉验证：国服→国际服应一一对应。指纹按 `.pdata` 的函数边界截断，不会越读进下一个函数。
4. `tools/dump_rva.py` — 定点反汇编，看序言数参数个数（决定 hook 签名）。
5. `tools/read_str.py` — 读 P/Invoke 描述符里的模块名/入口名。

工程化约定（为了能脚本化/进 CI）：

- 依赖固定在 `tools/requirements.txt`（capstone / pefile / numpy / pycryptodome）。
- PE 加载与 RVA→文件偏移映射统一走 `tools/pe_utils.py`（**越界即抛**，不再用
  `max(VirtualSize, SizeOfRawData)` 那种会接受越界 RVA 的不可靠映射）；
  USM 解析统一走 `tools/usm.py`（只有一份 `parse_chunks`）。
- 所有脚本：`main()` 返回 int + `raise SystemExit(main())`，**定位失败返回非 0**；
  加 `--json` 便于脚本消费；`--help` 一律可用。
- 脚本自身的单测在 `tools/tests/`（`python -m unittest discover -s tools/tests -v`），
  包含合成 USM 的解密往返（含第一个 chunk 的偏移陷阱）、PE RVA 越界、CTR 计数器等价性。

## 目录

```
├── inject/    注入 DLL（hook + 管道上报），NativeAOT，导出 YaeMain
├── launcher/  启动器（挂起拉起 + 注入 + 配对写 paired_keys.json），NativeAOT
├── run/       ManaKeyDumper.exe/dll + 产物
├── tests/     启动器纯逻辑单测（配对状态机 + 密钥库读写，xunit）
└── tools/     自研 RVA 定位 / 引用分析 / USM 结构脚本（Python + capstone/pefile）
```

---

## 首轮实测（2026-09-23）与 v2 诊断版

### 首轮结果：钩子全挂上，但密钥函数一次都没被调用

```
[DLL] 原神主模块 base = 7FF6678F0000   服务: 国服 YuanShen.exe
[DLL] hook SetVideoAudioDecryptionKeys @ 0x7FF66E9446F0
[DLL] hook SetVideoAesKeyAudioDecryptionKey @ 0x7FF66E944B80
[DLL] hook NativeMethods_SetVideoAudioDecryptionKeys @ 0x7FF66E9447F0
[DLL] hook NativeMethods_SetVideoAesKeyAudioDecryptionKey2 @ 0x7FF66E944A70
[DLL] hook NativeMethods_SetFile @ 0x7FF66E9438C0   → ★ 播放时正常触发
```

- 客户端确认是 **7.1 国服**（exe 头 64KB CRC32 `0xE597A764`，与官方 CDN 下发的国服指纹一致）；
- 触发的文件是 `Cs_ZD_AQ70201201_SLT.usm` / `Cs_ZD_AQ70201101_RTF_Girl.usm`，
  **md5 与我们手上的样本完全一致**（就是那 11 个目标里的两个）；
- 但 **4 个设密钥函数 0 次调用**。

### 静态补充结论

- `tools/xref.py` 扫全 `il2cpp` 段（853 万处 `call rel32`）：4 个 P/Invoke 包装**调用点全为 0**
  （对照：`NativeMethods_SetFile` 有 1 处，来自托管 `SetFile`）。
  ⇒ **7.1 里这套 AES 设密钥 API 很可能是 CRIWARE Unity 插件升级带来的"API 面"，游戏并没有走它。**
- 视频确实被加密（不是明文）：把视频块拼成 IVF 交 ffmpeg，容器/首帧头可读
  （vp9 / 1920x1080），但后续帧 **缺 VP9 同步码 `49 83 42`**、报 `Invalid sync code`；
  而明文 VP9 每帧必带同步码。→ 原 method2/AES 判定成立。
- 结构旁证：音频是 `C8 C3 C1`（"HCA" 高位置 1）＝ **加密头的 HCA**，4 条音轨 × 4692 块。

### v2 诊断版做了什么

1. **先把全部钩子挂完、最后才放行主线程** —— 首轮是"先放行再挂钩"，
   会漏掉"游戏启动早期一次性设 key"的窗口（`CriWareDecrypter` 那类全局配置就发生在启动期）。
2. 挂钩面扩到：4 个 AES 密钥函数 + 托管 `SetFile` + 2 个同一 CRI 入口的第二个重载包装
   + 启动期 `CriWareDecrypter.Initialize(Config/str)`、`CRIWARE1859E5C2`、
   `CriManaPlugin.SetConfigParameters`、`SetConfigAdditonalParameters_PC`。
3. **对象字段扫描**：在 `SetFile` / `Decrypter.Initialize` 回调里扫对象内存，
   直接找「长度 8/16/24/32 且非全零」的字节数组（7.1 给 CriMana.Player 新增了 `videoKey/audioKey/videoAesKey` 字段），
   并 dump 对象前 0x80 字节。所有指针读取都先过 `VirtualQuery` 可读性校验，避免野指针崩游戏。

诊断输出形如：

```
OBJDMP Player obj=...  <0x80 字节 hex>
OBJKEY Player +0x0A8 len=16  <32 hex>
DIAG Decrypter.Initialize(Config) cfg=...
DIAG Plugin.SetConfigParameters a1=... a5=...
```

拿到这些行就能确定密钥的真实来源，再把钩子收敛到那一个点上。

---

## 第三轮修复（2026-10-16）

对 `run/dumper.log`（2026-10-16 10:30–10:38 的实测会话，450 行）逐行复盘后又修了一批，
其中**有一条正在阻止工具达成设计目标**：

### 1. 密钥其实已经抓到了，只是没有归属到文件名

会话日志里 `BCKEY #1..#60` 的密钥值完全一致（`458725216E2CCBCD12961E57B85109A6`），
但 `file=(null)`，最终 `paired_keys.json` 根本没生成。两个原因：

- **托管 `SetFile` 钩子参数错位**：CRI Mana 的签名是 `SetFile(CriFsBinder binder, string fileName)`，
  即 `arg0=this / arg1=binder / arg2=path`，旧实现把 `arg1` 当成了 path（日志里
  `DIAG SetFile self=… (null)` 就是读到的空 binder）。现在取 `arg2`，并且**唯一稳定触发的原生
  `NativeMethods_SetFile` 也会写一次归属**。解析失败时保留上一次有效文件名，不再写成 `"(null)"`。
- **硬编码日志上限**：`BCKEY` 的上限是「总条数 60」、`BCENC` 是 200，两个上限都在 4 秒内打满，
  之后游戏又跑了 4 分钟工具却完全静默 —— 而密钥是 per-video 的，第 61 个视频起就丢。
  现在 `BCKEY` 改成**按密钥内容变化上报**（同一把最多重复 3 条），`BCENC` 按内容指纹去重，
  都没有总条数上限。

### 2. 默认补丁面积回到设计值

`AttachDiagnostics()` 以前是**无条件**调用的（`GMK_FULL` 只用来打了一行日志），
默认运行实际往 il2cpp 段打了 **14** 处补丁而不是文档说的 5 处。现在诊断钩子真正被 `GMK_FULL=1` 门控。

唯一保留在默认路径的是 `bcrypt.dll`（系统库）钩子：日志统计显示该会话
`MANAKEY2/3/N2/N3` 与 `DECKEY` 全是 0 条，**唯一产出密钥的就是这条 BCKEY 路径**，
所以它不跟诊断钩子一起关；要排除它可用 `GMK_BC=0`。

### 3. 其它已修项

- **指针安全**：挂钩前用 exe 自己的 PE 节表校验 RVA 在可执行节内 + 地址可读 + 序言合法
  （旧实现只判断首字节，而且直接解引用 —— RVA 一失效就是访问违例带走游戏）。
- **异常可诊断**：89 处静默 `catch { }` 换成具名站点 + 限速上报 + 会话结束汇总
  （热路径不拼串、不加 lambda，零堆分配）。
- **`RestoreVirtualProtect`**：保护/写入长度 1 字节 → 8 字节，还原保护用独立变量。
  「校验 `mPtr-0x20`、写 `mPtr`」这个上游行为按原样保留并加了注释，**仍待有游戏的机器复核**。
- **启动器**：`paired_keys.json` 原子写 + `System.Text.Json`；损坏文件备份而非覆盖；
  配对暂存槽改队列；`MANAKEY*` 与 `MANAFILE*` 都落 `mana_keys.log`；路径统一到 exe 目录；
  `Log` 长驻写入器；`OnExit` 订阅提前；注入失败不再在库里 `Environment.Exit`；
  `Win32Exception` 带上真实错误码；删除作者本机绝对路径。
- **工具链**：抽 `pe_utils.py` / `usm.py` 共享模块，修 `max(VirtualSize, SizeOfRawData)` 越界映射、
  `locate_hooks.py` 的空转与未实现的 `--window`、`usm_frame_marker.py` 漏筛 `@SFV`（会把 HCA 音频
  混进判读）与除零、`usm_stream_extract.py` 第 0 帧的解密偏移（它的 payload 多含 32 字节 IVF 头，
  明文前缀是 `0x14` 而不是 `0x34`，与实测确认过的 `usm_decrypt.mjs` 对齐）。

### 仍未验证（需要有游戏的机器）

1. `bcrypt.dll` 系统库补丁是否影响视频播放 —— 未实测，故给了 `GMK_BC=0` 一键排除。
2. `AppDomain.CurrentDomain.ProcessExit` 在注入式 NativeAOT DLL 里能否触发 —— 未实测，
   因此异常汇总还有「每累计 100 次打一行」的兜底。
3. 国际服那 5 个 RVA 无法离线校验（本机只有国服客户端），值原样取自上面的表，未做任何推断。
4. 「默认只剩 5 个 il2cpp 补丁」是静态推演（`AttachCore` 内 5 处 `MinHook.Attach`），无运行实证。
5. 修好归属之后能否稳定产出 `paired_keys.json` —— **2026-10-16 18:14 已实测，见文末「实测结果」**。

---

## 实测结果（2026-10-16 18:14，国服 7.1）

这一轮把「密钥链路」从头到尾验证了一遍，结论：**DLL 侧抓取完全正确，缺口在启动器没接住 BCKEY**。

### 日志证据（`run\dumper.log` 里那一段）

```
[18:14:00] 游戏: ...\YuanShen.exe（国服 YuanShen.exe，来源：game_path.txt）   ← 双击免输入生效
[18:14:00] hook × 5 + BCRYPT [core] ...  诊断钩子未启用                    ← 默认补丁面积 = 设计值
[18:16:35] ★ 文件 [0]: Cs_ZD_AQ70201201_SLT
[18:16:35] MANAFILE [0] ...\Cs_ZD_AQ70201201_SLT.usm
[18:16:35] BCKEY #1 file=Cs_ZD_AQ70201201_SLT.usm len=16 F5AC17FFE4B4B430553AE073EB8A8A1D rep=1 uni=1
[18:16:35] BCENC #1 cbIn=16 cbIV=0 IN=AE86AE7B164984D60000000000000000 OUT=F48E3E4F20237446EE27F70DB2EF49B8
```

`file=` 从旧版的 `(null)` 变成了真实文件名，密钥也从「打满 60 条上限就静默」变成「同一把只报 3 次」——
**这两条修复都按设计生效了**。

### 独立交叉验证（离线，不复用本仓库代码）

| 验证 | 结果 |
|---|---|
| `AES-128-ECB(F5AC…)` 加密日志里的 counter 块 | 与日志 `OUT` **3/3 精确一致** → 该密钥就是视频密钥流的钥匙 |
| 日志推得的 nonce 与 `Cs_ZD_AQ70201201_SLT.usm` 文件内嵌 nonce | 都是 `AE86AE7B164984D6` |
| 用该密钥解该文件的视频块（`payload[0x40:]` + CTR） | 解密后出现 VP9 明文同步码 `49 83 42` **3 处**，密文里 **0 处** |

也就是说：**截获到的就是这把视频密钥，归属也是对的**。

### 当轮暴露的缺口：BCKEY 没被配对状态机接住

`paired_keys.json` 那一轮**没有生成**，日志结尾是「共截获 18 条事件，但本次没有配对出任何密钥」。
原因很具体：实际产出密钥的是 `BCKEY`（bcrypt 系统库通路，见上文「钩子开关」），
而启动器的配对状态机只认 `MANAKEY*` 行 —— 密钥一直在日志里，只是没人把它写进密钥库。

已修：`KeyPairing` 新增 `BCKEY` 分支（自带文件名，不需要跟 `MANAFILE` 配对），
`JsonStore.UpsertAes` 写 `{ "文件名": {"aes":"…"} }`。**为什么不写空的 audio 字段**：
BCKEY 只能拿到视频密钥，音频 key 属于那 4 个从未被调用的 `MANAKEY*` 钩子；
写 `"audio":""` 等于对下游宣称「音频 key 是空字符串」，会把一条错记录带进 key 库。

对应的回归测试：`ProgramFlowTests`（反射驱动 `Program.HandleMessage`，断言一条 `BCKEY` 上报
真的落进 `paired_keys.json`）、`KeyPairingTests`（`file=?` 必须拒绝、重复上报只留一条、大小写归一）。


