# GenshinManaKey — 原神过场动画（USM / CRI Mana）解密密钥截获工具

Hook 游戏内 CRI Mana 播放器的**设 key API**，在过场动画真正播放时截获**最终解密密钥**，
并按"正在播放的文件"自动配对，直接产出可并入 key 库的 JSON。

> 版本适配：**国服 7.2 已迁（`0x0717D410`），国际服仍是 7.1 的值（未复核）**。
> 每次游戏更新只需双击 `update_rva.cmd`，详见「版本更新后怎么把这些 RVA 重新找回来」。

结构仿照崩铁的 `hsr-mana-key`（本身就是仿 `YaeAchievement` 的注入框架）。

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

## Hook 一览（RVA 相对 exe 基址）

| 钩子 | 方法 | 国服 YuanShen.exe（**7.2**） | 国际服 GenshinImpact.exe（**7.1，未复核**） | 默认挂 |
|---|---|---|---|---|
| NF | `NativeMethods_SetFile(int, IntPtr binder, string path)` → **文件名** | `0x0717D410`（7.1 是 `0x070538C0`） | `0x070507A0` | ★ **是（唯一的 il2cpp 钩子）**；`GMK_STRICT=1` 且版本指纹不匹配时不挂 |
| — | `bcrypt.dll!BCryptGenerateSymmetricKey` → **key 本体**（系统库，无 RVA） | 导出地址，运行时解析 | 同左 | ★ 是 |
| — | `bcrypt.dll!BCryptEncrypt` → 密钥流验证（系统库，无 RVA） | 导出地址，运行时解析 | 同左 | ★ 是 |

> **7.2 的迁移（2026-11-02）**：`update_rva.py` 掩码指纹唯一命中 `0x070538C0 → 0x0717D410`，
> 落盘前三项静态复核全过 —— ① 落在 `.pdata` 函数起点；② 函数体 231 字节 / 57 条指令，
> 与 7.1 **逐字节一致**（只有 imm/disp 共 112 字节被通配，固定字节 0 处不同）；
> ③ `il2cpp` 段内唯一 `E8` 直接调用点在函数起点 −0x25，与 7.1 同一相对位置。

> **v20（2026-10-24）起诊断钩子全部删除。** 原有的 S2/S3/N2/N3 四个 MANAKEY 钩子与
> 9 个 GMK_FULL 侦察钩子实测（2026-10-16 多轮日志）要么 0 次调用、要么只服务逆向调查，
> 却每个版本都要迁移 RVA —— 已从源码移除（历史代码与 RVA 见 git，v19 及之前）。
> il2cpp 补丁面积恒为 1，`GMK_FULL` 开关随之取消。
>
> ⚠️ 与崩铁的关键差异：原神的 IL2CPP 代码**在 exe 里**（`il2cpp` 段），
> **没有 GameAssembly.dll**；而且 exe **不导出任何 il2cpp_\* API**（只有 4 个导出）。
> 所以只能走 RVA 路线，不能运行时按类名反射找方法。

> 📌 两套 RVA 已内置在 `inject/src/Application.cs` 的 `Cn` / `Gl` 常量集里，按主模块名
> （`YuanShen.exe` / `GenshinImpact.exe`）自动选择，日志会打印「生效 RVA 常量集 = …」。
>
> 挂钩前会用 exe 自己的 PE 节表校验 RVA 落在**可执行节**内、地址可读、序言合法；
> 任一步不过就跳过并打印「RVA 可能已过期」。游戏更新后 RVA 失效时，是"少挂钩"而不是"崩游戏"。

## 实际起作用的钩子（2026-10-16 默认配置实测）

> **本节也是历史记录**：命中数是那一轮 DLL 构建（v19 口径，默认 `hook × 5`）跑出来的，
> v20 已删除全部诊断钩子，**当前默认补丁面积只有 1 + 2**（见「钩子开关」）。
> 保留下面的表是为了留"为什么只剩 NF + bcrypt"的证据链，不代表现在的挂钩清单。

一整轮里每个钩子的**命中次数**（`run/dumper.log`，5 个视频）：

| 钩子 | 命中 | 作用 |
|---|---|---|
| `bcrypt.dll!BCryptGenerateSymmetricKey` | BCKEY 15 条（每视频 rep=1/2/3） | ★ **唯一的 key 来源**（16 字节 AES-128） |
| `NativeMethods_SetFile` @ `0x070538C0` | MANAFILE 5 条 | ★ **唯一的文件名来源**（key → 视频 归属） |
| `bcrypt.dll!BCryptEncrypt` | BCENC 15 条 | 只做密钥流验证（IN=计数块/OUT=密钥流），**不产出 key** |
| S2 / N2 / N3 | **0** | 方法存在、RVA 正确，但游戏不走这条托管 API |
| S3 | **0** | ⚠️ 旧值 `0x07054B80` 其实是 `Player.UpdateWithUserTime`（挂错，已修正为 `0x070548F0`） |
| 托管 `SetFile` / KeyFeed / DECKEY / CRICIPHER / CRIKEY | **0**（默认不挂） | 历史 `GMK_FULL=1` 轮次里 KeyFeed 命中 16 次，抓到的 CRIKEY 是 `D0070002…`（不是密钥） |

`run/mana_keys.log` 里也只有两种行：`BCKEY` + `MANAFILE` —— 这是"只有这两个钩子在生产"的直接证据。

**所以默认运行只需要**：`bcrypt.dll` 的 2 个导出钩子（key + 验证）+ 1 个 il2cpp 钩子（文件名）。
v19 起 4 个 MANAKEY 移入 `GMK_FULL=1`，默认 il2cpp 补丁面积 **5 → 1**；
**v20 起诊断钩子彻底删除**（`AttachManaKeyHooks`/`AttachDiagnostics` 等已从源码移除），补丁面积恒为 1。

**这些 RVA 是怎么核对的**：`cn/out` 的 dump.cs 只有方法索引、没有 RVA，所以拿
`genshin-metadata/global/out/methods_r.csv`（国际服 7.1 全量 idx→RVA）当参照 —— 两服同一份源码、
**同一个类内的代码布局一致**，只差一个区段恒定位移。用两个已实测的国服值标定位移
（idx 75713 `Player.SetFile` → `0x07053800`、idx 75746 `NativeMethods_SetFile` → `0x070538C0`，
两者相隔 33 个方法、位移都是 `0x3120`），再反查全部常量：S2/S3/N2/N3 分别命中
`SetVideoAudioDecryptionKeys` / `SetVideoAesKeyAudioDecryptionKey` / 两个 `NativeMethods_*` 包装 ——
6 个常量全中、无一落空。
（2026-10-24 复核：`genshin-metadata/cn/out/methods.csv` 与当时全部 14 个常量机器核对，
14/14 可按名解析、8 个命名钩子逐一精确一致 —— 这也是"按名直读 RVA"方案的可行性证明，
见下文「版本更新」。）

> ⚠️ 别用"按 `.pdata` 槽位顺序对齐"或"暴力找 methodPointer 表基址"这两种做法：类内方法之间夹着
> 非方法函数（adjustor thunk 之类），槽位会整体串位。这两种都试过并失败，上面的证据就是反例。

## 版本更新后怎么把这些 RVA 重新找回来

**核心事实：RVA 每次更新都会变，稳定的只有「同一个函数的代码形状」。**
所以更新流程是"拿旧 exe 当参照、把函数迁到新 exe"，不是重新逆向一遍。

### 快速通道：双击 `update_rva.cmd`（推荐）

游戏更新完之后，**双击根目录的 `update_rva.cmd`** 就行（也可以把新的 `YuanShen.exe` 拖到它上面）：

1. 它自己找新 exe（`run\game_path.txt` → 游戏目录；拖拽/参数优先）；
2. 拿 `rva_cache\<exe名>` 里缓存的**上一版 exe** 当参照（脚本每次成功后自动缓存，所以这个目录别删）；
3. 从 `inject\src\Application.cs` 读出当前常量当"旧 RVA"，用掩码指纹迁到新 exe
   （v20 起清单只有 NF 一项）；
4. 打印 旧→新 对照表：**只采信唯一命中**；不唯一的会把候选列出来让你选（绝不自动猜）；
5. **没迁上的常量会不会写成 `0`，取决于它是不是关键项** —— 真实语义（以前文档写含糊了）：
   非 NF 的常量迁不上就写 `0`（C# 侧约定"0 = 该服务器未定位此钩子 → 跳过并打日志"，
   比留着旧 RVA 安全）；**`NativeSetFile`（NF）例外：不写 0、保留旧 RVA**，脚本以非 0 退出 ——
   关掉唯一的文件名来源比"少挂"更糟。⚠ 于是存在这种组合："**迁移失败还直接 build**" =
   出厂的二进制是"**新 exe + 旧 RVA**"；旧 RVA 很容易仍通过"可执行节+可读+序言"三项校验，
   于是把补丁打到别的函数上、错得不声不响。这正是下一节「版本指纹」存在的理由：下一次启动就把它喊出来。
   旧值可在 `.bak-<时间戳>` 备份里找回，或 `git diff inject/src/Application.cs` 取回；
6. **指纹会被一起写回**：迁移成功后脚本同时把**新 exe 的 `Fingerprint`**（`CRC32(头部 SizeOfHeaders 字节)`）写进
   `RvaSet`，从此每次启动都能自证"这版 RVA 是给这版 exe 用的"（见下节）。显式 `--old-rva NAME=0xHEX`
   用于兜底：源码里那一项**已被上次失败的迁移写成 0**（NF 则停在旧值）时，手工指定旧 RVA 重跑；
7. 确认后写回源码（自动备份 `Application.cs.bak-<时间戳>`），可选接着跑 `build.bat`（`--build`）。
   `--build` 失败时退出码是 **3**，此时**源码已经写回**、只有编译失败 —— 别误当成"没改源码"。

> **交叉校验（推荐）**：NF 的真名 `CriWare.CriMana.Player.NativeMethods_SetFile` 不受混淆影响
> （CRI 包装类保留原名）。用 [genshin-metadata](../../genshin-metadata/) 项目对新客户端跑一次
> `python build.py`（约 5 分钟，自动推导 key + 生成 `methods.csv`），就能**按名直读**新 RVA ——
> 与指纹迁移的结果必须一致，不一致就是哪一个都别信。
> 全部 14 个历史钩子的真名对照（2026-10-24 机器核对）已在 git 历史与 genshin-metadata 分析中留档。

```powershell
update_rva.cmd                 # 双击等价：问一句就写
update_rva.cmd --yes --build   # 不问，写完直接重新编译部署
update_rva.cmd --dry-run       # 只看结果，不写源码
update_rva.cmd --force         # 旧/新 exe 完全相同也照跑（默认认为"没更新"直接退出）
update_rva.cmd --old-rva NativeSetFile=0x070538C0   # 源码里该项已成 0 时手工指定旧 RVA 重跑
```

> 退出码：`0` 成功（含 `--dry-run` 成功）；`2` 参数/环境错误；
> `1` = **NF 没迁上**（v20 起 NF 是唯一常量，此即"什么都没写"、NF 保留旧值）；
> **`3` = 源码已写回但 `--build` 编译失败** —— 唯一一个"源码改了、产物没换"的码。

> 第一次用（还没有 `rva_cache\`）时，把当前版本的 exe 复制成 `rva_cache\YuanShen.exe`，
> 或者 `update_rva.cmd --old <旧exe>`。**这次 7.1 的 exe 已经缓存好了**，7.2 一更新直接双击即可。

### 版本指纹（自证）

**要解决的问题**：挂钩前那四道门（RVA≠0 → 落在可执行节 → 可读 → 序言像函数入口）只能证明
"这是个函数入口"，证明不了"这个函数是 `NativeMethods_SetFile`"。最坏的情况是**旧 RVA 在新版里
恰好仍然合法** —— 补丁打到别的函数上、游戏行为变得无法解释，而日志里一切都"正常"。
指纹机制不改任何挂钩行为，只负责把这种状态**在启动第一秒就喊出来**。

**口径**：`CRC32(exe **磁盘文件**头部 SizeOfHeaders 字节)`（标准 zlib 口径：反射输入输出、多项式 `0xEDB88320`、
初值全 1、结果取反）。国服 `SizeOfHeaders = 0x400` → 当前（7.2）登记值 `0x88FB991A`（7.1 时是 `0xC66689B9`）。
`VersionGuard.FingerprintBytes = 0x10000` 只是**上限**（防畸形 `SizeOfHeaders` 把 CRC 拖成整文件）：
实际长度由 `VersionGuard.FingerprintLength` 从头部读 —— 判据 `0x40 ≤ e_lfanew ≤ 0x1000`、签名 `PE\0\0`、
`0x200 ≤ SizeOfHeaders ≤ 0x10000`，任一不过就兜底 `0x400`。登记值在
`inject/src/Application.cs` 的 `RvaSet.Fingerprint`：

| 常量集 | `Fingerprint` | 说明 |
|---|---|---|
| `Cn`（国服 `YuanShen.exe`） | `0x88FB991A` | 7.2，`SizeOfHeaders = 0x400`；由 `update_rva.py` 迁移时写入（7.1 是 `0xC66689B9`） |
| `Gl`（国际服 `GenshinImpact.exe`） | `0x00000000` | **未登记**：本机没有国际服客户端，没实测就不填（编一个假指纹比不填更糟） |

**判定只认磁盘文件，内存镜像只作参照**（这是 2026-11-02 实跑踩出来的第二个坑）：
带保护壳的客户端（本 exe 有 `.tls` 段 + TLS 目录）会在**注入线程启动时先跑 TLS 回调**，等 DLL 读头部时，
内存里那 1KB 早被壳改写过 —— 7.1 实跑实测：**磁盘 `0xC66689B9` / 内存 `0x9735915B`**（同长度、同算法）。
若拿内存值比对，就会每次启动都误报"游戏已更新"，而且一开 `GMK_STRICT=1` 就会**误杀 NF**
（NF 挂了不上 → 文件名归属全丢 → 所有 `BCKEY` 因 `file=?` 被拒收，密钥库一个字都写不进去）。

所以现在的实现是：
- **判定**：`Application.TryHashFileHeader` 用 `Environment.ProcessPath` 取本进程 exe 路径，
  以 `FileShare.ReadWrite | Delete` 读前 `SizeOfHeaders` 字节算 CRC（与 `update_rva.py` 读的是同一个文件、同一段字节）；
- **参照**：`TryHashModuleHeader` 把内存镜像头部的 CRC 也算一份写进日志，**永不参与判定**；
- **读不到就跳过**：文件打不开 / 头部声明长度超过可读字节 → 只打一行说明，不判"不匹配"（宁可不说，也不说错）。

**为什么不用"文件头 64KB"**：`FileAlignment = 0x200 ≠ SectionAlignment = 0x1000`，所以**内存镜像的前 64KB
与文件前 64KB 不是同一段字节** —— 镜像里 `[SizeOfHeaders, 0x1000)` 是 0 填充，文件里那段是 `.text` 数据。
实测：**7.2 文件前 64KB CRC32 = `0x8CB60F3D`（判定用的头 0x400 是 `0x88FB991A`），7.1 则是 `0xE597A764` 与 `0xC66689B9`**。
长度取 `SizeOfHeaders` 之后，文件与镜像的 `[0, SizeOfHeaders)` 本来逐字节一致（保护壳改写是后来的事，
所以才把判定挪到文件上）。

`0` 的语义是"**未登记**"，不是"不匹配" —— 三态而非两态（`VersionGuard.State`：
`Match` / `Mismatch` / `Unregistered`）。

**启动时多两行日志**（`Goshujin.Report` → `[DLL] 版本指纹…`，落在 `dumper.log`；
`mana_keys.log` 只收 `MANAKEY*` / `MANAFILE*` / `BCKEY` 三种前缀，所以那里没有这两行）：

| 实测 vs 登记（**磁盘**） | 日志（`N` = 本次实际取的字节数，十进制） |
|---|---|
| 相等 | `版本指纹匹配 0x88FB991A（这版 RVA 属于这个 exe）（口径：exe 头 1024 字节）` |
| 登记为 `0` | `版本指纹未登记（实测 0x…）：无法校验 RVA 是否属于本版本，只能靠四道门（可执行节/可读/序言）自保。跑一次 tools\update_rva.cmd 即可登记（口径：exe 头 N 字节）` |
| 不等 | `⚠ 版本指纹不匹配：实测 0x…，源码登记 0x… —— 游戏已更新？请先跑 tools\update_rva.cmd；残留旧 RVA 会把补丁打到别的函数上（口径：exe 头 N 字节）` |

每次还会多一行参照：`版本指纹：磁盘文件头部 0x…；内存镜像头部 0x…（仅参照：保护壳会改写，不参与判定）`
—— 两个数不一样是**正常的**，正是它解释了"为什么判定非要读文件"。

末尾的 `（口径：exe 头 N 字节）` 是 `VersionGuard.Describe(state, actual, expected, length)` 的 `length`
（`Application.CheckVersion` 传实际长度，国服 = `0x400` → "1024 字节"）。它存在的理由：
**"口径被改坏"这件事在日志里能立刻看见** —— 按 64KB 取会得到 `0x8CB60F3D`、判定用的却是 `0x88FB991A`，
而带后缀的行一眼就能看出"这轮到底算了多少字节"，不用回头翻源码。

（还有一条"读不到 exe 文件（…），跳过校验"—— 文件读不出来时只靠四道门。）

> **这些数别混用**（C# 与 Python 两侧都按第 1 行实现，测试把"64KB / 内存镜像"那几行钉成了反例断言）：
>
> | 数值 | 是什么 | 能不能当指纹 |
> |---|---|---|
> | `0x88FB991A` | **文件**头 `SizeOfHeaders`（0x400）字节的 CRC32 —— **7.2 当前登记值** | ✅ 判定用的就是它 |
> | `0xC66689B9` | 同口径，**7.1** 的登记值（历史） | ⚠ 只对 7.1 有效；7.2 下会正确报"不匹配" |
> | `0x8CB60F3D` | **文件**前 64KB 的 CRC32（7.2） | ❌ 不能（镜像里那段是 0 填充，算出来是别的值） |
> | `0xE597A764` | **文件**前 64KB 的 CRC32（7.1，当年手工核对 CDN 指纹用过） | ❌ 同上 |
> | `0xF1CC54E7` | **内存镜像**前 64KB 的 CRC32（按 64KB 取值时的模拟结果） | ❌ 不能（文件里不是这个值） |
> | `0x9735915B` | **内存镜像**头 1KB 的 CRC32（7.1 实跑实测） | ❌ 不能（保护壳改写了头部，无法从文件复现） |

**默认只警告、照挂**，不改变任何挂钩行为。理由很实际：一次正常更新后如果忘了跑 `update_rva.cmd`，
用户至少还能拿到 key（只是没有文件名归属，`BCKEY file=?`）；把"宁可少挂也不打错补丁"的选择权
交给一个显式开关，而不是替所有人做决定。

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `GMK_STRICT=1` | 关 | **只有**"指纹已登记但与当前 exe 不符（`Mismatch`）"时**跳过 NF 挂钩**（其余钩子不拦）；默认只警告、照挂。"未登记"（登记值 `0`，例如国际服）**不拦** —— 否则这个开关会让人一个钩子都挂不上，比不检查更糟 |

严格模式的日志形态：`[skip] NativeMethods_SetFile: GMK_STRICT=1 且版本指纹不匹配 → 不挂 NF（避免把补丁打到别的函数上）。跑 tools\update_rva.cmd 迁移后重试`。

**闭环**：`tools\update_rva.py` 迁移成功时把新 exe 的指纹一起写回 `RvaSet.Fingerprint`，所以正常流程是
"双击 `update_rva.cmd` → 指纹自动更新 → 下次启动显示「匹配」"。指纹**不是**安全机制，
也不是"证明这版 RVA 正确"的证据 —— 它只防"忘记迁移"这一种事故（含上文「迁移失败还直接 build」那种组合）。

**算不出来就不算**（两边同一条规矩）：头部声明 `SizeOfHeaders` 比实际可读字节还多、
或 `read_constants` 发现源码是旧格式（`RvaSet` 里没有 `Fingerprint` 字段）时，
`update_rva.py` **不登记指纹**（打一句 `⚠ … 跳过指纹登记（RVA 仍然照常迁移）`，退出码不变），
DLL 侧对应地**跳过校验**并打一行说明。理由：指纹的全部意义是"两边算出同一个数"，
任何"夹到可读长度凑一个 CRC"都会变成假绿灯或永久误报。
同理，`Fingerprint` **只在迁移清单里每一项都成功时**才写回 —— 有任何一个没迁上还登记，
下一版拿到的就是"版本对得上、地址却过期"，比不登记更危险。

**顺带的自证：名字形状**。NF 是唯一能在运行时**被动**发现"挂错函数"的钩子 —— CRI Mana 只播 `.usm`。
所以 `OnNativeSetFile` 里有一条**只观察、不改变归属**的日志（最多 3 条，之后只累加计数）：

```
NFWARN #1 名字不像视频文件（NF 可能挂错函数）：<拿到的字符串>
```

它绝不擅自丢文件名（宁可留着可疑归属，也不让 `paired_keys.json` 空转）；真正的拦截是
`--old-rva` 重迁 + `GMK_STRICT=1`。

下面是不用脚本时的手动流程/原理，排错时看。

### 它们的来历（三代叠加）

1. **7.0**：从 exe 的 **methodPointer 表**读出来的（连续的 8 字节指针数组，第 i 项 =
   全局方法索引 i 的代码地址）。表基址最初由 CDN 下发的 `to_int32` RVA 反推
   （`tools/locate_hooks.py`：`表基址 = to_int32 指针所在文件偏移 − 1357×8`）。
2. **7.0 → 7.1**：`tools/migrate_masked.py`（掩码指纹 + 函数边界）逐个迁移，
   `tools/align_class.py` 对整类做序列对齐；再双服交叉验证 + 运行时实证。
   （注意：7.0 还没有 7.1 这套 AES_HCA/BCrypt 链路，所以 7.0 **不能**拿来做这次改动的验证样本。）
3. **2026-10-18 复核**：用国际服 7.1 全量 `idx→RVA` 表 + 两个国服实测锚点标定位移
   （`0x3120`）反查，发现 5 个里 4 个对、S3 错指到 `Player.UpdateWithUserTime`（已修正）。

> 上面提到的 `tools/locate_hooks.py`（求 methodPointer 表基址）与 `tools/align_class.py`（整类对齐）
> 已在 **2026-10-25 瘦身**（commit `ede0c7f`）中删除。现在 `tools\` 只有 4 个文件：
> `update_rva.py` / `migrate_masked.py` / `pdata.py` / `pe_utils.py`；剩下的都是历史，
> 需要复现当时流程时从 git 恢复（见下文「游戏版本更新后怎么重新定位 RVA」）。

### 重找（一条命令）

```powershell
python tools\migrate_masked.py --src <旧exe> --dst <新exe> `
    --rva NF=0x070538C0 --dis
```

判据（工具自己会卡死这些）：
- **只采信"唯一命中"**；0 个或多个候选都非 0 退出，绝不给你一个"看着合理"的地址；
- 指纹按函数边界截断（不会吃到下一个函数），`call/jmp` 的 rel32、`rip` 相对位移、立即数
  全部掩码 → 地址整体平移、编译器微调都不影响；
- 输出里的 `delta` 是整体平移量，可用来给同类函数做快速换算，但**仍要逐个验证落在函数起点**。

某个函数不命中时（函数体改动大）：以前用 `tools\align_class.py` 做**整类对齐**（一个类的方法在二进制里
是连续区块、顺序基本不变，整类对齐比单函数迁移稳）—— **该脚本已删**（2026-10-25 瘦身，`ede0c7f`），
需要时从 git 恢复。现在日常只剩两条路：`--old-rva NAME=0xHEX` 手工指定旧值重跑，
或者用 `genshin-metadata` 的 `methods.csv` 按名直读新 RVA 做交叉校验。

### 验证（三步）

```powershell
# ① 新地址必须是函数起点，且 size 合理
python tools\pdata.py --exe <新exe> --near 0x<新RVA> --span 0x40
# ② 反汇编看序言与参数个数（dump_rva.py 已删；migrate_masked 的 --dis 打印源函数反汇编）
python tools\migrate_masked.py --src <旧exe> --dst <新exe> --rva NF=0x<旧RVA> --dis
```
③ 实跑一轮：日志里应只有 1 行 `hook NativeMethods_SetFile @ …`，播放几个视频能看到
`★★ 已配对`；文件名变成 `?` 就说明 NF 挂错了（该轮日志里会有 `NFWARN`，见「版本指纹」一节）。

### 兜底（RVA 全失效也能出 key）

`bcrypt.dll` 那两个钩子**不依赖任何 RVA**：最坏情况是"密钥照样抓得到、只是不知道是哪个视频"
（`BCKEY file=?`），这时用别的途径拿文件名再手工对应即可。

### 两个必须知道的坑

**① 这版 exe 的 `.pdata` 段是诱饵。** 1,177,301 条里 588,950 条 `end<=start`，连一个真实
函数起点都找不到；真正的 RUNTIME_FUNCTION 表被搬进 `.upx0`，**只有异常目录**（数据目录[3]，
RVA `0x19F73B00` / `0xD796B8` 字节 / 1,177,402 条，全部合法且单调有序）指向它。
`tools/pdata.py` 以前按名字读 `.pdata` 段 → 函数边界全错（指纹截断跟着错、迁移会误判
"RVA 不是函数起点"）；现在**优先读异常目录**、两个来源按「合法条目占比」取信，诱饵分数写进 warning。

**② 别用这两种"看起来更聪明"的对齐：**
- 按 `.pdata` 条目的**槽位顺序**对齐方法列表 —— 类内方法之间夹着非方法函数（adjustor thunk 等），
  槽位会整体串位（实测：会得出 `NativeMethods_SetFile` 是 `RendererResource` 的方法这种荒谬结果）；
- 暴力搜 methodPointer 表基址再按全局索引读 —— 这张表按程序集分成多段（最大的 460,313 项），
  没有程序集边界就对不上全局索引。

## 钩子开关（默认只挂核心）

| 环境变量 | 默认 | 作用 |
|---|---|---|
| `GMK_BC=0` | 开 | 关掉 `bcrypt.dll`（系统库）钩子。默认运行**唯一真正产出密钥**的就是这条路径 —— 除非事实证明系统库补丁也影响播放，否则不要关 |
| `GMK_FS=1` | 关 | 启动 CRI FS 侦察线程。实测该线程会让视频无法播放，仅用于调查（无 RVA 依赖，不参与版本更新） |
| `GMK_REUSE=1` | 关 | 打开「跨视频复用密钥」的补报。实测每个视频都会自己重建密钥对象并报 `BCKEY`（自带文件名），补报只会在换新钥匙时抢跑误报，仅当某个视频一条 `BCKEY` 都没有时才需要它（见下面「同一把密钥可能覆盖多个视频」） |
| `GMK_STRICT=1` | 关 | 严格版本模式：**只在"版本指纹已登记但与当前 exe 不符"时跳过 NF 挂钩**（默认只警告、照挂；"未登记"不拦）。取舍见「版本指纹（自证）」一节 |

（v20 起没有诊断钩子了，`GMK_FULL` 开关已随诊断代码一起删除。）

默认运行 = **1 个 il2cpp 补丁（NF，文件名来源）+ 2 个 bcrypt 导出钩子（取 key + 验签）**，
即**补丁面积 1 + 2**；诊断钩子（`SUB*` / `MANAKEY*` 等）已不存在，所以**默认**下这个数字是常数。
只有两个开关会改它：`GMK_BC=0` 关掉 bcrypt 的那 2 个（只剩 NF = 1 + 0）；
`GMK_STRICT=1` 在"指纹不匹配"时关掉 NF（只剩 bcrypt 的 2 个）。

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

- `run\mana_keys.log` — 原始事件（`MANAFILE*` / `BCKEY` 行，去重后落盘）
- `run\paired_keys.json` — **按文件名配对**的密钥（累积写入，缩进美化，可直接并入 key 库）：
  `{ "文件名": { "aes": "<32hex>" } }`
  （v20 起只存 BCKEY 的视频 AES —— 文件名 + aes；旧掩码 / method2 体系随钩子一起退役）

四个产物（`mana_keys.log` / `paired_keys.json` / `dumper.log` / `dump\`）全部锚定在 **exe 所在目录**，
不管从哪个工作目录启动都一样。

> ⚠️ `run\` 里**现存**的 `dumper.log` / `mana_keys.log` / `paired_keys.json` 与 `dump\` 是历史运行残留，
> 可能来自**旧版 DLL**（与当前源码不同步：`dumper.log` 里还有 v20 已删除的
> `SUB hook VideoSubtitles.Start`、`hook SetVideoAudioDecryptionKeys`、`hook × 5` 这类行）。
> 它们只证明"当时那一轮"，不能用来核对当前默认补丁面积（= 1 + 2）、也不能当成当前版本跑通了的证据；
> 判据一律以本轮新生成的 `dumper.log` 为准。
>
> 但 `paired_keys.json` 要分开看：它的**条目格式与当前完全一致**（`{ "文件名": { "aes": "32hex" } }`），
> 已有的旧条目**可直接并入 key 库、不要删** —— 旧痕迹只在日志行里，不在密钥库里。

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

> 字体文件放进 `run\` **不会被提交**：`run\` 整个目录被 `.gitignore` 覆盖
> （`.gitignore` 里还单独列了 `game_path.txt` 兜底）。所以拷字体既不影响仓库、也不占 diff。

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

（远程 CI 已于 2026-10-25 移除 —— 个人仓库用不上，本地测试已覆盖同样内容；
历史配置见 git。提交前建议本地跑一遍上面两条测试命令。）

一个编码坑（原 CI 配置里处理过的，本机同样适用）：在非中文代码页的控制台里，
这些脚本的中文 `--help` 会因 Python 对管道 stdout 用严格编码而
`UnicodeEncodeError` 非 0 退出 —— `chcp 65001` 或 `set PYTHONIOENCODING=utf-8` 即可。

NativeAOT 编译若报 `LNK1181 ... .lib`，是 MSVC 库路径没进环境变量，需显式：

```
set LIB=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\<ver>\lib\x64;^
        C:\Program Files (x86)\Windows Kits\10\Lib\<sdk>\um\x64;^
        C:\Program Files (x86)\Windows Kits\10\Lib\<sdk>\ucrt\x64
```

## 游戏版本更新后怎么重新定位 RVA

**不要**靠 dump.cs（米哈游的混淆 metadata 让 Il2CppDumper 直接报
`Metadata file not found or encrypted`）。用 `tools/` 里的自研链 —— 现在只有 4 个脚本：

1. `tools/update_rva.py` — **版本迁移的唯一入口**（`update_rva.cmd` 就是它的壳）：
   从 `inject/src/Application.cs` 读旧常量 → 掩码指纹迁到新 exe → 打印 旧→新 对照表 →
   写回源码 + 新 exe 的 `Fingerprint`。`--old-rva NAME=0xHEX` 用于"源码里该项已被写成 0"时手工指定旧值；
   `--dry-run` 只看不写；`--build` 写完接着编译（失败退出码 3）。
2. `tools/migrate_masked.py` — 单函数跨版本/跨服迁移（掩码指纹，`call/disp/imm` 通配），
   用来双服交叉验证：国服→国际服应一一对应。指纹按函数边界截断，不会越读进下一个函数；
   `--dis` 顺带打印源函数反汇编（原来 `dump_rva.py` 的用途）。
3. `tools/pdata.py` — 函数边界（异常目录 / `.pdata` 双来源取信），迁移与校验都靠它。
4. `tools/pe_utils.py` — PE 加载与 RVA→文件偏移映射的共用层（不单独跑，被上面几个 import）。

> **已删脚本（2026-10-25 瘦身，commit `ede0c7f`）**：`align_class.py`（整类对齐）、
> `locate_hooks.py`（methodPointer 表基址 / `--window` 平移搜索）、`dump_rva.py`（定点反汇编）、
> `read_str.py`（读 P/Invoke 描述符里的模块名/入口名）、以及全部 `usm*.py`。
> 文档里教这些脚本的段落已改成"已删，历史见 git"；需要时从 git 恢复，例如
> `git show ede0c7f^:tools/dump_rva.py > tools/dump_rva.py`。日常迁移流程不再需要它们。

工程化约定（为了能脚本化/进 CI）：

- 依赖固定在 `tools/requirements.txt`（只有 `capstone` / `pefile`）。`pip install -r tools\requirements.txt`
  **不再需要 numpy** —— `numpy` 在文件里是注释掉的可选项，只被 `pe_utils.find_direct_calls`
  （扫全段找 `E8 rel32` 调用点那类调查）在函数内 `import`；缺它时抛 `NumpyMissing` 并提示装包
  （**不会**静默返回空表）。日常迁移四件套用不到它。
- PE 加载与 RVA→文件偏移映射统一走 `tools/pe_utils.py`（**越界即抛**，不再用
  `max(VirtualSize, SizeOfRawData)` 那种会接受越界 RVA 的不可靠映射）。
- （USM 解析脚本已于 2026-10-25 随瘦身删除 —— 密钥直接从游戏内存读出，
  无需解密验证；离线解密/验证工具在 `../genshin-video-keys`。）
- 所有脚本：`main()` 返回 int + `raise SystemExit(main())`，**定位失败返回非 0**；
  加 `--json` 便于脚本消费；`--help` 一律可用。
- 脚本自身的单测在 `tools/tests/`（`python -m unittest discover -s tools/tests -v`），
  覆盖 PE RVA 越界、`.pdata` 边界解析、update_rva 的读写回源码约定、**指纹写回与
  `--old-rva` 解析**、以及"迁移失败绝不登记指纹"这条铁律。

## 目录

```
├── inject/    注入 DLL（hook + 管道上报），NativeAOT，导出 YaeMain
├── launcher/  启动器（挂起拉起 + 注入 + 配对写 paired_keys.json），NativeAOT
├── run/       ManaKeyDumper.exe/dll + 产物
├── tests/     纯逻辑单测（配对状态机 + 密钥库读写 + 序言判据 + 版本指纹，xunit）
└── tools/     版本迁移四件套：update_rva / migrate_masked / pdata / pe_utils（Python + capstone/pefile）
```

---

## 首轮实测（2026-09-23）与 v2 诊断版

> **本节以及下面的「第三轮修复」「实测结果」都是历史记录**，日志来自**当时的 DLL 构建**，与当前源码不同步
> （`SUB*`、`MANAKEY*`、`hook × 5`、14 个诊断钩子都已被 v20 删除）。事实内容按原样保留，
> 只作事故复盘证据；**当前行为以「钩子开关」「版本指纹」两节为准**。

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
  *（口径提醒：这个 `0xE597A764` 是**文件前 64KB** 的 CRC32、当时手工核对 CDN 指纹用的。
  7.1 的 `RvaSet.Fingerprint` 用的是 `SizeOfHeaders` 字节口径 = `0xC66689B9`（现在是 7.2 的 `0x88FB991A`），
  **这些数别混用** —— 镜像前 64KB 又是第三个数 `0xF1CC54E7`。原因见「版本指纹（自证）」一节。）*
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

更进一步（v19）：实测 4 个 MANAKEY 钩子**整场游戏 0 次调用**，已从默认集合移到 `GMK_FULL=1`，
默认 il2cpp 补丁 **5 → 1**（只剩 `NativeMethods_SetFile`）。

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
4. 「默认只剩 1 个 il2cpp 补丁」是静态推演（`AttachCore` 内 1 处 `MinHook.Attach`）+ 实测日志里
   只有 `hook NativeMethods_SetFile` 一行；`GMK_FULL=1` 那 13 个诊断钩子仍未逐个实机验证。
5. 修好归属之后能否稳定产出 `paired_keys.json` —— **2026-10-16 18:14 已实测，见文末「实测结果」**。

---

## 实测结果（2026-10-16 18:14，国服 7.1）

这一轮把「密钥链路」从头到尾验证了一遍，结论：**DLL 侧抓取完全正确，缺口在启动器没接住 BCKEY**。

### 日志证据（`run\dumper.log` 里那一段）

```
[18:14:00] 游戏: ...\YuanShen.exe（国服 YuanShen.exe，来源：game_path.txt）   ← 双击免输入生效
[18:14:00] hook × 5 + BCRYPT [core] ...  诊断钩子未启用                    ← 当轮默认（v19 起只挂 NF）
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


