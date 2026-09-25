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

## 使用（需要管理员，游戏必须已关闭）

```
cd run
ManaKeyDumper.exe                          # 自动探测国服/国际服游戏路径
ManaKeyDumper.exe <YuanShen.exe 全路径>     # 或显式指定
```

进游戏播放加密过场动画（例：内容组 3003 的 300317-300321）。实时输出两份文件：

- `run\mana_keys.log` — 原始事件（`MANAKEY*` / `MANAFILE` 行）
- `run\paired_keys.json` — **按文件名配对**的密钥：
  `{ "文件名": {"aes": "<32hex>", "audio": "<16hex>"} }`

每个视频只在第一次播放时设一次 key（launcher 侧去重）。

## 构建

```
build.bat    # dotnet publish ×2 并部署到 run\（纯 ASCII，避免 GBK 控制台乱码）
```

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
   然后按索引直接读表拿 RVA。
2. `tools/align_class.py` — 把上一版本的某个类**逐方法做掩码指纹对齐**，
   找出新版本新增的槽位（新增的就是新钩子）。
3. `tools/migrate_masked.py` — 单函数跨版本/跨服迁移（掩码指纹，`call/disp/imm` 通配），
   用来双服交叉验证：国服→国际服应一一对应。
4. `tools/dump_rva.py` — 定点反汇编，看序言数参数个数（决定 hook 签名）。
5. `tools/read_str.py` — 读 P/Invoke 描述符里的模块名/入口名。

## 目录

```
├── inject/    注入 DLL（hook + 管道上报），NativeAOT，导出 YaeMain
├── launcher/  启动器（挂起拉起 + 注入 + 配对写 paired_keys.json），NativeAOT
├── run/       ManaKeyDumper.exe/dll + 产物
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
