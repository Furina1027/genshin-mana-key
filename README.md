# GenshinManaKey

原神过场动画（USM / CRI Mana）密钥截获工具。

在游戏播放过场动画时，通过注入 DLL 挂钩 CRI Mana 的设钥路径，实时截获：

- **视频 AES-128 密钥**（7.1+）
- **音频 HCA 密钥**（audioKey，7.1+）
- **旧体系 videoKey**（≤7.0；旧文件里 audioKey 与它同值）

密钥按「正在播放的文件名」自动配对，写入 `run\paired_keys.json`，可直接并入
[hk4e_keys.json](https://github.com/Furina1027/hoyo-files/blob/main/pkg_version/usm/hk4e_keys.json)。

## 支持版本

| 客户端 | 当前适配 |
|---|---|
| 国服 `YuanShen.exe` | 7.2 |
| 国际服 `GenshinImpact.exe` | 7.2 |

游戏更新后运行 `update_rva.cmd` 迁移 RVA；工具会用 exe 头部指纹自检 RVA 是否属于当前版本。

## 使用

需要 Windows、管理员权限，且游戏必须已关闭。

1. 构建：双击 `build.bat`（需要 .NET 9 SDK 和 MSVC）。
2. 把游戏目录或 exe 全路径写进 `run\game_path.txt`，或作为第一个参数传给启动器。
3. 双击 `run\ManaKeyDumper.exe`。
4. 进游戏播放加密过场动画。结果实时写入：
   - `run\paired_keys.json` — 按文件名配对的密钥
   - `run\mana_keys.log` — 原始密钥事件
   - `run\dumper.log` — 全量日志

## 输出格式

```json
{
  "Cs_ZD_AQ70201201_SLT": {
    "aes": "F5AC17FFE4B4B430553AE073EB8A8A1D",
    "audio": "0004BA5069B44BD4"
  },
  "Cs_ZD_AQ70091801_HY": "00112B7D77DE1D7C"
}
```

- 新体系：`aes`（32 hex）+ `audio`（16 hex）
- 旧体系：只写一个裸 16 hex 字符串（videoKey）

## 免责声明

本项目仅用于技术研究与学习交流，风险自负。

## 致谢

- [YaeAchievement](https://github.com/HolographicHat/YaeAchievement)：注入框架与 Native 相关实现的参考来源（GPL-3.0）。

## 许可证

GPL-3.0，见 [LICENSE](LICENSE)。
