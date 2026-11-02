# tools/tests — 工具链的单元测试（纯标准库 `unittest`）

## 怎么跑

在**仓库根目录**执行：

```
python -m unittest discover -s tools/tests -v
```

或者只跑某一个文件：

```
python tools/tests/test_pdata.py -v
```

不要用 pytest —— 这些测试刻意只用标准库 `unittest`，不引入额外依赖。
`capstone` / `pefile` 是工具链本身的依赖（见 `tools/requirements.txt`）。

## 为什么这些测试长这样

仓库里**没有**真实游戏 exe，所以测试全部基于**自己构造的合成文件**：

| 文件 | 作用 |
|---|---|
| `_synth_pe.py` | 手写一个结构合法（pefile 能解析）的最小 PE32+，可指定段名/RVA/虚拟大小/特征位 |

| 测试文件 | 覆盖内容 |
|---|---|
| `test_pe_utils.py` | RVA→文件偏移的边界语义：越界必抛、**虚拟尾部（只有内存里有）不许映射**、缺段显式报错 |
| `test_pdata.py` | `.pdata`/异常目录的函数边界解析：诱饵段按合法占比取信、越界与残余字节显式报告 |
| `test_update_rva.py` | `update_rva` 的迁移清单读写回源码（8 位十六进制、只改目标常量集、写前必备份）、多候选绝不自动猜、**Fingerprint 字段格式契约与"全部迁成才登记"的决策**、`--old-rva` 解析与拒绝 0/非法值、退出码 3 的语义、**迁移链路不许依赖 numpy** |

`update_rva.main()` 本身需要两代 exe 才能驱动，所以只测它拆出来的纯函数
（`read_constants` / `write_constants` / `exe_fingerprint` / `plan_fingerprint` /
`parse_old_rva` / `pick` / `candidates`）；整条流程用合成 PE 做过手工 smoke（不在本目录）。

（USM 与调查类脚本的测试已随脚本一起删除 —— 2026-10-25 瘦身，
`usm`/`align_class`/`locate_hooks` 等的历史见 git。）

关键点：**这些测试是为「缺陷回归」写的** —— 把迁移链路任何一处安全语义改坏
（越界映射静默返回 None、指纹跨函数边界、失败常量不写 0），对应的测试立刻会红。
