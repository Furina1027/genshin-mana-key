# tools/tests — 工具链的单元测试（纯标准库 `unittest`）

## 怎么跑

在**仓库根目录**执行：

```
python -m unittest discover -s tools/tests -v
```

或者只跑某一个文件：

```
python -m unittest tools.tests.test_usm -v          # 需要仓库根目录在 sys.path（cwd 就是根目录）
python tools/tests/test_usm.py -v                    # 直接跑单文件也可以
```

不要用 pytest —— 这些测试刻意只用标准库 `unittest`，不引入额外依赖。
`numpy` / `capstone` / `pefile` / `pycryptodome` 是工具链本身的依赖（见 `tools/requirements.txt`）。

## 为什么这些测试长这样

仓库里**没有**真实游戏 exe、也没有样例 USM 文件，所以测试全部基于**自己构造的合成文件**：

| 文件 | 作用 |
|---|---|
| `_synth_pe.py` | 手写一个结构合法（pefile 能解析）的最小 PE32+，可指定段名/RVA/虚拟大小/特征位 |
| `_usm_fixture.py` | 合成 USM 容器；**独立实现**加密器（直接 `Crypto.Cipher.AES` ECB 拼计数器），不复用 `usm.py`，避免自证 |

| 测试文件 | 覆盖内容 |
|---|---|
| `test_pe_utils.py` | RVA→文件偏移的边界语义：越界必抛、**虚拟尾部（只有内存里有）不许映射**、缺段显式报错 |
| `test_ctr.py` | CTR 计数器等价性：手写实现 / pycryptodome `MODE_CTR` / 朴素第三方实现三者逐字节一致，含 32 位进位 |
| `test_parse_chunks.py` | `parse_chunks` 对畸形块（size 过小、越界、data_offset+padding 越界）必须带偏移报错 |
| `test_usm.py` | USM 加解密端到端 + **C2 回归闸门**：加密区必须是 `payload[0x40:]`，第 0 帧明文前缀 0x14、其余 0x34；旧的「一律 0x34」必须解不出第 0 帧 |
| `test_usm_tools.py` | 三个 USM CLI 的退出码：缺 nonce 时拒绝输出 `.dec.ivf`、明文/已加密/样本不足三种 verdict |
| `test_align_tools.py` | `align_class` 全局分配与 sanity gate、`migrate_masked` 按 `.pdata` 截断指纹、唯一性失败非 0 |
| `test_rva_tools.py` | `locate_hooks` 的索引平移/退化、`table_scan`、`find_methptr`、`ptr_semantics`、`dump_rva`、`xref`、`read_str` |

关键点：**这些测试是为「缺陷回归」写的** —— 比如把 `usm_stream_extract.py` 里的
明文前缀改回固定的 `0x34`，`test_usm.py::test_frame0_regression_old_plain_0x34_is_wrong`
与 `test_usm_tools.py::StreamExtractTest::test_decrypt_writes_correct_ivf` 立刻会红。
