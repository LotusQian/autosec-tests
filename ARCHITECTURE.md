# 架构与设计决策

> 给接手这个仓库的人：为什么这么分层、改哪里会牵动哪里、哪些设计不能随便动。
> 操作层面（怎么跑、怎么加用例、提交规范）见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 定位

把「汽车诊断安全的测评经验」变成**可执行、可复现、可交付证据**的断言库。

**不是**：产品级协议栈（`uds_core` 只实现测评需要的十几个服务）、fuzz 平台（没有覆盖引导）、
CANoe 替代品（没有界面和 CAPL）、硬件在环台架（全部仿真）。

## 三层架构

```
┌──────────────────────── 测试层（只写断言） ────────────────────────┐
│ test_uds_security   test_can_signals   test_doip   test_secoc      │
│ test_flashing       test_firmware      test_case_matrix            │
└──────────┬────────────────────────────────────────────┬────────────┘
           │ fixture 给通道                              │ 直接调用
┌──────────▼───────────┐                       ┌────────▼─────────┐
│ flasher（客户端流程） │                       │ secoc（PDU 层）   │
└──────────┬───────────┘                       └────────┬─────────┘
           │                                            │
┌──────────▼────────────────────────────────────────────▼─────────┐
│                  uds_core.UdsCore（唯一的 ECU 大脑）             │
│   0x10  0x11  0x22  0x27  0x2E  0x31  0x34  0x36  0x37  0x3E     │
└──────────┬────────────────────────────────────────────┬─────────┘
           │                                            │
┌──────────▼───────────┐                      ┌─────────▼─────────┐
│ sim_ecu（CAN/ISO-TP） │                      │ doip_gateway(TCP) │
└──────────┬───────────┘                      └─────────┬─────────┘
           │                                            │
   iso_tp_bus（python-can + can-isotp）            socket :13400

   横切两层：evidence.py（记录每次交互） · cases/registry.json（覆盖矩阵）
```

**箭头只有一个方向**：测试层依赖目标层，目标层依赖传输层，反过来不成立。

- 换硬件 → 只改最底层 `iso_tp_bus.open_bus(interface=..., channel=...)`
- 加协议 → 只加中间层（新的 `xxx_ecu.py` 挂到同一个 `UdsCore`）
- 加用例 → 只动最上层

**如果改一个需求要同时动三层，说明分层错了，先停下重新设计。**

## 四个不能随便改的决定

| 决定 | 原因 | 改掉会怎样 |
|---|---|---|
| UDS 与传输解耦 | 同一套断言要跑 CAN 和 TCP | 出现两套 UDS 实现，改一处漏一处 |
| 双档实现（compliant / vulnerable） | 用例必须证明"能检出缺陷"；单档实现永远绿，等于没测 | 用例退化成"跑通即通过"，测评价值归零 |
| 矩阵用 xfail 而不是删掉 | 缺口要可见 | 覆盖报告失真，客户问"这条测了吗"答不上 |
| 证据用 json+md 而不是 pcap | pytest 进程内拿不到网卡级包，pcap 该由 tshark 现场抓 | 为产 pcap 引入抓包依赖，CI 跑不动 |

### 双档实现怎么用

`secoc.py` 里 `SecoCConfig` 的开关可以组合出「合规」和「有缺陷」两种行为：

```python
compliant_config()    # 全开：新鲜度、绑定 PDU、必须有 MAC
vulnerable_config()   # 全关：重放、移植、降级全部放行
```

同一组攻击跑两遍：**合规必须拦住，缺陷必须放过**。第二遍挂掉，说明这条用例根本没测到东西。

## 代码地图

| 文件 | 职责 | 谁依赖它 | 改动风险 |
|---|---|---|---|
| `uds_core.py` | UDS 服务端逻辑，纯状态机 | sim_ecu、doip_gateway、flasher | **高**：影响全部 60+ 条诊断用例 |
| `sim_ecu.py` | 把 UdsCore 挂到 CAN | conftest 的 `ecu` fixture | 中 |
| `doip_gateway.py` | DoIP 编解码 + 路由激活 | test_doip | 中 |
| `iso_tp_bus.py` | python-can / isotp 胶水 | sim_ecu、conftest | 低（换硬件只改这里） |
| `secoc.py` | CMAC + 新鲜度 + 双档配置 | test_secoc | 中 |
| `flasher.py` | 刷写客户端流程 | test_flashing | 低 |
| `firmware.py` | 固件初筛（独立模块） | test_firmware | 低 |
| `evidence.py` | 证据记录与渲染 | conftest | 低 |
| `tools/extract_cases.py` | 文档 → registry | 无（离线工具） | 低 |
| `cases/registry.json` | 覆盖矩阵（**生成物，不要手改**） | test_case_matrix | 改错会让矩阵撒谎 |

## 为什么有 73 条用例矩阵

文档里有 73 条用例，只有一部分能自动化。矩阵把它们分成四种状态：

| 状态 | 含义 |
|---|---|
| `covered` | 有直接对应的自动化用例 |
| `partial` | 只覆盖了部分检查点 |
| `blocked` | 环境不具备（缺硬件/未实现协议），**必须写原因** |
| `todo` | 还没写 |

`test_covered_cases_point_to_existing_tests` 会检查每条覆盖声明是否真的指向一个存在的测试函数——
没有这条自检，矩阵会在重构后悄悄撒谎。

## 测试规模

146 个测试项 = **85 passed + 61 xfailed**。xfail 全部来自矩阵，是**故意可见的缺口**。

| 文件 | 数量 | 内容 |
|---|---|---|
| `test_uds_security.py` | 10 | 会话、DID、安全访问 |
| `test_can_signals.py` | 5 | DBC、边界、模糊 |
| `test_doip.py` | 9 | 路由激活、NACK、存活检查 |
| `test_secoc.py` | 18 | 重放、移植、降级、密钥隔离 |
| `test_flashing.py` | 13 | 刷写流程、CRC、验签 |
| `test_firmware.py` | 10 | 熵、魔数、字符串、解包 |
| `test_case_matrix.py` | 77 | 73 条文档用例 + 4 条自检 |
| `test_evidence.py` | 4 | 证据链自检 |

## 证据链

每次跑测试自动生成 `evidence/<时间戳>/session.json` + `session.md`，
CI 把它作为 artifact 上传。`pytest --no-evidence` 可关闭。

## 下一步

阶段 A（纯仿真）已完成。阶段 B 需要 CAN 硬件，见 README 的「下一步」。
