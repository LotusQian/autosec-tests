# autosec-tests — 汽车诊断安全的最小可跑靶场

[![tests](https://github.com/LotusQian/autosec-tests/actions/workflows/test.yml/badge.svg)](https://github.com/LotusQian/autosec-tests/actions/workflows/test.yml)
[![python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)

不需要任何 CAN 硬件。用一个**虚拟 CAN 总线 + 仿真 ECU**，把桌面
`汽车网络安全面试\008 UDS 诊断安全测试用例集` 里的断言变成可执行的 pytest。

## 为什么先做这个

你手上有 20 多份用例文档，但一条都跑不起来——因为缺总线、缺协议栈、缺对端。
这三个缺口里，**协议栈和对端可以软件补**，只有"真实总线"必须靠硬件。
所以先让整条链路在软件里闭环：等 CAN 适配器插上，只改一个参数就能转到实车。

## 目录

```
autosec-tests/
  uds_core.py          UDS 服务端核心（0x10/0x22/0x27/0x2E/0x31/0x34/0x36/0x37/0x11）
  iso_tp_bus.py        python-can 与 isotp 的胶水（换硬件只改这里）
  sim_ecu.py           把 UdsCore 挂到 CAN 上
  doip_gateway.py      DoIP 网关仿真（TCP 13400：路由激活 + 诊断 + 存活检查）
  secoc.py             SecOC：AES-128-CMAC 截断 + 新鲜度窗口（合规/缺陷双档）
  flasher.py           刷写客户端：解锁 → 下载 → 传输 → CRC → 验签 → 复位
  firmware.py          固件初筛：熵扫描 + 特征识别 + 字符串 + 解包（纯标准库）
  evidence.py          证据链：每次交互落成 json + markdown
  demo.dbc             示例 DBC（3 个信号 + 1 个安全访问报文）
  conftest.py          fixtures + 证据链挂钩
  tools/
    extract_cases.py   把用例集 Markdown 解析成 cases/registry.json
  cases/
    registry.json      73 条文档用例 + 覆盖状态（covered/partial/blocked/todo）
  tests/
    test_uds_security.py   10 条诊断安全用例（CAN）
    test_can_signals.py     5 条信号/DBC/健壮性用例（CAN）
    test_doip.py            9 条 DoIP 用例（4 条正常路径 + 5 条协议层否定）
    test_secoc.py           18 条 SecOC 用例（基线 2 + 攻击面 8 + 对照 8）
    test_flashing.py        13 条刷写用例（流程 7 + 安全 6）
    test_firmware.py        10 条固件初筛用例
    test_case_matrix.py     73 条文档用例的覆盖矩阵 + 4 条自检
    test_evidence.py        4 条证据链自检
  pytest.ini
  requirements.txt
```

## 跑起来

```powershell
cd C:\deepseekHARNESSwork\projects\autosec-tests
$env:PYTHONUTF8 = '1'                      # 让中文断言信息不乱码
C:\env\autosec\Scripts\python.exe -m pytest -v
```

当前结果：**146 个测试项 = 85 passed + 61 xfailed**（约 2 秒）。
xfail 全部来自用例矩阵——那是**故意可见的缺口**，不是失败。

## 覆盖了什么

| 用例 | 检测的缺陷 |
|---|---|
| `test_session_control_positive` | 0x10 会话切换基线 |
| `test_read_vin_positive` | 0x22 F190 读 17 字节 VIN，多帧 ISO-TP |
| `test_read_unknown_did_nrc31` | 非法 DID 必须回 0x31 |
| `test_unknown_service_nrc11` | 非法服务必须回 0x11 |
| `test_seed_must_change_between_requests` | **种子重放**：两次种子相同即高危 |
| `test_write_denied_before_unlock` | **鉴权绕过**：未解锁就能 0x2E 写入 |
| `test_wrong_key_nrc35` | 错误密钥必须回 0x35 |
| `test_unlock_with_correct_key_then_write` | 正向链路：解锁 → 写 → 读回 |
| `test_lockout_after_three_wrong_keys` | **无锁定**：可无限暴力猜密钥 |
| `test_random_traffic_does_not_kill_ecu` | 总线洪水下诊断是否仍可用 |
| `test_dbc_roundtrip` / `test_encode_out_of_range_raises` / `test_signal_limits_are_sane` / `test_ecu_decodes_fuzzed_frames` | 信号边界与解码健壮性 |
| `test_routing_activation_success` | 路由激活响应码 0x10、实体地址回填 |
| `test_diagnostic_without_activation_is_rejected` | **未激活就发诊断** → 必须 NACK 0x02 |
| `test_unknown_target_address_is_rejected` | **目标地址不存在** → 必须 NACK 0x03（否则网关可被当前跳板） |
| `test_unsupported_payload_type_gets_generic_nack` | 未知载荷类型 → 通用 NACK 0x01 |
| `test_alive_check` | 0x0007/0x0008 存活检查 |
| `test_security_access_state_survives_tcp` | 安全访问状态必须绑定在 TCP 连接上，不能跨连接串状态 |
| `test_rejects_replay` | **重放**：同一帧再发一次，FV 没前进就必须拒 |
| `test_rejects_stale_fv` | **旧帧回放**：滞后于窗口下界的 FV |
| `test_rejects_fv_too_far_ahead` | FV 跳跃超窗口（伪造未来帧） |
| `test_rejects_tampered_mac` | MAC 改 1 bit |
| `test_rejects_cross_pdu_transplant` | **跨报文移植**：MAC 未绑定 PDU ID 时可把 A 报文的 MAC 贴到 B 上 |
| `test_rejects_unsecured_frame` | **降级**：发裸报文，必须 fail-closed，不能当合法 |
| `test_rejects_wrong_ecu_key` | **密钥不隔离**：拿 B 的密钥签 A 的报文 |
| `test_vulnerable_implementation_is_detected` ×4 | 对照组：同样的攻击在缺陷实现上必须成功，否则用例是摆设 |

前 6 个"缺陷检测"用例，在真实 ECU 上复现时就是**可直接写进报告的发现**。

## DoIP 部分

结构是分层的：`uds_core.UdsCore` 只懂 UDS，`sim_ecu.SimEcu` 和 `doip_gateway.DoIpGateway`
各自把它挂到 CAN 和 TCP 上。所以**同一套诊断用例，换个传输层就能复用**——
`test_uds_security.py`（CAN）和 `test_doip.py`（TCP）测的其实是同一个大脑。

为什么另写一批裸 socket 用例：`doipclient` 只会走"正常路径"，而测评里最容易漏的是
**网关不守规矩**的情况——未激活就转发诊断、目标地址不存在时默默丢弃、未知载荷类型不返回 NACK。
这些用库是测不出来的，必须手工拼字节。

抓包验证：

```powershell
& C:\Tools\Wireshark\tshark.exe -i loopback -f "tcp port 13402" -V
```

改端点只需换 `DoIPClient` 的三个参数（真车一般是网关 IP + 0x0E80 之类的逻辑地址）：

```python
client = DoIPClient("192.168.1.10", 0x0E80, tcp_port=13400, client_logical_address=0x0E00)
```

## SecOC 部分

**它解决什么**：CAN 报文本身没有任何认证。任何能接上总线的人都能伪造一条「扭矩请求 300 Nm」，
接收端照单全收。SecOC 给每条报文加一个**截断 MAC** 和一个**新鲜度值（FV）**，接收端验证通过才采信。

**线路格式**（本项目实现）：

```
authentic PDU ‖ 截断 FV(1 字节) ‖ 截断 MAC(3 字节)        → 8 字节报文变成 12 字节
MAC = AES-128-CMAC(K, [PDU_ID] ‖ payload ‖ full_FV)[:24bit]
```

**为什么做成两套实现**：`secoc.py` 的 `SecoCConfig` 有四个开关，`compliant_config()` 全开、
`vulnerable_config()` 全关。同一组攻击跑两遍：

| | 合规实现 | 缺陷实现 |
|---|---|---|
| 重放 / 旧帧 | 必须拦住 | 必须放过 |
| 跨报文移植 | 必须拦住 | 必须放过 |
| 降级为裸报文 | 必须拦住（fail-closed） | 必须放过（fail-open） |

第二条不是凑数的——**如果那条用例在缺陷实现上也拦住了，说明它根本没测到东西**。
这是测评用例最容易被忽略的自检。

**四个攻击面对应的真实缺陷**：

1. **新鲜度不校验** → 攻击者录一条刹车指令反复重放
2. **MAC 不绑定 PDU ID** → 把低价值报文的 MAC 挪到高价值报文上
3. **fail-open** → 只要不发 SecOC 字段就能绕过（最容易被漏测，因为它**不报错**）
4. **密钥全局共用** → 拆掉一个节点就能伪造全网

**边界（重要）**：SecOC 是 **CAN / CAN FD** 的方案。到了车载以太网，业界用 TLS / MACsec，
不是 SecOC。所以本项目**没有**给 DoIP 链路套 SecOC——硬套是把两个不同层次的机制混为一谈。
这个边界在面试里经常被问到，能答清楚的人不多。

## 刷写部分

刷写（reprogramming）是整车攻击面里**收益最高**的一环：一次成功就能改固件，而不是改一帧报文。

标准流程与对应服务：

| 步骤 | 服务 | 本项目的校验点 |
|---|---|---|
| 安全访问 | 0x27 | 未解锁直接 0x34 → NRC 0x33 |
| 请求下载 | 0x34 | 地址/长度格式、镜像大小上限 |
| 传输数据 | 0x36 | 块序号连续、累计长度不超声明值 |
| 退出传输 | 0x37 | 没传完就退出 → NRC 0x24 |
| 完整性 | 0x31 FF01 | CRC32 与客户端一致 |
| 真实性 | 0x31 FF02 | Ed25519 验签 |
| 复位 | 0x11 | 状态清空 |

**为什么 CRC 和签名都要**：CRC 防的是传输损坏（丢包、位翻转），签名防的是恶意替换。
只做 CRC 等于"完好地刷入一个假镜像"；只做签名则每次失败都要跑完整验签，日志和耗时都不划算。

四个最有价值的用例：

- `test_tampered_image_fails_signature` —— 用原镜像的签名去刷被改过的镜像
- `test_corrupted_transfer_is_caught_by_crc` —— 传输途中翻 1 bit，CRC 先抓住
- `test_block_counter_wraps_past_255` —— 块序号 0xFF→0x00 回绕，这里的 off-by-one 很常见
- `test_ecu_without_public_key_rejects_signature` —— 没配公钥时**不能静默跳过验签**

## 证据链部分

`146 passed` 不是证据。客户要的是「哪条用例、什么时间、发了什么字节、回了什么字节」。

每次跑测试自动生成：

```
evidence/20261031-230720/
  session.json    机器可读：时间戳、用例名、传输类型、请求/响应原始字节
  session.md      人可读：Markdown 表格，可直接贴进报告附录
```

```powershell
pytest                                  # 默认生成
pytest --no-evidence                    # 关掉
pytest --evidence-dir D:\case-001       # 指定目录（按项目/客户分）
```

CI 里每次运行都会把证据包作为 artifact 上传（保留 14 天），评审时可以直接下载。

## 用例矩阵部分

`cases/registry.json` 里是 **73 条**用例——不是我编的，是从 `汽车网络安全面试/` 那套 Markdown 里解析出来的：

```powershell
python tools/extract_cases.py "C:\Users\ASUS\Desktop\工作\汽车网络安全面试"
```

状态模型：

| 状态 | 含义 | 在测试里的表现 |
|---|---|---|
| `covered` | 有直接对应的自动化用例 | 通过 |
| `partial` | 只覆盖了部分检查点 | 通过（备注写清覆盖到哪） |
| `blocked` | 环境不具备（缺硬件/未实现协议） | xfail，**必须写原因** |
| `todo` | 还没写 | xfail |

关键设计：`test_covered_cases_point_to_existing_tests` 会检查每条覆盖声明是否**真的指向一个存在的测试函数**。
没有这条自检，矩阵就会在重构后悄悄撒谎。

`blocked` 和 `todo` 分开，是为了让「没做」和「做不了」不混为一谈——这在测评报告里是两个完全不同的结论。

## 固件分析部分

binwalk 在 Windows 上要 WSL，CI 里跑不了。`firmware.py` 是纯标准库实现，Windows / Linux / Actions 都能跑：

```powershell
python firmware.py scan  update.bin
python firmware.py carve update.bin out/
```

`scan` 输出四件事——正好是打开一个未知固件第一分钟想知道的东西：

1. **熵**：整体熵 + 窗口化高熵区（>7.5 视为压缩/加密载荷）
2. **特征**：19 种魔数（gzip/xz/squashfs/cramfs/JFFS2/UBI/ELF/U-Boot/Android boot/DTB/PEM…）
3. **字符串**：ASCII 提取 + 可疑项标记（AKIA 密钥、私钥头、URL、`root:`/`debug=`）
4. **解包**：gzip / xz 成员直接提取

一个实现细节值得说：解压用 `zlib.decompressobj` 而不是 `gzip.decompress`。
固件里的压缩成员后面通常还跟着别的数据，一次性解压会因为"尾部有多余字节"而失败——
这个坑在真实固件上非常常见。

## 换成真实硬件

只改 `conftest.py` 里的三行：

```python
CHANNEL  = "PCAN_USBBUS1"     # 或 gs_usb 的 channel=0 / slcan 的 "COM5"
INTERFACE = "pcan"            # pcan / gs_usb / slcan / vector / socketcan
BITRATE   = 500000
```

并把 `iso_tp_bus.open_bus()` 的调用改成：

```python
bus = iso_tp_bus.open_bus(interface=INTERFACE, channel=CHANNEL, bitrate=BITRATE)
```

常见适配器对应关系：

| 硬件 | interface | channel |
|---|---|---|
| PEAK PCAN-USB FD | `pcan` | `PCAN_USBBUS1` |
| CANable 2.0 / candleLight | `gs_usb` | `0` |
| 串口 SLCAN（如 CANable slcan 固件） | `slcan` | `COM5` |
| Kvaser | `kvaser` | `0` |
| Vector VN1610 | `vector` | `0`（需装 XL Driver） |
| WSL 里的 vcan | `socketcan` | `vcan0` |

换完先跑 `test_tester_present`——它能通，说明物理层、波特率、ID 全对了。

## 已知局限（刻意的）

- **单 ECU、固定 ID**：真实整车是多 ECU、网关路由、功能寻址。要扩，就把 `SimEcu` 里的
  `req_id/resp_id` 变成列表，或用 `functional_id`。
- **密钥算法是假的**（`seed ^ 0xA5A5A5A5`）：真实是 HSM 里跑 AES-CMAC。
- **没有时间参数校验**：P2/P2\*/S3 超时这类用例需要真实 ECU 的响应时间才有意义。
- **没有 SOME/IP / LIN / 车载以太网二层**：见 `cases/registry.json` 里的 `blocked`。
- **固件分析只做初筛**：不解 squashfs、不做反编译。深挖需要 Ghidra + binwalk（WSL）。

## 阶段 A 完成情况

| # | 任务 | 状态 | 产物 |
|---|---|---|---|
| A1 | SecOC | ✅ | `secoc.py` + 18 条用例（合规/缺陷双档对照） |
| A2 | 刷写 0x34/0x36/0x37 + CRC + 签名 | ✅ | `flasher.py` + 13 条用例 |
| A3 | 用例集转 pytest 矩阵 | ✅ | `tools/extract_cases.py` + 73 条用例的 `registry.json` |
| A4 | 证据链 | ✅ | `evidence.py` + 自动 json/md + CI artifact |
| A5 | 固件初筛 | ✅ | `firmware.py` + 10 条用例 |

## 下一步：阶段 B（需要硬件）

1. **接真硬件**：PCAN 或 CANable，把 `test_tester_present` 跑通（物理层/波特率/ID 全对）
2. **真实 DBC**：用实车 DBC 替换 `demo.dbc`，识别周期报文
3. **UDS 模糊测试**：种子熵、NRC 组合、时序（P2/P2\*）
4. **双通道场景**：CAN + 以太网经网关路由的联合测试
