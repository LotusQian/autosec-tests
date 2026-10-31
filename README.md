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
  uds_core.py          UDS 服务端核心（与传输层无关，CAN/DoIP 共用）
  iso_tp_bus.py        python-can 与 isotp 的胶水（换硬件只改这里）
  sim_ecu.py           把 UdsCore 挂到 CAN 上（0x10 / 0x22 / 0x27 / 0x2E / 0x3E）
  doip_gateway.py      DoIP 网关仿真（TCP 13400：路由激活 + 诊断 + 存活检查）
  demo.dbc             示例 DBC（3 个信号 + 1 个安全访问报文）
  conftest.py          fixtures：虚拟总线、Tester 通道、DBC
  tests/
    test_uds_security.py   10 条诊断安全用例（CAN）
    test_can_signals.py     5 条信号/DBC/健壮性用例（CAN）
    test_doip.py            9 条 DoIP 用例（4 条正常路径 + 5 条协议层否定）
  pytest.ini
  requirements.txt
```

## 跑起来

```powershell
cd C:\deepseekHARNESSwork\projects\autosec-tests
$env:PYTHONUTF8 = '1'                      # 让中文断言信息不乱码
C:\env\autosec\Scripts\python.exe -m pytest -v
```

当前结果：**24 passed**（约 1 秒）。

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
- **密钥算法是假的**（`seed ^ 0xA5A5A5A5`）：真实是 HSM 里跑 AES-CMAC。留着是为了让你
  先练"流程缺陷"，而不是"算法破解"。
- **没有 SecOC、没有 DoIP、没有刷写（0x34/0x36/0x37）**：这些是下一步。
- **没有时间参数校验**：P2/P2\*/S3 超时这类用例需要真实 ECU 的响应时间才有意义。

## 下一步（按性价比）

1. **接真硬件**：拿 PCAN 或 CANable，把 `test_tester_present` 跑通。
2. **加 SecOC**：用 `cryptography` 做 CMAC，模拟新鲜度值 + 截断 MAC，写"重放/降级"用例。
3. **加刷写**：0x34 RequestDownload → 0x36 TransferData → 0x37，配 CRC 校验与签名校验。
4. ~~接 DoIP~~ ✅ 已完成（`doip_gateway.py` + `tests/test_doip.py`，9 条用例）
5. **证据链**：每次运行把请求/响应写成 `.txt` + `pcap`（`can.Logger`），直接进报告附录。
