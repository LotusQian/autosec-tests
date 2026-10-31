"""SecOC（AUTOSAR 安全车载通信）测评用例。

核心思路：同一组攻击，跑两遍。
  * 对「合规实现」→ 必须全部拦住
  * 对「缺陷实现」→ 必须全部放过（证明用例真有检测能力，不是摆设）

四个攻击面对应真实项目里最常见的四个坑：
  重放 / 心跳乱序、跨报文移植、降级为无保护帧、密钥不隔离。
"""
import struct

import can
import pytest

from secoc import (
    SecoCReceiver,
    SecoCSender,
    compliant_config,
    vulnerable_config,
)

KEY_A = bytes(range(16))                 # ECU-A 的密钥
KEY_B = bytes(range(16, 32))             # ECU-B 的密钥

PDU_TORQUE = 0x110                       # 扭矩请求（8 字节）
PDU_GEAR = 0x2F1                         # 挡位（8 字节，便于做移植攻击）
PDU_DEMO = 0x123                          # 用于 CAN 总线集成测试（4 字节）

PAYLOAD_8 = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
PAYLOAD_4 = bytes([0x10, 0x20, 0x30, 0x40])

LENGTHS = {PDU_TORQUE: 8, PDU_GEAR: 8, PDU_DEMO: 4}
KEYS = {PDU_TORQUE: KEY_A, PDU_GEAR: KEY_A, PDU_DEMO: KEY_A}


def make_pair(cfg):
    tx = SecoCSender(KEYS, cfg)
    rx = SecoCReceiver(KEYS, cfg, pdu_lengths=LENGTHS)
    return tx, rx


# ---------------- 基线 ----------------
def test_accepts_valid_frame():
    tx, rx = make_pair(compliant_config())
    frame = tx.build(PDU_TORQUE, PAYLOAD_8)
    ok, data, reason = rx.receive(PDU_TORQUE, frame)
    assert ok and data == PAYLOAD_8 and reason == "ok"


def test_wire_format_is_truncated():
    """线上 MAC 只有 24 bit、FV 只有 8 bit —— 这个截断本身就是攻击面。"""
    tx, _ = make_pair(compliant_config())
    frame = tx.build(PDU_TORQUE, PAYLOAD_8)
    assert len(frame) == 8 + 1 + 3          # payload + FV + MAC


# ---------------- 四个攻击面（合规实现必须拦住） ----------------
def test_rejects_replay():
    """同一帧重放：FV 不前进就是攻击。"""
    tx, rx = make_pair(compliant_config())
    frame = tx.build(PDU_TORQUE, PAYLOAD_8)
    assert rx.receive(PDU_TORQUE, frame)[0] is True
    ok, _, reason = rx.receive(PDU_TORQUE, frame)
    assert not ok and reason.startswith("freshness:")


def test_rejects_fv_too_far_ahead():
    """FV 一次跳太远（比如伪造未来帧），应落在窗口外。"""
    tx, rx = make_pair(compliant_config())
    rx.receive(PDU_TORQUE, tx.build(PDU_TORQUE, PAYLOAD_8, counter=1))
    ok, _, reason = rx.receive(PDU_TORQUE, tx.build(PDU_TORQUE, PAYLOAD_8, counter=101))
    assert not ok and reason == "freshness:too-far-ahead"


def test_rejects_stale_fv():
    """回放一个较旧的 FV，即使 MAC 正确也必须拒。"""
    tx, rx = make_pair(compliant_config())
    for c in range(1, 21):
        assert rx.receive(PDU_TORQUE, tx.build(PDU_TORQUE, PAYLOAD_8, counter=c))[0]
    ok, _, reason = rx.receive(PDU_TORQUE, tx.build(PDU_TORQUE, PAYLOAD_8, counter=5))
    assert not ok and reason.startswith("freshness:")


def test_rejects_tampered_mac():
    """改 1 bit 的 MAC。"""
    tx, rx = make_pair(compliant_config())
    frame = bytearray(tx.build(PDU_TORQUE, PAYLOAD_8))
    frame[-1] ^= 0x01
    ok, _, reason = rx.receive(PDU_TORQUE, bytes(frame))
    assert not ok and reason == "mac:invalid"


def test_rejects_cross_pdu_transplant():
    """把 0x110 的 FV+MAC 贴到 0x2F1 上（MAC 未绑定 PDU ID 时可成功）。"""
    tx, rx = make_pair(compliant_config())
    legit = tx.build(PDU_TORQUE, PAYLOAD_8, counter=1)
    forged = PAYLOAD_8 + legit[8:]           # 换成挡位报文的 PDU ID
    ok, _, reason = rx.receive(PDU_GEAR, forged)
    assert not ok and reason == "mac:invalid"


def test_rejects_unsecured_frame():
    """降级攻击：发一条完全不带 SecOC 字段的裸报文，必须 fail-closed。"""
    _, rx = make_pair(compliant_config())
    ok, _, reason = rx.receive(PDU_TORQUE, PAYLOAD_8)
    assert not ok and reason == "secoc:missing"


def test_rejects_wrong_ecu_key():
    """用 ECU-B 的密钥签名，ECU-A 必须拒（密钥隔离）。"""
    tx_b = SecoCSender({PDU_TORQUE: KEY_B}, compliant_config())
    _, rx = make_pair(compliant_config())
    ok, _, reason = rx.receive(PDU_TORQUE, tx_b.build(PDU_TORQUE, PAYLOAD_8, counter=1))
    assert not ok and reason == "mac:invalid"


# ---------------- 同一组攻击在缺陷实现上的表现 ----------------
ATTACKS = ["replay", "stale", "transplant", "downgrade"]


def _attack(name, cfg):
    """返回该实现是否接受了这次攻击。"""
    tx, rx = make_pair(cfg)
    if name == "replay":
        frame = tx.build(PDU_TORQUE, PAYLOAD_8)
        rx.receive(PDU_TORQUE, frame)
        return rx.receive(PDU_TORQUE, frame)[0]
    if name == "stale":
        for c in range(1, 21):
            rx.receive(PDU_TORQUE, tx.build(PDU_TORQUE, PAYLOAD_8, counter=c))
        return rx.receive(PDU_TORQUE, tx.build(PDU_TORQUE, PAYLOAD_8, counter=5))[0]
    if name == "transplant":
        legit = tx.build(PDU_TORQUE, PAYLOAD_8, counter=1)
        return rx.receive(PDU_GEAR, PAYLOAD_8 + legit[8:])[0]
    if name == "downgrade":
        return rx.receive(PDU_TORQUE, PAYLOAD_8)[0]
    raise ValueError(name)


@pytest.mark.parametrize("attack", ATTACKS)
def test_compliant_implementation_blocks_attack(attack):
    assert _attack(attack, compliant_config()) is False


@pytest.mark.parametrize("attack", ATTACKS)
def test_vulnerable_implementation_is_detected(attack):
    """如果这条挂了，说明用例没抓住缺陷 —— 那这些用例就是摆设。"""
    assert _attack(attack, vulnerable_config()) is True


# ---------------- 真实总线集成 ----------------
def test_over_virtual_can_bus():
    """4 字节 payload + 1 字节 FV + 3 字节 MAC = 恰好一帧标准 CAN。"""
    tx, rx = make_pair(compliant_config())
    frame = tx.build(PDU_DEMO, PAYLOAD_4)
    assert len(frame) == 8

    # 虚拟总线默认不回环自己发的报文，这里开 receive_own_messages 模拟"另一台 ECU 收到"
    bus = can.Bus(interface="virtual", channel="secoc-bus", receive_own_messages=True)
    try:
        bus.send(can.Message(arbitration_id=PDU_DEMO, data=frame, is_extended_id=False))
        msg = bus.recv(timeout=1.0)
        assert msg is not None and msg.arbitration_id == PDU_DEMO

        ok, data, _ = rx.receive(msg.arbitration_id, msg.data)
        assert ok and data == PAYLOAD_4

        # 同一条帧重放到总线上，依然要被拒
        bus.send(can.Message(arbitration_id=PDU_DEMO, data=frame, is_extended_id=False))
        msg2 = bus.recv(timeout=1.0)
        assert rx.receive(msg2.arbitration_id, msg2.data)[0] is False
    finally:
        bus.shutdown()
