"""CAN 信号层：DBC 编解码、越界值、以及总线上有垃圾流量时 ECU 是否还活着。"""
import random

import can
import pytest


def test_dbc_roundtrip(dbc):
    """DBC 编解码自洽：物理值 -> 原始值 -> 物理值。"""
    msg = dbc.get_message_by_name("VehicleStatus")
    raw = msg.encode(
        {
            "VehicleSpeed": 100.0,
            "SteeringAngle": -90.0,
            "BrakePressure": 12.5,
            "GearPosition": 3,
        }
    )
    dec = msg.decode(raw, decode_choices=False)
    assert abs(dec["VehicleSpeed"] - 100.0) < 0.02
    assert abs(dec["SteeringAngle"] - (-90.0)) < 0.2
    assert abs(dec["BrakePressure"] - 12.5) < 0.2
    assert dec["GearPosition"] == 3


def test_encode_out_of_range_raises(dbc):
    """超出 DBC 定义范围的物理值，编码时必须报错（否则就是测试用例能注入的缺口）。"""
    msg = dbc.get_message_by_name("VehicleStatus")
    with pytest.raises(Exception):
        msg.encode({"VehicleSpeed": 300.0, "SteeringAngle": 0.0,
                    "BrakePressure": 0.0, "GearPosition": 0})


def test_signal_limits_are_sane(dbc):
    """信号边界值应当是"不可能的物理值"，用来做越界注入。"""
    msg = dbc.get_message_by_name("VehicleStatus")
    speed = msg.get_signal_by_name("VehicleSpeed")
    assert speed.minimum == 0 and speed.maximum == 250
    assert speed.scale == 0.01


def test_random_traffic_does_not_kill_ecu(client, dbc):
    """总线上灌 500 帧随机报文（非诊断 ID），ECU 仍应正常响应诊断。"""
    bus = client.bus
    rnd = random.Random(1337)
    for _ in range(500):
        aid = rnd.randint(0x100, 0x6FF)
        bus.send(can.Message(arbitration_id=aid,
                             data=bytes(rnd.getrandbits(8) for _ in range(8)),
                             is_extended_id=False))
    assert client([0x3E, 0x00])[:1] == b"\x7e"


def test_ecu_decodes_fuzzed_frames(dbc):
    """对 DBC 报文做原始字节级模糊：解码不应抛异常（健壮性基线）。"""
    msg = dbc.get_message_by_name("VehicleStatus")
    rnd = random.Random(42)
    for _ in range(200):
        data = bytes(rnd.getrandbits(8) for _ in range(8))
        dec = msg.decode(data, decode_choices=False, scaling=True)
        assert isinstance(dec, dict)
