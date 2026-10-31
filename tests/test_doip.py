"""DoIP（ISO 13400-2）测试：同一套 UDS 用例跑在 TCP 上，外加协议层否定用例。

两类测试刻意分开：
  * 用 doipclient 的"正常路径"——验证与常用开源工具互通
  * 用裸 socket 的"协议层"——验证网关自己是否守规矩（NACK 码、路由激活前置）
"""
import socket
import struct
import time

import pytest
from doipclient import DoIPClient

from doip_gateway import (
    DoIpGateway,
    PT_ALIVE_CHECK_REQUEST,
    PT_ALIVE_CHECK_RESPONSE,
    PT_DIAG_MESSAGE,
    PT_DIAG_NEG_ACK,
    PT_ROUTING_ACT_REQUEST,
    PT_ROUTING_ACT_RESPONSE,
    PT_GENERIC_NACK,
)
from uds_core import UdsCore

ECU_ADDR = 0x0E80
CLIENT_ADDR = 0x0E00
PORT = 13402


# ---------------- fixtures ----------------
@pytest.fixture(scope="module")
def gw():
    g = DoIpGateway(UdsCore(), port=PORT, entity_address=ECU_ADDR).start()
    time.sleep(0.2)
    yield g
    g.stop()


@pytest.fixture(scope="module")
def doip(gw):
    client = DoIPClient("127.0.0.1", ECU_ADDR, tcp_port=PORT, udp_port=PORT)
    yield client
    client.close()


def uds(doip, req):
    """DoIP 上的 UDS 一问一答。send_diagnostic 返回只代表收到肯定确认。"""
    doip.send_diagnostic(bytes(req))
    return bytes(doip.receive_diagnostic())


# ---------------- 裸 socket 工具 ----------------
def raw_conn():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    s.settimeout(3)
    return s


def send_raw(s, ptype, payload):
    s.sendall(struct.pack(">BBHI", 0x02, 0xFD, ptype, len(payload)) + payload)


def recv_raw(s):
    hdr = b""
    while len(hdr) < 8:
        chunk = s.recv(8 - len(hdr))
        if not chunk:
            raise ConnectionError("gateway closed connection")
        hdr += chunk
    _ver, _inv, ptype, length = struct.unpack(">BBHI", hdr)
    payload = b""
    while len(payload) < length:
        payload += s.recv(length - len(payload))
    return ptype, payload


def activate(s, client_addr=CLIENT_ADDR):
    send_raw(s, PT_ROUTING_ACT_REQUEST,
             struct.pack(">H", client_addr) + b"\x00" + b"\x00\x00\x00\x00")
    return recv_raw(s)


# ---------------- 正常路径（doipclient） ----------------
def test_session_control_over_doip(gw, doip):
    assert uds(doip, [0x10, 0x03])[:2] == b"\x50\x03"


def test_read_vin_over_doip(gw, doip):
    resp = uds(doip, [0x22, 0xF1, 0x90])
    assert resp[:3] == b"\x62\xf1\x90"
    assert len(resp) == 3 + 17


def test_tester_present_over_doip(gw, doip):
    assert uds(doip, [0x3E, 0x00])[:1] == b"\x7e"


def test_security_access_state_survives_tcp(gw, doip):
    """安全访问的种子必须落在这条 TCP 连接的状态里，不能每次都是新会话。"""
    gw.core.reset()
    seed = uds(doip, [0x27, 0x01])[2:6]
    assert uds(doip, [0x27, 0x02] + list(UdsCore.key_for(seed))) == b"\x67\x02"
    assert uds(doip, [0x2E, 0xF1, 0x90] + list(b"OVER-DOIP-VIN-001")) == b"\x6e\xf1\x90"
    assert uds(doip, [0x22, 0xF1, 0x90])[3:] == b"OVER-DOIP-VIN-001"


# ---------------- 协议层（裸 socket） ----------------
def test_routing_activation_success(gw):
    s = raw_conn()
    try:
        ptype, payload = activate(s)
        assert ptype == PT_ROUTING_ACT_RESPONSE
        assert payload[0:2] == struct.pack(">H", CLIENT_ADDR)
        assert struct.unpack(">H", payload[2:4])[0] == ECU_ADDR
        assert payload[4] == 0x10            # routing successfully activated
    finally:
        s.close()


def test_diagnostic_without_activation_is_rejected(gw):
    """未做路由激活就发诊断，必须回 0x8003 / 0x02（routing activation required）。"""
    s = raw_conn()
    try:
        send_raw(s, PT_DIAG_MESSAGE,
                 struct.pack(">HH", CLIENT_ADDR, ECU_ADDR) + bytes([0x3E, 0x00]))
        ptype, payload = recv_raw(s)
        assert ptype == PT_DIAG_NEG_ACK
        assert payload[4] == 0x02
    finally:
        s.close()


def test_unknown_target_address_is_rejected(gw):
    """目标地址不是本网关时，必须回 0x8003 / 0x03（unknown target address）。"""
    s = raw_conn()
    try:
        activate(s)
        send_raw(s, PT_DIAG_MESSAGE,
                 struct.pack(">HH", CLIENT_ADDR, 0x1234) + bytes([0x3E, 0x00]))
        ptype, payload = recv_raw(s)
        assert ptype == PT_DIAG_NEG_ACK
        assert payload[4] == 0x03
    finally:
        s.close()


def test_alive_check(gw):
    s = raw_conn()
    try:
        send_raw(s, PT_ALIVE_CHECK_REQUEST, struct.pack(">H", CLIENT_ADDR))
        ptype, payload = recv_raw(s)
        assert ptype == PT_ALIVE_CHECK_RESPONSE
        assert payload == struct.pack(">H", CLIENT_ADDR)
    finally:
        s.close()


def test_unsupported_payload_type_gets_generic_nack(gw):
    s = raw_conn()
    try:
        send_raw(s, 0x1234, b"\x00")
        ptype, payload = recv_raw(s)
        assert ptype == PT_GENERIC_NACK
        assert payload[0] == 0x01            # unknown payload type
    finally:
        s.close()
