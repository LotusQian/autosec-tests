"""UDS 诊断安全：对照桌面 008 用例集，验证安全访问的四个常见缺陷。

每个用例都对应一条"应该在真实 ECU 上复现"的断言，
换到实车只需要把 conftest 里的 CHANNEL 换成 pcan/slcan。
"""
import pytest


def test_session_control_positive(client, clean_ecu):
    """0x10 03 进入扩展会话，应回 0x50 03。"""
    resp = client([0x10, 0x03])
    assert resp[:2] == b"\x50\x03", f"unexpected: {resp.hex()}"


def test_tester_present(client, clean_ecu):
    """0x3E 00 保活。"""
    assert client([0x3E, 0x00])[:1] == b"\x7e"


def test_read_vin_positive(client, clean_ecu):
    """0x22 F190 读 VIN：应回 0x62 + DID + 17 字节 ASCII。"""
    resp = client([0x22, 0xF1, 0x90])
    assert resp[:3] == b"\x62\xf1\x90", f"unexpected: {resp.hex()}"
    assert len(resp) == 3 + 17
    resp[3:].decode("ascii")          # 能解成 ASCII 才算合法 VIN


def test_read_unknown_did_nrc31(client, clean_ecu):
    """读不存在的 DID 应回 NRC 0x31 (requestOutOfRange)。"""
    assert client([0x22, 0x12, 0x34]) == b"\x7f\x22\x31"


def test_unknown_service_nrc11(client, clean_ecu):
    """不支持的服务应回 NRC 0x11。"""
    assert client([0x99, 0x01]) == b"\x7f\x99\x11"


def test_seed_must_change_between_requests(client, clean_ecu):
    """【缺陷检测】两次 0x27 01 的种子必须不同，否则可重放。"""
    a, b = client([0x27, 0x01]), client([0x27, 0x01])
    assert a[:2] == b"\x67\x01" and b[:2] == b"\x67\x01"
    assert a[2:6] != b[2:6], "seed reused -> replay attack possible"


def test_write_denied_before_unlock(client, clean_ecu):
    """【缺陷检测】未做安全访问就写 DID，必须是 NRC 0x33。"""
    assert client([0x2E, 0xF1, 0x90] + list(b"A" * 17)) == b"\x7f\x2e\x33"


def test_wrong_key_nrc35(client, clean_ecu):
    """错误密钥应回 NRC 0x35 (invalidKey)。"""
    client([0x27, 0x01])
    assert client([0x27, 0x02, 0x00, 0x00, 0x00, 0x00]) == b"\x7f\x27\x35"


def test_unlock_with_correct_key_then_write(client, clean_ecu):
    """正确密钥解锁后应能写 DID 并读回。"""
    from sim_ecu import SimEcu

    seed_resp = client([0x27, 0x01])
    seed = seed_resp[2:6]
    assert client([0x27, 0x02] + list(SimEcu.key_for(seed))) == b"\x67\x02"

    payload = b"NEW-VIN-000000001"
    assert client([0x2E, 0xF1, 0x90] + list(payload)) == b"\x6e\xf1\x90"
    assert client([0x22, 0xF1, 0x90])[3:] == payload


def test_lockout_after_three_wrong_keys(client, clean_ecu):
    """【缺陷检测】连续三次错误密钥后应锁定，NRC 0x36。

    放在最后：它会把 ECU 置为 locked_out，影响后续用例。
    """
    last = b""
    for _ in range(3):
        client([0x27, 0x01])
        last = client([0x27, 0x02, 0x01, 0x02, 0x03, 0x04])
    assert last == b"\x7f\x27\x36", f"unexpected: {last.hex()}"
