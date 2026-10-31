"""刷写（UDS 0x34 / 0x36 / 0x37 / 0x31 / 0x11）测评用例。

覆盖两类问题：
  * 流程类：未解锁就下载、序号错、超长传输、没传完就退出、复位后状态残留
  * 安全类：传输被篡改（CRC 抓）、镜像被替换（签名抓）、无公钥时不该静默通过
"""
import zlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from flasher import FlashError, flash, reset_ecu, unlock
from uds_core import UdsCore

ADDR = 0x08000000


def make_ecu():
    priv = Ed25519PrivateKey.generate()
    return UdsCore(public_key=priv.public_key()), priv


def requester(core):
    return lambda payload: core.handle(payload)


def start_download(core, size, address=ADDR):
    return core.handle(b"\x34\x00\x44" + address.to_bytes(4, "big") + size.to_bytes(4, "big"))


# ---------------- 正常流程 ----------------
def test_flash_happy_path():
    core, priv = make_ecu()
    image = bytes(range(256)) * 4
    report = flash(requester(core), image, signer=priv.sign, block_size=256)

    assert report.blocks == 4
    assert report.verified is True
    assert report.crc == (zlib.crc32(image) & 0xFFFFFFFF)
    assert core.image == image
    assert core.image_verified is True


def test_block_counter_wraps_past_255():
    """块序号到 0xFF 要回绕到 0x00 —— 这里的 off-by-one 是常见实现缺陷。"""
    core, priv = make_ecu()
    image = bytes([0x11]) * 1300
    report = flash(requester(core), image, signer=priv.sign, block_size=5)
    assert report.blocks == 260
    assert core.image == image


# ---------------- 流程类缺陷 ----------------
def test_download_requires_security_access():
    core, _ = make_ecu()
    assert start_download(core, 100) == b"\x7f\x34\x33"


def test_wrong_block_sequence_is_rejected():
    core, _ = make_ecu()
    unlock(requester(core))
    start_download(core, 100)
    # 期望序号 1，这里发 2
    assert core.handle(b"\x36\x02" + b"\x00" * 10) == b"\x7f\x36\x73"


def test_oversize_transfer_is_rejected():
    core, _ = make_ecu()
    unlock(requester(core))
    start_download(core, 10)
    assert core.handle(b"\x36\x01" + b"\x00" * 11) == b"\x7f\x36\x71"


def test_exit_before_complete_is_rejected():
    core, _ = make_ecu()
    unlock(requester(core))
    start_download(core, 100)
    core.handle(b"\x36\x01" + b"\x00" * 10)
    assert core.handle(b"\x37") == b"\x7f\x37\x24"


def test_reset_clears_download_state():
    core, _ = make_ecu()
    unlock(requester(core))
    start_download(core, 100)
    assert core.handle(b"\x11\x01") == b"\x51\x01"
    assert core.handle(b"\x37") == b"\x7f\x37\x24"


def test_download_size_limit():
    core, _ = make_ecu()
    unlock(requester(core))
    assert start_download(core, UdsCore.MAX_IMAGE_BYTES + 1) == b"\x7f\x34\x31"


# ---------------- 安全类 ----------------
def test_tampered_image_fails_signature():
    """用原镜像的签名去刷被改过的镜像 —— 必须被拒。"""
    core, priv = make_ecu()
    original = b"A" * 512
    tampered = b"B" * 512

    with pytest.raises(FlashError) as ei:
        flash(requester(core), tampered, signer=lambda _img: priv.sign(original), block_size=256)

    assert ei.value.step == "VerifySignature"
    assert core.image_verified is False


def test_corrupted_transfer_is_caught_by_crc():
    """传输途中翻转 1 bit —— 签名会过（镜像本身没变？不，镜像变了），CRC 先抓住。"""
    core, priv = make_ecu()
    image = bytes([0x5A]) * 512
    base = requester(core)

    def corrupting(payload):
        if payload[0] == 0x36 and payload[1] == 2:      # 第二块里翻一个字节
            payload = payload[:2] + bytes([payload[2] ^ 0xFF]) + payload[3:]
        return base(payload)

    with pytest.raises(FlashError) as ei:
        flash(corrupting, image, signer=priv.sign, block_size=256)
    assert ei.value.step == "CheckCRC"


def test_unsigned_image_is_not_marked_verified():
    core, _ = make_ecu()
    report = flash(requester(core), b"\x00" * 64, signer=None, block_size=256)
    assert report.verified is False
    assert core.handle(b"\x31\x01\xFF\x03") == b"\x7f\x31\x72"


def test_ecu_without_public_key_rejects_signature():
    """ECU 没配公钥时不能"跳过验签"，必须明确报 conditionsNotCorrect。"""
    priv = Ed25519PrivateKey.generate()
    core = UdsCore()                                     # 无公钥
    with pytest.raises(FlashError) as ei:
        flash(requester(core), b"\x02" * 64, signer=priv.sign, block_size=256)
    assert ei.value.response[0] == 0x7F
    assert ei.value.response[2] == 0x22


def test_reset_after_flash_reports_success():
    core, priv = make_ecu()
    flash(requester(core), b"\x03" * 64, signer=priv.sign, block_size=256)
    assert reset_ecu(requester(core)) == b"\x51\x01"
