"""刷写客户端：把 ISO 14229 的 0x34 / 0x36 / 0x37 / 0x31 / 0x11 串成一条完整流程。

流程（也是真实项目的标准顺序）：

    安全访问 0x27  →  RequestDownload 0x34  →  若干 TransferData 0x36
                   →  RequestTransferExit 0x37  →  校验 CRC 0x31 FF01
                   →  验签 0x31 FF02  →  ECUReset 0x11

设计上刻意保留两个"客户端也能发现问题"的环节：
  * 传输过程中被篡改 → CRC 对不上 → 拒绝
  * 镜像被替换     → 签名对不上 → 拒绝

只做 CRC 不做签名，等于只防丢包不防篡改；只做签名不做 CRC，
则每次校验失败都要跑完整套验签，成本和日志都不友好。两个一起才是正常工程做法。
"""
import zlib
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from uds_core import UdsCore

DEFAULT_BLOCK_SIZE = 256


class FlashError(RuntimeError):
    def __init__(self, step: str, detail: str, response: bytes = b""):
        super().__init__(f"[{step}] {detail}" + (f" (resp={response.hex()})" if response else ""))
        self.step = step
        self.detail = detail
        self.response = response


@dataclass
class FlashReport:
    image_size: int = 0
    blocks: int = 0
    crc: Optional[int] = None
    verified: bool = False
    steps: List[tuple] = field(default_factory=list)


def _check(step: str, resp: bytes, expect: bytes) -> bytes:
    if not resp:
        raise FlashError(step, "empty response")
    if resp[0] == 0x7F:
        raise FlashError(step, f"NRC 0x{resp[2]:02X}", resp)
    if not resp.startswith(expect):
        raise FlashError(step, f"unexpected positive response", resp)
    return resp


def unlock(request: Callable[[bytes], bytes]) -> None:
    """0x27 安全访问。算法与仿真 ECU 一致（真实项目走 HSM / 产线密钥）。"""
    seed_resp = _check("SecurityAccess.seed", request(b"\x27\x01"), b"\x67\x01")
    seed = seed_resp[2:6]
    key = UdsCore.key_for(seed)
    _check("SecurityAccess.key", request(b"\x27\x02" + key), b"\x67\x02")


def flash(request: Callable[[bytes], bytes], image: bytes,
          address: int = 0x08000000,
          signer: Optional[Callable[[bytes], bytes]] = None,
          block_size: int = DEFAULT_BLOCK_SIZE,
          unlock_first: bool = True) -> FlashReport:
    """执行一次完整刷写。request(payload) -> response。"""
    image = bytes(image)
    report = FlashReport(image_size=len(image))

    def call(step, payload, expect):
        resp = request(payload)
        report.steps.append((step, payload, resp))
        return _check(step, resp, expect)

    if unlock_first:
        unlock(request)

    # 0x34 RequestDownload: dataFormat=0x00, ALFID=0x44 (4 字节地址 + 4 字节长度)
    payload = b"\x34\x00\x44" + address.to_bytes(4, "big") + len(image).to_bytes(4, "big")
    resp = call("RequestDownload", payload, b"\x74")
    # 解析 ECU 声明的 maxNumberOfBlockLength（高半字节是字节数）
    lfi = resp[1] if len(resp) > 1 else 0x20
    n = lfi >> 4
    if n and len(resp) >= 2 + n:
        block_size = min(block_size, int.from_bytes(resp[2:2 + n], "big") - 2)

    # 0x36 TransferData: 序号从 1 开始，到 0xFF 回绕到 0x00
    seq = 1
    for offset in range(0, len(image), block_size):
        chunk = image[offset:offset + block_size]
        resp = call(f"TransferData#{report.blocks + 1}",
                    bytes([0x36, seq & 0xFF]) + chunk, b"\x76")
        if resp[1] != (seq & 0xFF):
            raise FlashError("TransferData", "block counter echo mismatch", resp)
        report.blocks += 1
        seq = (seq + 1) & 0xFF

    call("RequestTransferExit", b"\x37", b"\x77")

    # 0x31 FF01 校验 CRC
    resp = call("CheckCRC", b"\x31\x01\xFF\x01", b"\x71\x01\xFF\x01")
    ecu_crc = int.from_bytes(resp[4:8], "big")
    local_crc = zlib.crc32(image) & 0xFFFFFFFF
    if ecu_crc != local_crc:
        raise FlashError("CheckCRC", f"CRC mismatch: ecu={ecu_crc:08X} local={local_crc:08X}", resp)
    report.crc = ecu_crc

    # 0x31 FF02 验签
    if signer is not None:
        sig = signer(image)
        payload = b"\x31\x01\xFF\x02" + bytes([len(sig)]) + sig
        resp = call("VerifySignature", payload, b"\x71\x01\xFF\x02")
        if len(resp) > 4 and resp[4] != 0:
            raise FlashError("VerifySignature", "signature rejected", resp)
        report.verified = True

    return report


def reset_ecu(request: Callable[[bytes], bytes], reset_type: int = 0x01) -> bytes:
    return _check("ECUReset", request(bytes([0x11, reset_type])), b"\x51")
