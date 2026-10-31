"""AUTOSAR SecOC 精简实现 —— 用于测评教学，不是生产代码。

线路格式（一条 secured PDU）：

    ┌──────────────┬───────────┬──────────┐
    │ authentic PDU│ 截断 FV   │ 截断 MAC │
    └──────────────┴───────────┴──────────┘

    MAC = AES-128-CMAC(key, [pdu_id] ‖ payload ‖ full_fv)[:mac_trunc_bits]

设计要点（也是测评的四个抓手）：
  1. 新鲜度（FV）：发送端单调递增，接收端用低位重建高位，再按窗口校验 —— 防重放
  2. MAC 绑定 PDU ID：否则可以把 A 报文的 MAC 贴到 B 报文上（跨报文移植）
  3. 必须校验 MAC：收到不带 MAC 的帧要拒绝（fail-closed），不能降级接受
  4. 每 ECU 独立密钥：共用密钥等于拿下一台就能伪造全网

`SecoCConfig` 里的开关可以把实现切成「合规」或「有缺陷」，
测试用例据此证明：同一套攻击在合规实现上被拦住、在缺陷实现上被放过。
"""
from __future__ import annotations

import hmac
import struct
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

# 典型取值：AES-128-CMAC，线上截断到 24 bit，FV 线上 8 bit
DEFAULT_MAC_BITS = 24
DEFAULT_FV_BITS = 8


@dataclass
class SecoCConfig:
    """实现开关。默认全开 = 合规实现。"""

    mac_trunc_bits: int = DEFAULT_MAC_BITS
    fv_bits: int = DEFAULT_FV_BITS
    window: int = 16              # 允许的超前量（按 FV 计数）

    check_freshness: bool = True  # False -> 重放/乱序帧会被接受
    bind_pdu_id: bool = True      # False -> MAC 不绑定报文，可跨 PDU 移植
    require_mac: bool = True      # False -> 不带 SecOC 的帧被当成合法（fail-open）

    @property
    def mac_bytes(self) -> int:
        return max(1, self.mac_trunc_bits // 8)

    @property
    def fv_bytes(self) -> int:
        return max(1, self.fv_bits // 8)


def compliant_config() -> SecoCConfig:
    return SecoCConfig()


def vulnerable_config() -> SecoCConfig:
    """把三个关键校验全关掉，用来证明用例确实能抓出缺陷。"""
    return SecoCConfig(check_freshness=False, bind_pdu_id=False, require_mac=False)


def compute_mac(key: bytes, pdu_id: int, payload: bytes, fv: int,
                bind_pdu_id: bool = True) -> bytes:
    """AES-128-CMAC，输入按配置决定是否绑定 PDU ID。"""
    c = CMAC(algorithms.AES(key))
    if bind_pdu_id:
        c.update(struct.pack(">H", pdu_id))
    c.update(payload)
    c.update(struct.pack(">I", fv))
    return c.finalize()


class SecoCSender:
    def __init__(self, keys: Dict[int, bytes], cfg: Optional[SecoCConfig] = None):
        self.keys = keys
        self.cfg = cfg or compliant_config()
        self.counters: Dict[int, int] = {}

    def build(self, pdu_id: int, payload: bytes, counter: Optional[int] = None) -> bytes:
        """组一条 secured PDU。counter 留空则自动递增。"""
        if counter is None:
            self.counters[pdu_id] = self.counters.get(pdu_id, 0) + 1
            counter = self.counters[pdu_id]
        else:
            self.counters[pdu_id] = max(self.counters.get(pdu_id, 0), counter)

        key = self.keys[pdu_id]
        mac = compute_mac(key, pdu_id, payload, counter, self.cfg.bind_pdu_id)
        mac_trunc = mac[: self.cfg.mac_bytes]
        fv_trunc = (counter & ((1 << self.cfg.fv_bits) - 1)).to_bytes(self.cfg.fv_bytes, "big")
        return bytes(payload) + fv_trunc + mac_trunc


class SecoCReceiver:
    def __init__(self, keys: Dict[int, bytes], cfg: Optional[SecoCConfig] = None,
                 pdu_lengths: Optional[Dict[int, int]] = None):
        self.keys = keys
        self.cfg = cfg or compliant_config()
        self.pdu_lengths = pdu_lengths or {}
        self.last_fv: Dict[int, int] = {}

    # ---------- 内部 ----------
    def _reconstruct(self, last: int, fv_trunc: int) -> int:
        span = 1 << self.cfg.fv_bits
        base = last & ~(span - 1)
        cand = base | fv_trunc
        if cand < last - span // 2:
            cand += span
        return cand

    # ---------- 对外 ----------
    def receive(self, pdu_id: int, frame: bytes) -> Tuple[bool, bytes, str]:
        """返回 (是否接受, 还原出的 payload, 判定原因)。"""
        frame = bytes(frame)
        expected_len = self.pdu_lengths.get(pdu_id)
        min_len = self.cfg.fv_bytes + self.cfg.mac_bytes

        # 完全不带 SecOC 字段：长度正好等于裸 payload
        if expected_len is not None and len(frame) == expected_len:
            if self.cfg.require_mac:
                return False, frame, "secoc:missing"
            return True, frame, "fail-open:no-secoc"

        if len(frame) < min_len:
            return False, b"", "malformed:too-short"

        payload = frame[: len(frame) - min_len]
        fv_off = len(frame) - min_len
        fv_trunc = int.from_bytes(frame[fv_off: fv_off + self.cfg.fv_bytes], "big")
        mac = frame[fv_off + self.cfg.fv_bytes:]

        last = self.last_fv.get(pdu_id, 0)
        fv = self._reconstruct(last, fv_trunc)

        if self.cfg.check_freshness:
            if fv <= last:
                return False, payload, "freshness:replay"
            if fv - last > self.cfg.window:
                return False, payload, "freshness:too-far-ahead"

        expected = compute_mac(self.keys[pdu_id], pdu_id, payload, fv,
                               self.cfg.bind_pdu_id)[: self.cfg.mac_bytes]
        if not hmac.compare_digest(expected, mac):
            return False, payload, "mac:invalid"

        self.last_fv[pdu_id] = fv
        return True, payload, "ok"
