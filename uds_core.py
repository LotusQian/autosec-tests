"""UDS 服务端核心逻辑 —— 与传输层无关。

CAN（ISO-TP）和 DoIP（TCP）都复用这一个 UdsCore，
这样同一个"ECU 大脑"可以被不同总线/协议驱动，测试用例也能复用。

安全访问算法故意做成弱实现（key = seed ^ 0xA5A5A5A5），
用来练"流程缺陷"（种子重放、无锁定、未鉴权写入），不是练算法破解。
"""
import os


class UdsCore:
    VIN = b"LSVAA4185E2123456"          # 17 字节
    SECRET_MASK = 0xA5A5A5A5
    MAX_FAILED = 3

    def __init__(self):
        self.reset()

    def reset(self):
        self.seed = None
        self.unlocked = False
        self.failed_attempts = 0
        self.locked_out = False
        self.written_dids = {}
        self.request_count = 0

    # ---------- 协议 ----------
    def handle(self, req: bytes) -> bytes:
        req = bytes(req)
        if not req:
            return b""
        self.request_count += 1
        sid = req[0]

        if sid == 0x3E:                                  # TesterPresent
            return bytes([0x7E, req[1] if len(req) > 1 else 0x00])

        if sid == 0x10:                                  # 会话控制
            if len(req) < 2:
                return bytes([0x7F, 0x10, 0x13])
            return bytes([0x50, req[1], 0x00, 0x32, 0x01, 0xF4])

        if sid == 0x22:                                  # 读 DID
            if len(req) < 3:
                return bytes([0x7F, 0x22, 0x13])
            did = req[1:3]
            if did in self.written_dids:
                return bytes([0x62]) + did + self.written_dids[did]
            if did == b"\xF1\x90":
                return bytes([0x62]) + did + self.VIN
            if did == b"\xF1\x86":
                return bytes([0x62]) + did + b"SW-1.0.0-demo"
            return bytes([0x7F, 0x22, 0x31])             # requestOutOfRange

        if sid == 0x27:                                  # 安全访问
            if len(req) < 2:
                return bytes([0x7F, 0x27, 0x13])
            sub = req[1]
            if sub == 0x01:
                if self.locked_out:
                    return bytes([0x7F, 0x27, 0x36])
                self.seed = os.urandom(4)
                self.unlocked = False
                return bytes([0x67, 0x01]) + self.seed
            if sub == 0x02:
                if self.locked_out:
                    return bytes([0x7F, 0x27, 0x36])
                if self.seed is None:
                    return bytes([0x7F, 0x27, 0x24])
                if req[2:6] == self.key_for(self.seed):
                    self.unlocked = True
                    self.failed_attempts = 0
                    self.seed = None
                    return bytes([0x67, 0x02])
                self.failed_attempts += 1
                self.seed = None
                if self.failed_attempts >= self.MAX_FAILED:
                    self.locked_out = True
                    return bytes([0x7F, 0x27, 0x36])
                return bytes([0x7F, 0x27, 0x35])
            return bytes([0x7F, 0x27, 0x12])

        if sid == 0x2E:                                  # 写 DID
            if not self.unlocked:
                return bytes([0x7F, 0x2E, 0x33])
            did = req[1:3]
            self.written_dids[did] = req[3:]
            return bytes([0x6E]) + did

        return bytes([0x7F, sid, 0x11])                  # serviceNotSupported

    # ---------- 安全访问算法（故意做得弱） ----------
    @classmethod
    def key_for(cls, seed: bytes) -> bytes:
        v = int.from_bytes(seed, "big")
        return ((v ^ cls.SECRET_MASK) & 0xFFFFFFFF).to_bytes(4, "big")
