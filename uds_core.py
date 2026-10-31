"""UDS 服务端核心逻辑 —— 与传输层无关。

CAN（ISO-TP）和 DoIP（TCP）都复用这一个 UdsCore，
这样同一个"ECU 大脑"可以被不同总线/协议驱动，测试用例也能复用。

安全访问算法故意做成弱实现（key = seed ^ 0xA5A5A5A5），
用来练"流程缺陷"（种子重放、无锁定、未鉴权写入），不是练算法破解。
"""
import os
import zlib


class UdsCore:
    VIN = b"LSVAA4185E2123456"          # 17 字节
    SECRET_MASK = 0xA5A5A5A5
    MAX_FAILED = 3
    MAX_IMAGE_BYTES = 256 * 1024        # 允许刷写的镜像上限

    def __init__(self, public_key=None):
        # Ed25519 公钥：用于刷写后的镜像签名校验。None 表示不支持签名校验
        self.public_key = public_key
        self.reset()

    def reset(self):
        self.seed = None
        self.unlocked = False
        self.failed_attempts = 0
        self.locked_out = False
        self.written_dids = {}
        self.request_count = 0
        self.session = 0x01

        # 刷写状态机：None -> 已 0x34 -> 若干 0x36 -> 0x37 关闭
        self.download = None
        self.image = None            # 刷写完成的镜像
        self.image_verified = False

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
            self.session = req[1]
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

        if sid == 0x34:                                  # RequestDownload
            return self._request_download(req)

        if sid == 0x36:                                  # TransferData
            return self._transfer_data(req)

        if sid == 0x37:                                  # RequestTransferExit
            return self._transfer_exit(req)

        if sid == 0x31:                                  # RoutineControl
            return self._routine_control(req)

        if sid == 0x11:                                  # ECUReset
            if len(req) < 2:
                return bytes([0x7F, 0x11, 0x13])
            self.reset()                                 # 硬复位：状态全清
            return bytes([0x51, req[1]])

        return bytes([0x7F, sid, 0x11])                  # serviceNotSupported

    # ---------- 刷写（0x34 / 0x36 / 0x37） ----------
    def _request_download(self, req):
        if not self.unlocked:
            return bytes([0x7F, 0x34, 0x33])             # securityAccessDenied
        if len(req) < 3:
            return bytes([0x7F, 0x34, 0x13])
        alfid = req[2]
        addr_len, size_len = alfid >> 4, alfid & 0x0F
        if addr_len == 0 or size_len == 0 or len(req) < 3 + addr_len + size_len:
            return bytes([0x7F, 0x34, 0x13])

        p = 3
        address = int.from_bytes(req[p:p + addr_len], "big")
        p += addr_len
        size = int.from_bytes(req[p:p + size_len], "big")

        if size == 0 or size > self.MAX_IMAGE_BYTES:
            return bytes([0x7F, 0x34, 0x31])             # requestOutOfRange

        self.download = {"address": address, "size": size,
                         "data": bytearray(), "next_seq": 1, "closed": False}
        self.image = None
        self.image_verified = False
        # lengthFormatIdentifier=0x20，maxNumberOfBlockLength=1026
        return bytes([0x74, 0x20, 0x04, 0x02])

    def _transfer_data(self, req):
        if self.download is None or self.download["closed"]:
            return bytes([0x7F, 0x36, 0x24])             # requestSequenceError
        if len(req) < 2:
            return bytes([0x7F, 0x36, 0x13])

        seq = req[1]
        expected = self.download["next_seq"] & 0xFF
        if seq != expected:
            return bytes([0x7F, 0x36, 0x73])             # wrongBlockSequenceCounter

        chunk = req[2:]
        if len(self.download["data"]) + len(chunk) > self.download["size"]:
            return bytes([0x7F, 0x36, 0x71])             # transferDataSuspended

        self.download["data"].extend(chunk)
        self.download["next_seq"] = (self.download["next_seq"] + 1) & 0xFF
        return bytes([0x76, seq])

    def _transfer_exit(self, req):
        if self.download is None or self.download["closed"]:
            return bytes([0x7F, 0x37, 0x24])             # requestSequenceError
        if len(self.download["data"]) != self.download["size"]:
            return bytes([0x7F, 0x37, 0x24])             # 还没传完就退出
        self.download["closed"] = True
        self.image = bytes(self.download["data"])
        return bytes([0x77])

    # ---------- 例程控制（0x31） ----------
    def _routine_control(self, req):
        if len(req) < 4:
            return bytes([0x7F, 0x31, 0x13])
        sub = req[1]
        rid = req[2:4]
        if sub != 0x01:
            return bytes([0x7F, 0x31, 0x12])             # subFunctionNotSupported

        if rid == b"\xFF\x01":                           # 镜像 CRC32
            if self.image is None:
                return bytes([0x7F, 0x31, 0x24])
            crc = zlib.crc32(self.image) & 0xFFFFFFFF
            return b"\x71\x01\xFF\x01" + crc.to_bytes(4, "big")

        if rid == b"\xFF\x02":                           # 镜像签名校验
            if self.image is None:
                return bytes([0x7F, 0x31, 0x24])
            if self.public_key is None:
                return bytes([0x7F, 0x31, 0x22])         # conditionsNotCorrect
            if len(req) < 5:
                return bytes([0x7F, 0x31, 0x13])
            sig_len = req[4]
            sig = req[5:5 + sig_len]
            if len(sig) != sig_len:
                return bytes([0x7F, 0x31, 0x13])
            try:
                self.public_key.verify(sig, self.image)
                self.image_verified = True
                return b"\x71\x01\xFF\x02\x00"           # 0 = 校验通过
            except Exception:
                self.image_verified = False
                return bytes([0x7F, 0x31, 0x72])         # generalProgrammingFailure

        if rid == b"\xFF\x03":                           # 查询校验状态
            if not self.image_verified:
                return bytes([0x7F, 0x31, 0x72])
            return b"\x71\x01\xFF\x03\x00"

        return bytes([0x7F, 0x31, 0x31])                 # requestOutOfRange

    # ---------- 安全访问算法（故意做得弱） ----------
    @classmethod
    def key_for(cls, seed: bytes) -> bytes:
        v = int.from_bytes(seed, "big")
        return ((v ^ cls.SECRET_MASK) & 0xFFFFFFFF).to_bytes(4, "big")
