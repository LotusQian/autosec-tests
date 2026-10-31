"""ISO 13400-2 (DoIP) 网关仿真。

只实现诊断链路上最关键的四类报文，够跑通 UDS over IP：
    0x0005/0x0006  路由激活
    0x8001         诊断报文（UDS 载荷）
    0x8002/0x8003  诊断确认 / 否定确认
    0x0007/0x0008  存活检查

UDS 逻辑复用 uds_core.UdsCore，和 CAN 上的仿真 ECU 是同一个"大脑"。

报文头（通用头）：版本 0x02 | 取反 0xFD | 载荷类型(2) | 载荷长度(4)，大端。
"""
import socket
import struct
import threading

from uds_core import UdsCore

PT_GENERIC_NACK = 0x0000
PT_ROUTING_ACT_REQUEST = 0x0005
PT_ROUTING_ACT_RESPONSE = 0x0006
PT_ALIVE_CHECK_REQUEST = 0x0007
PT_ALIVE_CHECK_RESPONSE = 0x0008
PT_DIAG_MESSAGE = 0x8001
PT_DIAG_POS_ACK = 0x8002
PT_DIAG_NEG_ACK = 0x8003

PROTOCOL_VERSION = 0x02
INVERSE_VERSION = 0xFD

NACK_INCORRECT_PATTERN = 0x00
NACK_UNKNOWN_PAYLOAD = 0x01
NACK_ROUTING_REQUIRED = 0x02
NACK_UNKNOWN_TARGET = 0x03
NACK_INVALID_LENGTH = 0x04

ACT_SUCCESS = 0x10


def _header(payload_type: int, length: int) -> bytes:
    return struct.pack(">BBHI", PROTOCOL_VERSION, INVERSE_VERSION, payload_type, length)


class DoIpGateway(threading.Thread):
    def __init__(self, core=None, host="127.0.0.1", port=13401,
                 entity_address=0x0E80, keep_log=True):
        super().__init__(daemon=True)
        self.core = core or UdsCore()
        self.entity_address = entity_address
        self.keep_log = keep_log
        self.log = []                       # [(ptype, payload)] 便于断言
        self._stop = threading.Event()
        self._conns = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(5)
        self._sock.settimeout(0.2)

    # ---------- 生命周期 ----------
    def start(self):
        super().start()
        return self

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        for c in list(self._conns):
            try:
                c.close()
            except OSError:
                pass

    def run(self):
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(0.5)
            self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    # ---------- 单个连接 ----------
    def _serve(self, conn):
        activated = False
        try:
            while not self._stop.is_set():
                hdr = self._recv_exact(conn, 8)
                if hdr is None:
                    break
                ver, inv, ptype, length = struct.unpack(">BBHI", hdr)
                payload = self._recv_exact(conn, length) if length else b""
                if payload is None:
                    break
                if self.keep_log:
                    self.log.append((ptype, payload))
                if ver != PROTOCOL_VERSION or (ver ^ inv) != 0xFF:
                    self._send(conn, PT_GENERIC_NACK, bytes([NACK_INCORRECT_PATTERN]))
                    continue

                if ptype == PT_ROUTING_ACT_REQUEST:
                    activated = self._on_routing_activation(conn, payload)
                elif ptype == PT_DIAG_MESSAGE:
                    self._on_diagnostic(conn, payload, activated)
                elif ptype == PT_ALIVE_CHECK_REQUEST:
                    self._send(conn, PT_ALIVE_CHECK_RESPONSE, payload[:2])
                else:
                    self._send(conn, PT_GENERIC_NACK, bytes([NACK_UNKNOWN_PAYLOAD]))
        except (ConnectionError, socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _on_routing_activation(self, conn, payload) -> bool:
        if len(payload) < 7:
            self._send(conn, PT_GENERIC_NACK, bytes([NACK_INVALID_LENGTH]))
            return False
        tester_sa = payload[0:2]
        # 可选 4 字节 OEM 参数跟在 reserved 后面，这里不回显
        resp = tester_sa + struct.pack(">H", self.entity_address) + bytes([ACT_SUCCESS]) + b"\x00\x00\x00\x00"
        self._send(conn, PT_ROUTING_ACT_RESPONSE, resp)
        return True

    def _on_diagnostic(self, conn, payload, activated: bool):
        if len(payload) < 5:
            self._send(conn, PT_GENERIC_NACK, bytes([NACK_INVALID_LENGTH]))
            return
        sa, ta, uds = payload[0:2], payload[2:4], payload[4:]
        if not activated:
            self._diag_nack(conn, sa, ta, NACK_ROUTING_REQUIRED)
            return
        if struct.unpack(">H", ta)[0] != self.entity_address:
            self._diag_nack(conn, sa, ta, NACK_UNKNOWN_TARGET)
            return

        # 肯定确认：源=本网关、目标=测试仪 + 0x00 + 原报文的前 4 字节
        # 注意方向与请求相反，doipclient 会校验 SA/TA
        self._send(conn, PT_DIAG_POS_ACK,
                   struct.pack(">H", self.entity_address) + sa + b"\x00" + payload[0:4])

        uds_resp = self.core.handle(uds)
        if uds_resp:
            self._send(conn, PT_DIAG_MESSAGE,
                       struct.pack(">H", self.entity_address) + sa + uds_resp)

    def _diag_nack(self, conn, sa, ta, code: int):
        self._send(conn, PT_DIAG_NEG_ACK, sa + ta + bytes([code]))

    # ---------- 底层 ----------
    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _send(self, conn, payload_type: int, payload: bytes):
        conn.sendall(_header(payload_type, len(payload)) + payload)
