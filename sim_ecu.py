"""CAN / ISO-TP 上的仿真 ECU。协议逻辑在 uds_core.UdsCore，这里只负责收发。"""
import threading

import iso_tp_bus
from uds_core import UdsCore


class SimEcu:
    """把 UdsCore 挂到一条 CAN 总线上（默认虚拟总线，无需硬件）。

    用法：
        ecu = SimEcu().start()      # 后台线程收报文
        ...
        ecu.stop()
    """

    def __init__(self, interface="virtual", channel="autosec-demo",
                 req_id=0x7E0, resp_id=0x7E8):
        self.core = UdsCore()
        self.bus = iso_tp_bus.open_bus(interface=interface, channel=channel)
        self.tp = iso_tp_bus.make_transport(self.bus, rxid=req_id, txid=resp_id)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    # 兼容旧接口：测试里会用 SimEcu.key_for(seed)
    key_for = staticmethod(UdsCore.key_for)

    # 状态转发到 core，方便测试直接读
    @property
    def seed(self):
        return self.core.seed

    @seed.setter
    def seed(self, v):
        self.core.seed = v

    @property
    def unlocked(self):
        return self.core.unlocked

    @unlocked.setter
    def unlocked(self, v):
        self.core.unlocked = v

    @property
    def failed_attempts(self):
        return self.core.failed_attempts

    @failed_attempts.setter
    def failed_attempts(self, v):
        self.core.failed_attempts = v

    @property
    def locked_out(self):
        return self.core.locked_out

    @locked_out.setter
    def locked_out(self, v):
        self.core.locked_out = v

    # ---------- 生命周期 ----------
    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        try:
            self.tp.stop()          # 先停 isotp 内部线程，再关总线
        except Exception:
            pass
        try:
            self.bus.shutdown()
        except Exception:
            pass

    def _loop(self):
        while not self._stop.is_set():
            try:
                req = self.tp.recv(block=True, timeout=0.1)
            except Exception:
                continue
            if req is None:
                continue
            try:
                resp = self.core.handle(bytes(req))
            except Exception:
                resp = bytes([0x7F, bytes(req)[0], 0x10])
            if resp:
                try:
                    self.tp.send(resp, send_timeout=1)
                except Exception:
                    pass
