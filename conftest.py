import time
from pathlib import Path

import cantools
import pytest

import iso_tp_bus
from sim_ecu import SimEcu

CHANNEL = "autosec-demo"
REQ_ID = 0x7E0
RESP_ID = 0x7E8


@pytest.fixture(scope="session")
def ecu():
    """整个测试会话共用一个仿真 ECU（在线程里跑）。"""
    e = SimEcu(channel=CHANNEL).start()
    time.sleep(0.2)
    yield e
    e.stop()


@pytest.fixture
def clean_ecu(ecu):
    """每个用例前把安全访问状态复位。"""
    ecu.seed = None
    ecu.unlocked = False
    ecu.failed_attempts = 0
    ecu.locked_out = False
    yield ecu


@pytest.fixture(scope="session")
def client(ecu):
    """测试仪（Tester）侧的 ISO-TP 通道。"""
    bus = iso_tp_bus.open_bus(channel=CHANNEL)
    tp = iso_tp_bus.make_transport(bus, rxid=RESP_ID, txid=REQ_ID)

    def request(payload, timeout=2.0):
        tp.send(bytes(payload), send_timeout=1)
        resp = tp.recv(block=True, timeout=timeout)
        return bytes(resp) if resp else b""

    request.tp = tp
    request.bus = bus
    yield request
    iso_tp_bus.close_transport(tp)
    bus.shutdown()


@pytest.fixture(scope="session")
def dbc():
    return cantools.database.load_file(str(Path(__file__).parent / "demo.dbc"))
