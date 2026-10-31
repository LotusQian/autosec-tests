import os
import time
from datetime import datetime
from pathlib import Path

import cantools
import pytest

import evidence
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

    def request(payload, timeout=2.0, note=""):
        tp.send(bytes(payload), send_timeout=1)
        resp = tp.recv(block=True, timeout=timeout)
        out = bytes(resp) if resp else b""
        evidence.record(bytes(payload), out, transport="can-iso-tp", note=note)
        return out

    request.tp = tp
    request.bus = bus
    yield request
    iso_tp_bus.close_transport(tp)
    bus.shutdown()


@pytest.fixture(scope="session")
def dbc():
    return cantools.database.load_file(str(Path(__file__).parent / "demo.dbc"))


# ---------------- 证据链挂钩 ----------------
def pytest_addoption(parser):
    parser.addoption("--no-evidence", action="store_true", default=False,
                     help="不生成证据包（默认生成到 evidence/<时间戳>/）")
    parser.addoption("--evidence-dir", action="store", default=None,
                     help="指定证据包输出目录")


def pytest_sessionstart(session):
    if session.config.getoption("--no-evidence"):
        return
    out = session.config.getoption("--evidence-dir")
    if not out:
        out = os.path.join("evidence", datetime.now().strftime("%Y%m%d-%H%M%S"))
    evidence.init(out)


def pytest_runtest_setup(item):
    evidence.begin(item.nodeid.split("::")[-1])


def pytest_sessionfinish(session, exitstatus):
    paths = evidence.finish(exitstatus)
    if paths:
        print(f"\n[evidence] {paths['count']} 条交互记录 -> {paths['md']}")
