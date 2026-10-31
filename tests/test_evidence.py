"""证据链自身的用例：记录器必须产出可解析、可读、可复现的文件。

证据包本身也是被测对象 —— 如果它写坏了，测评报告就失去依据。
"""
import json
import os

import evidence


def _sample_payload(tmp_path):
    rec = evidence.EvidenceRecorder(out_dir=str(tmp_path))
    rec.begin("test_demo_case")
    rec.record(b"\x22\xF1\x90", b"\x62\xF1\x90LSVAA4185E2123456", "can-iso-tp", "读 VIN")
    rec.record(b"\x27\x01", b"\x67\x01\x9E\x35\x03\xC7", "doip-tcp", "要种子")
    return rec


def test_dump_writes_json_and_markdown(tmp_path):
    rec = _sample_payload(tmp_path)
    paths = rec.dump(exitstatus=0)

    assert os.path.exists(paths["json"]) and os.path.exists(paths["md"])

    with open(paths["json"], encoding="utf-8") as f:
        payload = json.load(f)
    assert payload["count"] == 2
    assert payload["exitstatus"] == 0
    assert payload["records"][0]["test"] == "test_demo_case"
    assert payload["records"][0]["transport"] == "can-iso-tp"
    # 十六进制带空格、大写，方便直接贴进报告
    assert payload["records"][0]["request"] == "22 F1 90"


def test_markdown_contains_evidence_table(tmp_path):
    rec = _sample_payload(tmp_path)
    paths = rec.dump()
    with open(paths["md"], encoding="utf-8") as f:
        md = f.read()

    assert "| # | 用例 | 传输 | 请求 | 响应 | 说明 |" in md
    assert "22 F1 90" in md
    assert "test_demo_case" in md
    assert "读 VIN" in md


def test_large_payload_is_truncated(tmp_path):
    """镜像刷写会有上千字节，证据里只留头部，避免日志爆炸。"""
    rec = evidence.EvidenceRecorder(out_dir=str(tmp_path))
    rec.begin("test_big")
    rec.record(b"\x36\x01" + b"\xAA" * 4000, b"\x76\x01")
    rec.dump()
    with open(os.path.join(str(tmp_path), "session.json"), encoding="utf-8") as f:
        data = json.load(f)
    stored = data["records"][0]["request"].split()
    assert len(stored) == evidence._MAX_BYTES


def test_render_markdown_from_payload():
    payload = {
        "started": "a", "finished": "b", "exitstatus": 1, "count": 1,
        "records": [{"seq": 1, "test": "t", "transport": "can",
                     "request": "AA", "response": "BB", "note": "n"}],
    }
    md = evidence.render_markdown(payload)
    assert "| 1 | t | can | `AA` | `BB` | n |" in md
    assert "pytest 退出码：1" in md
