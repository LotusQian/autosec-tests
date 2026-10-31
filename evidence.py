"""证据链：把每次 UDS 交互落成一份可交付的证据包。

测评现场最常被挑战的一句话是「你说 ECU 有问题，证据呢」。
`42 passed` 不算证据——客户要的是：哪条用例、什么时间、发了什么字节、回了什么字节。

这个模块做三件事：
  1. 记录每一组「请求 / 响应」原始字节
  2. 会话结束时自动落盘为 `session.json`（机器可读）+ `session.md`（人可读）
  3. 支持把记录贴进报告附录，或二次处理成别的格式

用法（测试里）：
    from evidence import record
    record(request_bytes, response_bytes, transport="can-iso-tp", note="0x27 解锁")

命令行（把已有 json 重新渲染成 markdown）：
    python evidence.py evidence/20261031-230000/session.json
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional

_MAX_BYTES = 96          # 单条记录最多保留的字节数，避免日志被大镜像撑爆


@dataclass
class Record:
    seq: int
    test: str
    transport: str
    request: str
    response: str
    note: str
    ts: str


@dataclass
class EvidenceRecorder:
    out_dir: str
    started: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    records: List[Record] = field(default_factory=list)
    _test: str = ""

    # ---------- 记录 ----------
    def begin(self, test_name: str) -> None:
        self._test = test_name

    def record(self, request: bytes, response: bytes, transport: str = "direct",
               note: str = "") -> Record:
        rec = Record(
            seq=len(self.records) + 1,
            test=self._test,
            transport=transport,
            request=_hex(request),
            response=_hex(response),
            note=note,
            ts=datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        )
        self.records.append(rec)
        return rec

    # ---------- 落盘 ----------
    def dump(self, exitstatus: int = 0) -> dict:
        os.makedirs(self.out_dir, exist_ok=True)
        payload = {
            "started": self.started,
            "finished": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "exitstatus": exitstatus,
            "count": len(self.records),
            "records": [asdict(r) for r in self.records],
        }
        json_path = os.path.join(self.out_dir, "session.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

        md_path = os.path.join(self.out_dir, "session.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(render_markdown(payload))

        return {"json": json_path, "md": md_path, "count": len(self.records)}


def _hex(b) -> str:
    b = bytes(b)[:_MAX_BYTES]
    return b.hex(" ").upper()


def render_markdown(payload: dict) -> str:
    lines = [
        "# 诊断交互证据包",
        "",
        f"- 开始：{payload['started']}",
        f"- 结束：{payload['finished']}",
        f"- 记录数：{payload['count']}",
        f"- pytest 退出码：{payload['exitstatus']}",
        "",
        "| # | 用例 | 传输 | 请求 | 响应 | 说明 |",
        "|---|---|---|---|---|---|",
    ]
    for r in payload["records"]:
        lines.append(
            f"| {r['seq']} | {r['test']} | {r['transport']} | `{r['request']}` | `{r['response']}` | {r['note']} |"
        )
    lines.append("")
    lines.append("> 请求/响应为原始字节（十六进制）。超过 96 字节的部分已截断。")
    return "\n".join(lines)


# ---------------- 全局单例（供测试与 conftest 使用） ----------------
_recorder: Optional[EvidenceRecorder] = None


def init(out_dir: str) -> EvidenceRecorder:
    global _recorder
    _recorder = EvidenceRecorder(out_dir=out_dir)
    return _recorder


def begin(test_name: str) -> None:
    if _recorder is not None:
        _recorder.begin(test_name)


def record(request: bytes, response: bytes, transport: str = "direct", note: str = "") -> None:
    if _recorder is not None:
        _recorder.record(request, response, transport, note)


def finish(exitstatus: int = 0) -> Optional[dict]:
    if _recorder is None:
        return None
    return _recorder.dump(exitstatus)


def active() -> bool:
    return _recorder is not None


# ---------------- CLI ----------------
def main() -> None:
    import sys

    if len(sys.argv) != 2:
        print("usage: python evidence.py <session.json>")
        raise SystemExit(2)
    with open(sys.argv[1], encoding="utf-8") as f:
        payload = json.load(f)
    print(render_markdown(payload))


if __name__ == "__main__":
    main()
