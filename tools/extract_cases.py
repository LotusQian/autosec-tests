"""从用例集 Markdown 里提取用例编号，生成 cases/registry.json。

用法：
    python tools/extract_cases.py "C:\\Users\\ASUS\\Desktop\\工作\\汽车网络安全面试"

输出：cases/registry.json
    {
      "source": "...",
      "count": 72,
      "cases": [{"id": "UDS-0x27-SEED-003", "section": "10.3 ...", "file": "008 ...", "status": "covered", "covered_by": [...], "note": ""}]
    }

status 取值：
    covered —— 有直接对应的自动化用例
    partial —— 只覆盖了该用例的一部分检查点
    todo    —— 尚未自动化（矩阵里会以 xfail 形式显式列出，不允许悄悄消失）
"""
import json
import re
import sys
from pathlib import Path

CASE_RE = re.compile(r"用例编号\*\*[：:]\s*`([^`]+)`")
HEAD_RE = re.compile(r"^#{2,4}\s+(.+?)\s*$")

# 人工维护的覆盖映射：用例编号 -> [(测试文件, 测试函数, 备注)]
COVERAGE = {
    "UDS-0x10-SESSION-001": [
        ("tests/test_uds_security.py", "test_session_control_positive", "只覆盖正向切换"),
    ],
    "UDS-ENUM-002": [
        ("tests/test_uds_security.py", "test_unknown_service_nrc11", "只覆盖未知 SID 回 0x11"),
    ],
    "UDS-0x27-SEED-003": [
        ("tests/test_uds_security.py", "test_seed_must_change_between_requests", "种子随机性"),
    ],
    "UDS-0x27-BRUTE-005": [
        ("tests/test_uds_security.py", "test_lockout_after_three_wrong_keys", "失败锁定"),
        ("tests/test_uds_security.py", "test_wrong_key_nrc35", "错误密钥 NRC"),
    ],
    "UDS-0x22-DID-007": [
        ("tests/test_uds_security.py", "test_read_vin_positive", "正向读取"),
        ("tests/test_uds_security.py", "test_read_unknown_did_nrc31", "非法 DID"),
    ],
    "UDS-0x2E-WRITE-008": [
        ("tests/test_uds_security.py", "test_write_denied_before_unlock", "未授权写入必须拒"),
        ("tests/test_uds_security.py", "test_unlock_with_correct_key_then_write", "授权后写入"),
    ],
    "UDS-FLASH-011": [
        ("tests/test_flashing.py", "test_flash_happy_path", "完整刷写"),
        ("tests/test_flashing.py", "test_tampered_image_fails_signature", "镜像签名"),
        ("tests/test_flashing.py", "test_corrupted_transfer_is_caught_by_crc", "CRC"),
        ("tests/test_flashing.py", "test_download_requires_security_access", "刷写前置鉴权"),
    ],
    "DOIP-ROUTING-002": [
        ("tests/test_doip.py", "test_routing_activation_success", "激活成功"),
        ("tests/test_doip.py", "test_diagnostic_without_activation_is_rejected", "未激活即诊断"),
        ("tests/test_doip.py", "test_unknown_target_address_is_rejected", "目标地址不存在"),
    ],
    "SECOC-VERIFY-001": [
        ("tests/test_secoc.py", "test_rejects_tampered_mac", "MAC 篡改"),
        ("tests/test_secoc.py", "test_rejects_wrong_ecu_key", "密钥隔离"),
    ],
    "CAN-SECOC-008": [
        ("tests/test_secoc.py", "test_rejects_replay", "重放"),
        ("tests/test_secoc.py", "test_rejects_unsecured_frame", "降级"),
        ("tests/test_secoc.py", "test_vulnerable_implementation_is_detected", "缺陷对照"),
    ],
    "CAN-REPLAY-002": [
        ("tests/test_secoc.py", "test_rejects_replay", "重放层面（SecOC 上下文）"),
    ],
    "CAN-FUZZ-006": [
        ("tests/test_can_signals.py", "test_random_traffic_does_not_kill_ecu", "随机流量健壮性"),
        ("tests/test_can_signals.py", "test_ecu_decodes_fuzzed_frames", "字节级模糊解码"),
    ],
}

# 这些用例明确无法在当前环境自动化，写清楚原因，避免看起来像"漏了"
BLOCKED = {
    "CAN-SNIFF-001": "需要真实 CAN 适配器与目标总线",
    "CAN-INJECT-003": "需要真实总线与被控节点",
    "CAN-DOS-004": "需要真实总线时序测量",
    "CAN-BUSOFF-005": "需要触发真实 Bus-Off，虚拟总线无法复现",
    "CAN-GW-FILTER-007": "需要真实网关",
    "DOIP-DISCOVERY-001": "UDP 车辆发现未实现（可扩展）",
    "DOIP-DOS-003": "需要真实 DoIP 网关",
    "DOIP-TLS-004": "需要真实 TLS 服务端与证书链",
    "SOMEIP-SD-001": "SOME/IP 未实现",
    "SOMEIP-SUB-002": "SOME/IP 未实现",
    "SOMEIP-FUZZ-003": "SOME/IP 未实现",
    "LIN-SPOOF-001": "LIN 未实现",
    "LIN-MASTER-002": "LIN 未实现",
    "ETH-VLAN-001": "车载以太网二层未实现",
    "ETH-ARP-002": "车载以太网二层未实现",
    "ETH-SCAN-003": "车载以太网二层未实现",
    "ETH-MACSEC-004": "MACsec 未实现",
    "ETH-DOS-005": "车载以太网二层未实现",
}


def extract(root: Path):
    cases, seen = [], set()
    for md in sorted(root.glob("*.md")):
        section = ""
        for line in md.read_text(encoding="utf-8", errors="ignore").splitlines():
            head = HEAD_RE.match(line)
            if head:
                section = head.group(1).replace("\\", "")
                continue
            m = CASE_RE.search(line)
            if not m:
                continue
            cid = m.group(1).strip()
            if cid in seen:
                continue
            seen.add(cid)
            mapped = COVERAGE.get(cid, [])
            if mapped:
                status = "covered" if len(mapped) >= 2 else "partial"
            elif cid in BLOCKED:
                status = "blocked"
            else:
                status = "todo"
            cases.append({
                "id": cid,
                "section": section,
                "file": md.name,
                "status": status,
                "covered_by": [f"{f}::{t}" for f, t, _ in mapped],
                "covers": [n for _, _, n in mapped],
                "note": BLOCKED.get(cid, ""),
            })
    return cases


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / "Desktop" / "工作" / "汽车网络安全面试"
    if not root.exists():
        raise SystemExit(f"目录不存在: {root}")

    cases = extract(root)
    out_dir = Path(__file__).resolve().parent.parent / "cases"
    out_dir.mkdir(exist_ok=True)
    payload = {
        # 只记目录名，避免把本机绝对路径（含用户名）带进公开仓库
        "source": root.name,
        "count": len(cases),
        "by_status": {s: sum(1 for c in cases if c["status"] == s)
                      for s in ("covered", "partial", "blocked", "todo")},
        "cases": cases,
    }
    path = out_dir / "registry.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"{len(cases)} 条用例 -> {path}")
    for k, v in payload["by_status"].items():
        print(f"  {k:8s} {v}")


if __name__ == "__main__":
    main()
