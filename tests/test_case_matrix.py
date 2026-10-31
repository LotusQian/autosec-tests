"""用例覆盖矩阵：把桌面那 73 条用例集变成可执行、可追踪的 pytest 矩阵。

设计意图：
  * 每条文档用例在矩阵里都有且只有一个位置，不允许"悄悄消失"
  * 已实现的必须指向真实存在的测试函数（防止改名后矩阵撒谎）
  * 未实现的显式标 xfail 并写原因（TODO 要可见，不能假装覆盖了）
  * 环境不具备的（需要真实总线/网关）标 blocked，与"还没写"区分开

registry.json 由 tools/extract_cases.py 从 Markdown 生成，不要手改。
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "cases" / "registry.json"
ALLOWED = {"covered", "partial", "blocked", "todo"}


@pytest.fixture(scope="module")
def registry():
    assert REGISTRY.exists(), "cases/registry.json 缺失，先跑 tools/extract_cases.py"
    return json.loads(REGISTRY.read_text(encoding="utf-8"))


def _has_test(rel_path: str, func: str) -> bool:
    """在测试文件里找 `def func(`，不 import，避免副作用。"""
    p = ROOT / rel_path
    if not p.exists():
        return False
    return re.search(rf"^def {re.escape(func)}\(", p.read_text(encoding="utf-8"), re.M) is not None


# ---------------- 注册表自检 ----------------
def test_registry_is_wellformed(registry):
    cases = registry["cases"]
    assert registry["count"] == len(cases)
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "用例编号重复"
    assert all(c["status"] in ALLOWED for c in cases)
    assert all(c["id"] and c["section"] for c in cases), "用例缺少编号或章节"


def test_covered_cases_point_to_existing_tests(registry):
    """覆盖声明必须指向真函数 —— 否则矩阵就是在撒谎。"""
    missing = []
    for c in registry["cases"]:
        for node in c["covered_by"]:
            rel, func = node.split("::")
            if not _has_test(rel, func):
                missing.append(f"{c['id']} -> {node}")
    assert not missing, "以下覆盖声明指向不存在的测试：\n" + "\n".join(missing)


def test_blocked_cases_have_reason(registry):
    for c in registry["cases"]:
        if c["status"] == "blocked":
            assert c["note"], f"{c['id']} 标了 blocked 但没写原因"


def test_coverage_floor(registry):
    """覆盖率下限：防止以后重构把已覆盖的用例悄悄弄丢。"""
    done = sum(1 for c in registry["cases"] if c["status"] in ("covered", "partial"))
    assert done >= 12, f"自动化覆盖跌到 {done} 条，低于下限 12"


# ---------------- 逐条矩阵（跑起来就是一份覆盖报告） ----------------
def _cases():
    if not REGISTRY.exists():
        return [pytest.param(None, id="registry-missing")]
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return [pytest.param(c, id=c["id"]) for c in data["cases"]]


@pytest.mark.parametrize("case", _cases())
def test_case_matrix(case):
    if case is None:
        pytest.skip("registry 不存在")
    status = case["status"]
    if status in ("covered", "partial"):
        assert case["covered_by"], f"{case['id']} 标了 {status} 却没有映射"
        return
    if status == "blocked":
        pytest.xfail(f"环境不具备：{case['note']}")
    pytest.xfail("尚未自动化")
