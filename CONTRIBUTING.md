# 贡献与维护指南

这个仓库是一个**可执行的测评靶场**，不是产品代码。维护它的原则只有一条：
**每条断言都要能被别人在干净机器上复现。**

## 本地跑起来

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONUTF8 = '1'
pytest -q
```

期望：`85 passed, 61 xfailed`。

61 个 xfail 全部来自 `tests/test_case_matrix.py`——那是 `cases/registry.json` 里
尚未自动化或环境不具备的用例，**故意可见**。不要为了"全绿"把它们删掉或改成 skip。

## 加一条用例：五步

1. **选文件**：能复用 `UdsCore` 的放 `tests/test_uds_security.py`；CAN 信号放 `tests/test_can_signals.py`；
   DoIP 放 `tests/test_doip.py`；SecOC 放 `tests/test_secoc.py`；刷写放 `tests/test_flashing.py`。
2. **写断言**，函数名用 `test_<动词>_<对象>_<期望>`，docstring 写清"这条在真实 ECU 上对应什么缺陷"。
3. **单跑**：`pytest tests/test_xxx.py::test_yyy -v`
4. **全量**：`pytest -q`，确认没有打破已有的 85 条。
5. **更新覆盖矩阵**（如果这条用例覆盖了文档里的某条）：
   编辑 `tools/extract_cases.py` 里的 `COVERAGE`，然后重新生成：

   ```powershell
   python tools/extract_cases.py "C:\Users\ASUS\Desktop\工作\汽车网络安全面试"
   ```

   如果忘了这步，矩阵会在 `test_covered_cases_point_to_existing_tests` 上报错——这是故意的。

## 提交规范

```
feat(scope): 一句话说清加了什么能力
fix(scope): 一句话说清修了什么
docs: 文档
chore: 杂项（依赖、换行、构建）
```

`scope` 用模块名：`secoc` / `flash` / `doip` / `matrix` / `firmware` / `evidence` / `ci`。

示例：

- `feat(secoc): support 32-bit truncated MAC`
- `fix(flashing): reject transfer when block counter wraps at 0xFF`

## 提 PR / 直接推

单人维护时**直接推 main** 是合理的——CI 会拦下红的重构。
只有一种情况建议开分支：改动超过 3 个文件，或者要试错。

```powershell
git switch -c feat/32bit-mac
# ... 改 ...
git push -u origin feat/32bit-mac
gh pr create --fill
gh pr merge --squash
```

## 必须本地先跑的三件事

1. `pytest -q` —— 85 passed, 61 xfailed
2. `pytest -q --no-evidence` —— 确认证据链开关没坏
3. `git status` —— 没有意外的 `evidence/`、`*.pcap`、`__pycache__`

## 绝对不能提交

| 内容 | 原因 |
|---|---|
| 真实车辆的 DBC / ODX / ARXML | 客户资产，泄露即事故 |
| 任何密钥、种子、证书私钥 | 一眼看出是外行 |
| `evidence/` 下的抓包与日志 | 含现场数据，也可能含 PII |
| 客户报告、缺陷单截图 | 同上 |
| 公司内网地址、工号、车牌 | 同上 |

`.gitignore` 已经挡掉了 `evidence/` 和常见抓包格式，但**二进制文件不会被内容扫描**，
提交前自己看一眼 `git status`。

## 出问题了怎么办

- **CI 红了**：`gh run view --log-failed` 看失败步骤，别凭猜。
- **本地绿 CI 红**：多半是 `requirements.txt` 少写了依赖，或测试之间有状态泄漏。
- **改坏了想回退**：`git revert <sha>`（已推送）或 `git reset --hard <sha>`（未推送）。
- **永远不要 `git push --force` 到 main**。

## 许可

暂未指定。如果对外复用，建议加 MIT 或 Apache-2.0——在此之前请勿直接商用。
