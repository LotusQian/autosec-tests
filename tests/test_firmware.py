"""固件初筛用例：熵、特征、字符串、解包。

用合成固件做测试——真实固件太大且有版权，合成样本足以验证检测逻辑本身。
"""
import gzip
import lzma
import os
import random

import pytest

import firmware

ELF_HEAD = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
UIMAGE_HEAD = b"\x27\x05\x19\x56" + b"\x00" * 12
SQUASHFS = b"hsqs" + b"\x00" * 12


def synthetic_firmware():
    rnd = random.Random(20261031)
    payload = b"SECRET_FLAG_1234 " * 8
    blob = bytearray()
    blob += b"\x00" * 64                            # 头部
    blob += UIMAGE_HEAD                             # +0x40
    blob += bytes(rnd.getrandbits(8) for _ in range(600))   # 填充
    gz_off = len(blob)
    blob += gzip.compress(payload)                  # 压缩载荷
    blob += b"\x00" * 32
    elf_off = len(blob)
    blob += ELF_HEAD
    blob += b"\x11" * 128
    blob += SQUASHFS
    blob += b"PLAINTEXT_MARKER_XYZ\x00"             # 明文标记（不在压缩体里）
    blob += b"https://fota.example.com/update"      # 可疑 URL
    blob += b"\x00" * 16
    blob += bytes(rnd.getrandbits(8) for _ in range(4096))  # 高熵区
    return bytes(blob), gz_off, elf_off, payload


# ---------------- 基础度量 ----------------
def test_entropy_random_is_high_and_zeros_is_low():
    rnd = random.Random(7)
    high = bytes(rnd.getrandbits(8) for _ in range(4096))
    assert firmware.shannon_entropy(high) > 7.8
    assert firmware.shannon_entropy(b"\x00" * 4096) < 1.0


def test_entropy_handles_empty():
    assert firmware.shannon_entropy(b"") == 0.0


# ---------------- 特征识别 ----------------
def test_finds_signatures_at_correct_offsets():
    blob, gz_off, elf_off, _ = synthetic_firmware()
    hits = firmware.find_signatures(blob)
    found = {(h["name"], h["offset"]) for h in hits}

    assert ("gzip", gz_off) in found
    assert ("elf", elf_off) in found
    assert ("uimage", 64) in found
    assert any(h["name"] == "squashfs" for h in hits)
    # 结果必须按偏移排序，方便人读
    assert [h["offset"] for h in hits] == sorted(h["offset"] for h in hits)


def test_detects_high_entropy_tail():
    blob, _, _, _ = synthetic_firmware()
    regions = firmware.entropy_profile(blob)
    assert regions, "尾部 4KB 随机数据应被识别为高熵区"
    assert any(r["offset"] > len(blob) - 8192 for r in regions)


# ---------------- 字符串 ----------------
def test_extracts_ascii_strings():
    blob, _, _, _ = synthetic_firmware()
    strings = firmware.extract_strings(blob)
    assert any("PLAINTEXT_MARKER_XYZ" in s for s in strings)
    assert any("fota.example.com" in s for s in strings)


def test_flags_interesting_strings():
    strings = [
        "AKIAABCDEFGHIJKLMNOP",
        "-----BEGIN RSA PRIVATE KEY-----",
        "https://fota.example.com/update",
        "harmless text here",
        "root:toor",
    ]
    flagged = firmware.interesting_strings(strings)
    reasons = {f["reason"] for f in flagged}
    assert {"aws-access-key", "private-key", "url", "debug-or-credential"} <= reasons
    assert all("harmless" not in f["value"] for f in flagged)


# ---------------- 解包 ----------------
def test_carve_extracts_gzip_member(tmp_path):
    blob, gz_off, _, payload = synthetic_firmware()
    written = firmware.carve(blob, tmp_path)

    assert written, "应至少解出一个成员"
    name = os.path.basename(written[0])
    assert name.startswith(f"{gz_off:08x}_gzip")
    assert (tmp_path / name).read_bytes() == payload


def test_carve_survives_corrupt_member(tmp_path):
    """坏掉的 gzip 不能让整个分析崩掉。"""
    blob = b"\x1f\x8b\x08" + b"\xff" * 40
    assert firmware.carve(blob, tmp_path) == []


# ---------------- 汇总报告 ----------------
def test_scan_report_shape():
    blob, _, _, _ = synthetic_firmware()
    report = firmware.scan(blob)

    assert report["size"] == len(blob)
    assert 0 <= report["entropy"] <= 8
    assert report["signatures"]
    assert report["strings"]["count"] > 0
    assert isinstance(report["interesting"], list)
    assert isinstance(report["high_entropy_regions"], list)


def test_scan_on_xz_member(tmp_path):
    """换一种压缩格式也要认得出、解得开。"""
    payload = b"xz-payload-" * 20
    blob = b"\x00" * 32 + lzma.compress(payload)
    report = firmware.scan(blob)
    assert any(s["name"] == "xz" for s in report["signatures"])

    written = firmware.carve(blob, tmp_path)
    assert any(p.endswith("_xz.bin") for p in written)
