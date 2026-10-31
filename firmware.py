"""固件初步分析：熵扫描 + 特征识别 + 字符串提取 + 按类型解包。

为什么不用现成工具：binwalk 在 Windows 上要 WSL，CI 里跑不了；而这个模块是纯标准库，
Windows / Linux / GitHub Actions 都能跑，适合做「固件初筛」这一层。

它不替代 binwalk，替代的是「打开固件第一分钟想知道的四件事」：
    1. 有多大、整体熵多高（是否整体加密）
    2. 里面有哪些已知格式（gzip / squashfs / ELF / U-Boot / Android boot …）
    3. 有哪些高熵区（压缩或加密的载荷）
    4. 有没有可疑明文字符串（密钥、URL、调试口）

命令行：
    python firmware.py scan  update.bin
    python firmware.py carve update.bin out/
"""
from __future__ import annotations

import gzip
import lzma
import math
import re
import sys
import zlib
from pathlib import Path
from typing import Dict, List

# (名称, 魔数, 类别)
SIGNATURES = [
    ("gzip", b"\x1f\x8b\x08", "compress"),
    ("xz", b"\xfd7zXZ\x00", "compress"),
    ("bzip2", b"BZh", "compress"),
    ("lz4", b"\x04\x22\x4d\x18", "compress"),
    ("zstd", b"\x28\xb5\x2f\xfd", "compress"),
    ("lzma", b"\x5d\x00\x00", "compress"),
    ("zip", b"PK\x03\x04", "archive"),
    ("squashfs", b"hsqs", "fs"),
    ("squashfs-be", b"sqsh", "fs"),
    ("cramfs", b"\x45\x3d\xcd\x28", "fs"),
    ("jffs2", b"\x85\x19\x03\x20", "fs"),
    ("ubi", b"UBI#", "fs"),
    ("elf", b"\x7fELF", "exec"),
    ("uimage", b"\x27\x05\x19\x56", "boot"),
    ("android-boot", b"ANDROID!", "boot"),
    ("android-sparse", b"\x3a\xff\x26\xed", "boot"),
    ("dtb", b"\xd0\x0d\xfe\xed", "boot"),
    ("pem", b"-----BEGIN", "key"),
    ("uefi-fv", b"_FVH", "firmware"),
]

ENTROPY_WINDOW = 1024
HIGH_ENTROPY = 7.5
MIN_STR_LEN = 6


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def find_signatures(data: bytes) -> List[Dict]:
    hits = []
    for name, magic, kind in SIGNATURES:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            hits.append({"offset": idx, "name": name, "kind": kind})
            start = idx + 1
    hits.sort(key=lambda h: h["offset"])
    return hits


def entropy_profile(data: bytes, window: int = ENTROPY_WINDOW) -> List[Dict]:
    """按窗口算熵，只返回超过阈值的区间（压缩/加密载荷通常 7.9+）。"""
    out = []
    for off in range(0, len(data), window):
        chunk = data[off:off + window]
        if len(chunk) < window // 2:
            break
        ent = shannon_entropy(chunk)
        if ent >= HIGH_ENTROPY:
            out.append({"offset": off, "length": len(chunk), "entropy": round(ent, 2)})
    return out


def extract_strings(data: bytes, min_len: int = MIN_STR_LEN, limit: int = 200) -> List[str]:
    pattern = rb"[\x20-\x7e]{%d,}" % min_len
    found = [m.decode("ascii", "ignore") for m in re.findall(pattern, data)]
    return found[:limit]


_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def interesting_strings(strings: List[str]) -> List[Dict]:
    """从字符串里挑出安全相关的：密钥、私钥、URL、调试口。"""
    out = []
    for s in strings:
        reason = None
        if _AWS_KEY.search(s):
            reason = "aws-access-key"
        elif _PRIVATE_KEY.search(s):
            reason = "private-key"
        elif re.search(r"https?://", s):
            reason = "url"
        elif re.search(r"(debug|uart|console)=|root:|admin:", s, re.I):
            reason = "debug-or-credential"
        if reason:
            out.append({"value": s[:120], "reason": reason})
    return out


def scan(data: bytes) -> Dict:
    strings = extract_strings(data)
    return {
        "size": len(data),
        "entropy": round(shannon_entropy(data), 2),
        "signatures": find_signatures(data),
        "high_entropy_regions": entropy_profile(data),
        "strings": {"count": len(strings), "samples": strings[:20]},
        "interesting": interesting_strings(strings),
    }


def carve(data: bytes, out_dir: Path) -> List[str]:
    """把能直接解压的成员解出来（gzip / xz），返回产物路径。

    用 decompressobj 而不是 gzip.decompress：固件里压缩成员后面通常还跟着别的数据，
    一次性解压会因为"尾部有多余字节"而失败。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    for hit in find_signatures(data):
        blob = data[hit["offset"]:]
        try:
            if hit["name"] == "gzip":
                payload = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob)
            elif hit["name"] == "xz":
                payload = lzma.LZMADecompressor().decompress(blob)
            else:
                continue
        except Exception:
            continue
        if not payload:
            continue
        path = out_dir / f"{hit['offset']:08x}_{hit['name']}.bin"
        path.write_bytes(payload)
        written.append(str(path))
    return written


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)

    cmd, path = sys.argv[1], Path(sys.argv[2])
    data = path.read_bytes()

    if cmd == "scan":
        report = scan(data)
        print(f"file      : {path.name}")
        print(f"size      : {report['size']} bytes")
        print(f"entropy   : {report['entropy']}")
        print(f"signatures: {len(report['signatures'])}")
        for s in report["signatures"][:20]:
            print(f"  +0x{s['offset']:08x}  {s['name']:14s} ({s['kind']})")
        print(f"high-entropy regions: {len(report['high_entropy_regions'])}")
        for r in report["high_entropy_regions"][:10]:
            print(f"  +0x{r['offset']:08x}  {r['length']} bytes  H={r['entropy']}")
        print(f"strings   : {report['strings']['count']}")
        for i in report["interesting"][:10]:
            print(f"  ! {i['reason']:22s} {i['value']}")
    elif cmd == "carve":
        out = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("carved")
        for p in carve(data, out):
            print(p)
    else:
        print(f"unknown command: {cmd}")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
