#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
from pathlib import Path

REQUIRED_SYMBOLS = [
    "call_usermodehelper_exec_work",
    "noop_llseek",
    "generic_file_splice_read",
    "configfs_read_iter",
    "configfs_bin_write_iter",
    "ashmem_ioctl",
    "compat_ashmem_ioctl",
    "ashmem_mmap",
    "ashmem_open",
    "ashmem_release",
    "ashmem_show_fdinfo",
    "anon_pipe_buf_ops",
    "ashmem_fops",
    "kmalloc_caches",
    "system_unbound_wq",
    "init_task",
    "root_task_group",
    "selinux_state",
    "ashmem_misc",
    "nfulnl_logger",
    "sysctl_bootid",
    "__event_sched_blocked_reason",
    "__start_ftrace_events",
    "worker_thread",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_btf(image: bytes, out: Path):
    prefix = b"\x9f\xeb\x01\x00"
    candidates = []
    cursor = 0
    while True:
        start = image.find(prefix, cursor)
        if start < 0:
            break
        cursor = start + 1
        if start + 24 > len(image):
            continue
        vals = struct.unpack_from("<HBBIIIII", image, start)
        magic, version, flags, header_len, type_off, type_len, str_off, str_len = vals
        if magic != 0xEB9F or version != 1 or flags != 0 or header_len < 24:
            continue
        payload_len = max(type_off + type_len, str_off + str_len)
        end = start + header_len + payload_len
        string_start = start + header_len + str_off
        if end > len(image) or string_start >= end or image[string_start] != 0:
            continue
        candidates.append((start, end))
    if len(candidates) != 1:
        return {"count": len(candidates), "candidates": candidates}
    start, end = candidates[0]
    (out / "vmlinux.btf").write_bytes(image[start:end])
    return {"count": 1, "start": start, "end": end, "size": end - start}


def parse_nm(elf: Path):
    text = subprocess.check_output(["llvm-nm", "--numeric-sort", str(elf)], text=True, errors="replace")
    symbols = {}
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]+)\s+\S\s+(.+)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        name = m.group(2).strip()
        symbols.setdefault(name, addr)
    base = None
    base_name = None
    for candidate in ("_text", "_stext", "stext"):
        if candidate in symbols:
            base = symbols[candidate]
            base_name = candidate
            break
    if base is None and symbols:
        nonzero = [v for v in symbols.values() if v]
        if nonzero:
            base = min(nonzero)
            base_name = "lowest_nonzero_symbol"
    selected = {}
    for name in REQUIRED_SYMBOLS:
        if name in symbols:
            selected[name] = {
                "address": symbols[name],
                "offset": (symbols[name] - base) if base is not None else None,
            }
    return text, base, base_name, selected, symbols


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--elf")
    ap.add_argument("--model", default="")
    ap.add_argument("--region", default="")
    ap.add_argument("--firmware", default="")
    ap.add_argument("--probe-offset", default="")
    args = ap.parse_args()

    kernel = Path(args.kernel)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = kernel.read_bytes()

    info = {
        "model": args.model,
        "region": args.region,
        "firmware": args.firmware,
        "kernel_size": len(image),
        "kernel_sha256": sha256(kernel),
    }
    if len(image) >= 0x20:
        info["arm64_text_offset"] = struct.unpack_from("<Q", image, 0x08)[0]
        info["arm64_image_size"] = struct.unpack_from("<Q", image, 0x10)[0]
        info["arm64_flags"] = struct.unpack_from("<Q", image, 0x18)[0]

    info["btf"] = extract_btf(image, out)

    selected = {}
    if args.elf and Path(args.elf).exists():
        elf = Path(args.elf)
        nm_text, base, base_name, selected, all_symbols = parse_nm(elf)
        (out / "vmlinux.nm").write_text(nm_text)
        info["elf_sha256"] = sha256(elf)
        info["symbol_base"] = base
        info["symbol_base_source"] = base_name
        info["required_symbols_found"] = len(selected)
        info["required_symbols_total"] = len(REQUIRED_SYMBOLS)
        info["symbols"] = selected

        if "__event_sched_blocked_reason" in all_symbols and "__start_ftrace_events" in all_symbols:
            delta = all_symbols["__event_sched_blocked_reason"] - all_symbols["__start_ftrace_events"]
            info["sched_blocked_reason_event_index_if_8byte_table"] = delta // 8 if delta >= 0 and delta % 8 == 0 else None

    (out / "analysis.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Galaxy Tab S11 offline port report",
        "",
        f"- Model: `{args.model}`",
        f"- Region: `{args.region}`",
        f"- Firmware: `{args.firmware}`",
        f"- Raw kernel size: `{len(image)}` bytes",
        f"- Raw kernel SHA-256: `{info['kernel_sha256']}`",
    ]
    if "arm64_text_offset" in info:
        lines += [
            f"- ARM64 Image text_offset: `0x{info['arm64_text_offset']:x}`",
            f"- ARM64 Image size: `0x{info['arm64_image_size']:x}`",
            f"- ARM64 Image flags: `0x{info['arm64_flags']:x}`",
        ]
    btf = info["btf"]
    if btf.get("count") == 1:
        lines.append(f"- BTF: `0x{btf['start']:x}..0x{btf['end']:x}` ({btf['size']} bytes)")
    else:
        lines.append(f"- BTF: expected one candidate, found `{btf.get('count')}`")

    if selected:
        lines += ["", "## Symbol offsets", "", "| Symbol | Address | Offset from recovered text base |", "|---|---:|---:|"]
        for name in REQUIRED_SYMBOLS:
            if name not in selected:
                continue
            row = selected[name]
            off = row["offset"]
            lines.append(f"| `{name}` | `0x{row['address']:x}` | `0x{off:x}` |" if off is not None else f"| `{name}` | `0x{row['address']:x}` | n/a |")

    lines += [
        "",
        "## Still requires validation",
        "",
        "This report deliberately does not copy target-specific values from another Samsung device. Physical load address, pselect overlap, trace-event numbering, special data-object offsets, and runtime exploit behavior must be derived/validated for this exact firmware before publishing a payload.",
        "",
    ]
    (out / "PORT_REPORT.md").write_text("\n".join(lines))


if __name__ == "__main__":
    main()
