#!/usr/bin/env python3
"""
Load CSV produced by syscall_trace_loader (-o FILE) and print summary stats.

Example:
  python src/analysis.py trace.csv
  python src/analysis.py /tmp/trace.csv --head 5
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# UAPI headers: arch-specific and asm-generic (merge; later defs can override)
_UNISTD_CANDIDATES = (
    "/usr/include/asm-generic/unistd.h",
    "/usr/include/aarch64-linux-gnu/asm/unistd.h",
    "/usr/include/x86_64-linux-gnu/asm/unistd.h",
    "/usr/include/arm-linux-gnueabihf/asm/unistd.h",
)

_RE_DEFINE_NR = re.compile(
    r"^#define\s+__NR(?:3264)?_([a-zA-Z0-9_]+)\s+([0-9]+)\s*(?:/\*.*\*/\s*)?$"
)


def load_syscall_map_from_ausyscall() -> dict[int, str] | None:
    exe = Path("/usr/bin/ausyscall")
    if not exe.is_file():
        return None
    try:
        out = subprocess.run(
            [str(exe), "--dump"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0 or not out.stdout:
        return None
    m: dict[int, str] = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        try:
            nr = int(parts[0])
        except ValueError:
            continue
        m[nr] = parts[1].strip()
    return m if m else None


def load_syscall_map_from_headers() -> dict[int, str]:
    m: dict[int, str] = {}
    for path_str in _UNISTD_CANDIDATES:
        p = Path(path_str)
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            mo = _RE_DEFINE_NR.match(line)
            if not mo:
                continue
            name, num_s = mo.group(1), mo.group(2)
            try:
                nr = int(num_s)
            except ValueError:
                continue
            m[nr] = name
    return m


def load_syscall_map() -> tuple[dict[int, str], str]:
    """
    Return (number -> name, description of source for user messaging).
    """
    aus = load_syscall_map_from_ausyscall()
    if aus:
        return aus, "ausyscall --dump"
    hdr = load_syscall_map_from_headers()
    if hdr:
        return hdr, "kernel UAPI headers (__NR_*)"
    return {}, ""


def syscall_name(nr: int, m: dict[int, str]) -> str:
    return m.get(int(nr), "?")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize syscall trace CSV from syscall_trace_loader."
    )
    parser.add_argument(
        "csv",
        help="Path to CSV (header: ts_ns,pid,syscall_id,arg0..arg5)",
    )
    parser.add_argument(
        "--head",
        type=int,
        metavar="N",
        default=0,
        help="Print first N data rows after the summary",
    )
    parser.add_argument(
        "--no-syscall-names",
        action="store_true",
        help="Do not resolve syscall_id to names (faster, no /usr include needed)",
    )
    args = parser.parse_args()

    try:
        import pandas as pd
    except ImportError:
        print(
            "pandas is required: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 1

    sc_map: dict[int, str] = {}
    sc_src = ""
    if not args.no_syscall_names:
        sc_map, sc_src = load_syscall_map()
        if sc_src:
            print(f"syscall names: {sc_src}", file=sys.stderr)

    try:
        df = pd.read_csv(args.csv)
    except FileNotFoundError:
        print(f"not found: {args.csv}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"failed to read CSV: {e}", file=sys.stderr)
        return 1

    expected = [
        "ts_ns",
        "pid",
        "syscall_id",
        "arg0",
        "arg1",
        "arg2",
        "arg3",
        "arg4",
        "arg5",
    ]
    missing = [c for c in expected if c not in df.columns]
    if missing:
        print(f"unexpected columns; missing: {missing}", file=sys.stderr)
        print(f"got: {list(df.columns)}", file=sys.stderr)
        return 1

    n = len(df)
    print(f"rows: {n}")
    if n == 0:
        return 0

    ts = df["ts_ns"].astype("uint64")
    t0, t1 = int(ts.min()), int(ts.max())
    span_ns = t1 - t0
    print(f"ts_ns range: {t0} .. {t1} (span {span_ns} ns ~= {span_ns / 1e9:.6f} s)")

    pids = df["pid"].nunique()
    print(f"unique pid: {pids}")

    top = df["syscall_id"].value_counts().head(15)
    print("top syscall_id (count):")
    for sid, cnt in top.items():
        sid_i = int(sid)
        if sc_map:
            nm = syscall_name(sid_i, sc_map)
            print(f"  {sid_i} ({nm}): {int(cnt)}")
        else:
            print(f"  {sid_i}: {int(cnt)}")

    if args.head > 0:
        print(f"\nfirst {args.head} rows:")
        show = df.head(args.head).copy()
        if sc_map:
            show.insert(
                3,
                "syscall_name",
                show["syscall_id"].map(lambda x: syscall_name(int(x), sc_map)),
            )
        print(show.to_string(index=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
