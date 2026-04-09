#!/usr/bin/env python3
"""
Run syscall_trace_loader under sudo and write a trace CSV.

Requires a built loader (make) and Linux with BPF permissions.

Example:
  python src/collector.py -p 0 -n 500 -o data/raw.csv
  python src/collector.py -p 12345 -o /tmp/t.csv --dry-run
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    default_loader = root / "build" / "syscall_trace_loader"

    p = argparse.ArgumentParser(description="Collect syscall CSV via syscall_trace_loader.")
    p.add_argument(
        "-p",
        "--pid",
        default="0",
        help="PID filter (0 = all PIDs)",
    )
    p.add_argument(
        "-n",
        "--max-events",
        default="",
        metavar="N",
        help="Stop after N events (omit for run until Ctrl+C)",
    )
    p.add_argument(
        "-o",
        "--output",
        required=True,
        help="Output CSV path (passed to loader -o)",
    )
    p.add_argument(
        "--loader",
        type=Path,
        default=default_loader,
        help=f"path to loader binary (default: {default_loader})",
    )
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Pass -v to loader (libbpf messages)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the command and exit",
    )
    args = p.parse_args()

    loader = args.loader
    if not loader.is_file():
        print(f"loader not found: {loader} (run make from repo root)", file=sys.stderr)
        return 1

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["sudo", str(loader), "-p", str(args.pid), "-o", str(out)]
    if args.max_events:
        cmd.extend(["-n", str(args.max_events)])
    if args.verbose:
        cmd.append("-v")

    if args.dry_run:
        print(" ".join(cmd))
        return 0

    env = os.environ.copy()
    try:
        proc = subprocess.run(cmd, env=env)
    except OSError as e:
        print(f"failed to run: {e}", file=sys.stderr)
        return 1
    return int(proc.returncode) if proc.returncode is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
