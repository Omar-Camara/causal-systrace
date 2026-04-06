#!/usr/bin/env python3
"""
Load CSV produced by syscall_trace_loader (-o FILE) and print summary stats.

Example:
  python src/analysis.py trace.csv
  python src/analysis.py /tmp/trace.csv --head 5
"""

from __future__ import annotations

import argparse
import sys


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
    args = parser.parse_args()

    try:
        import pandas as pd
    except ImportError:
        print(
            "pandas is required: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 1

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
        print(f"  {int(sid)}: {int(cnt)}")

    if args.head > 0:
        print(f"\nfirst {args.head} rows:")
        print(df.head(args.head).to_string(index=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
