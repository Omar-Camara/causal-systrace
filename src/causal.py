#!/usr/bin/env python3
"""
Build a coarse lag-correlation graph between *channels* from an enriched trace.

Input: CSV with ts_ns + channel (use: python src/analysis.py RAW.csv --enrich --export-enriched data/enriched.csv).

Heuristic: for channels A,B, score = corr(A.shift(1), B) on time-bucket counts.
If |score| >= threshold, emit edge A -> B (exploratory, not a formal causal claim).

Example:
  python src/causal.py data/enriched.csv --auto-window --dot data/graph.dot
  python src/causal.py data/enriched.csv --window-ms 0.0005 --min-buckets 2 --dot data/graph.dot
  dot -Tpng data/graph.dot -o data/graph.png
"""

from __future__ import annotations

import argparse
import importlib.util
import math
import sys
from pathlib import Path


def load_analysis_module():
    path = Path(__file__).resolve().parent / "analysis.py"
    spec = importlib.util.spec_from_file_location("systrace_analysis", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def lag_corr(pivot: "pd.DataFrame", a: str, b: str) -> float:
    import pandas as pd

    x = pivot[a].shift(1)
    y = pivot[b]
    m = pd.concat([x, y], axis=1).dropna()
    if len(m) < 4:
        return float("nan")
    c = m.iloc[:, 0].corr(m.iloc[:, 1])
    if c is None or (isinstance(c, float) and math.isnan(c)):
        return float("nan")
    return float(c)


def dot_label(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_dot(path: Path, edges: list[tuple[str, str, float]]) -> None:
    lines = ["digraph G {", "  rankdir=LR;", "  node [shape=box];"]
    for u, v, w in edges:
        lines.append(
            f"  {dot_label(u)} -> {dot_label(v)} [label={dot_label(f'{w:.2f}')}];"
        )
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Lag-correlation graph over channels.")
    parser.add_argument("csv_arg", help="Enriched or raw loader CSV")
    parser.add_argument(
        "--window-ms",
        type=float,
        default=10.0,
        help="Time bucket size in ms (default: 10). For ~ms-long traces, use a much smaller value or --auto-window.",
    )
    parser.add_argument(
        "--auto-window",
        action="store_true",
        help="Pick bucket width from trace span so roughly (min-buckets+2) buckets fit (overrides --window-ms)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.35,
        help="Min |corr| for an edge (default: 0.35)",
    )
    parser.add_argument(
        "--min-buckets",
        type=int,
        default=4,
        help="Minimum time buckets required (default: 4)",
    )
    parser.add_argument(
        "--dot",
        type=Path,
        default=None,
        help="Write Graphviz DOT to this path",
    )
    parser.add_argument(
        "--auto-enrich",
        action="store_true",
        help="If CSV has no channel column, enrich using analysis.load_syscall_map (needs Linux ausyscall/headers)",
    )
    args = parser.parse_args()

    try:
        import pandas as pd
    except ImportError:
        print("pandas required: pip install -r requirements.txt", file=sys.stderr)
        return 1

    csv_path = Path(args.csv_arg)
    if not csv_path.is_file():
        print(f"not found: {csv_path}", file=sys.stderr)
        return 1

    df = pd.read_csv(csv_path)
    required_base = ["ts_ns", "pid", "syscall_id", "arg0", "arg1", "arg2", "arg3", "arg4", "arg5"]
    for c in required_base:
        if c not in df.columns:
            print(f"missing column {c}; need loader CSV", file=sys.stderr)
            return 1

    if "channel" not in df.columns:
        if not args.auto_enrich:
            print(
                "no 'channel' column; use enriched CSV or pass --auto-enrich",
                file=sys.stderr,
            )
            return 1
        mod = load_analysis_module()
        sc_map, src = mod.load_syscall_map()
        if not sc_map:
            print("could not load syscall map for enrich", file=sys.stderr)
            return 1
        print(f"auto-enrich syscall names: {src}", file=sys.stderr)
        df = mod.enrich_dataframe(df, sc_map, pd)

    ts = df["ts_ns"].astype("uint64")
    t_min, t_max = int(ts.min()), int(ts.max())
    span_ns = max(1, t_max - t_min + 1)
    span_ms = span_ns / 1e6

    if args.auto_window:
        target = max(args.min_buckets, 2) + 2
        window_ns = max(1, span_ns // target)
        used_ms = window_ns / 1e6
        print(
            f"auto-window: span~{span_ms:.6f} ms -> bucket ~{used_ms:.6f} ms ({target} target slices)",
            file=sys.stderr,
        )
    else:
        window_ns = max(1, int(args.window_ms * 1_000_000))

    df = df.copy()
    df["t_bucket"] = (ts // window_ns).astype("int64")

    counts = df.groupby(["t_bucket", "channel"], observed=False).size().unstack(
        fill_value=0
    )
    n_bk = counts.shape[0]
    if n_bk < args.min_buckets:
        suggest_ms = max(span_ms / max(args.min_buckets + 1, 3), 1e-9)
        print(
            f"only {n_bk} time buckets (need >= {args.min_buckets}); "
            f"trace span ~{span_ms:.6f} ms",
            file=sys.stderr,
        )
        print(
            f"  try: --auto-window   or   --window-ms {suggest_ms:.9f}",
            file=sys.stderr,
        )
        if n_bk >= 2:
            print(
                f"  or: --min-buckets {n_bk} (only if you accept coarse lag-corr)",
                file=sys.stderr,
            )
        return 1

    pivot = counts.astype("float64")
    cols = list(pivot.columns)
    edges: list[tuple[str, str, float]] = []
    thr = args.threshold

    for a in cols:
        for b in cols:
            if a == b:
                continue
            c = lag_corr(pivot, a, b)
            if math.isnan(c):
                continue
            if abs(c) >= thr:
                edges.append((a, b, c))

    edges.sort(key=lambda t: -abs(t[2]))
    print(f"buckets: {pivot.shape[0]}  channels: {len(cols)}  edges: {len(edges)}")
    for u, v, w in edges[:50]:
        print(f"  {u} -> {v}  corr={w:.3f}")
    if len(edges) > 50:
        print(f"  ... ({len(edges) - 50} more)")

    if args.dot:
        args.dot.parent.mkdir(parents=True, exist_ok=True)
        write_dot(args.dot, edges)
        print(f"wrote {args.dot}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
