#!/usr/bin/env python3
"""
Build a graph between *channels* from an enriched syscall trace (time-bucket counts).

--method corr (default): lagged Pearson correlation; exploratory, not formal causality.
--method pc: constraint-based PC (causal-learn) on the bucket×channel matrix (Fisher Z).

Example:
  python src/causal.py data/enriched.csv --auto-window --dot data/graph.dot
  python src/causal.py data/enriched.csv --method pc --window-ms 25 --dot data/pc.dot
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


def lag_corr(
    pivot: "pd.DataFrame", a: str, b: str, *, min_std: float = 1e-9
) -> float:
    import pandas as pd

    x = pivot[a].shift(1)
    y = pivot[b]
    m = pd.concat([x, y], axis=1).dropna()
    if len(m) < 4:
        return float("nan")
    s0 = float(m.iloc[:, 0].std())
    s1 = float(m.iloc[:, 1].std())
    if s0 < min_std or s1 < min_std:
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


def write_pc_dot(path: Path, directed_edges: list[tuple[str, str]]) -> None:
    """Write a DAG-style DOT from oriented PC edges only (no correlation weight)."""
    lines = ["digraph G {", "  rankdir=LR;", "  node [shape=box];"]
    for u, v in directed_edges:
        lines.append(f"  {dot_label(u)} -> {dot_label(v)} [label={dot_label('pc')}];")
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_bucket_pivot(
    df: "pd.DataFrame",
    pd,
    *,
    auto_window: bool,
    min_buckets: int,
    window_ms: float,
) -> tuple["pd.DataFrame", list[str], int, float] | tuple[None, None, int, float]:
    """
    Return (pivot float64, column names, n_buckets, span_ms) or (None, None, n_bk, span_ms) on failure.
    """
    ts = df["ts_ns"].astype("uint64")
    t_min, t_max = int(ts.min()), int(ts.max())
    span_ns = max(1, t_max - t_min + 1)
    span_ms = span_ns / 1e6

    if auto_window:
        target = max(min_buckets, 2) + 2
        window_ns = max(1, span_ns // target)
        used_ms = window_ns / 1e6
        print(
            f"auto-window: span~{span_ms:.6f} ms -> bucket ~{used_ms:.6f} ms ({target} target slices)",
            file=sys.stderr,
        )
    else:
        window_ns = max(1, int(window_ms * 1_000_000))

    work = df.copy()
    work["t_bucket"] = (ts // window_ns).astype("int64")

    counts = work.groupby(["t_bucket", "channel"], observed=False).size().unstack(
        fill_value=0
    )
    n_bk = counts.shape[0]
    if n_bk < min_buckets:
        suggest_ms = max(span_ms / max(min_buckets + 1, 3), 1e-9)
        print(
            f"only {n_bk} time buckets (need >= {min_buckets}); "
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
        return None, None, n_bk, span_ms

    pivot = counts.astype("float64")
    cols = list(pivot.columns)
    return pivot, cols, n_bk, span_ms


def run_pc_method(
    pivot: "pd.DataFrame",
    cols: list[str],
    n_bk: int,
) -> tuple[list[tuple[str, str, float]], list[tuple[str, str]]] | None:
    """
    Run PC; return (edges_with dummy weight for logging, directed_edges for DOT) or None on failure.
    """
    try:
        from causallearn.search.ConstraintBased.PC import pc
    except ImportError:
        print(
            "PC method requires causal-learn. Install with:\n"
            "  pip install -r requirements-causal.txt",
            file=sys.stderr,
        )
        return None

    import numpy as np

    # Drop time-constant channels (Fisher Z unstable)
    variances = pivot.var(axis=0)
    keep = [c for c in cols if float(variances.get(c, 0.0)) > 1e-12]
    dropped = sorted(set(cols) - set(keep))
    if dropped:
        print(
            f"pc: dropped {len(dropped)} zero-variance channel(s) across buckets",
            file=sys.stderr,
        )
    if not keep:
        print("pc: no channels left after variance filter", file=sys.stderr)
        return None

    sub = pivot[keep].astype(np.float64)
    n_vars = sub.shape[1]
    if n_bk < n_vars:
        print(
            f"pc: warning — time buckets ({n_bk}) < channels ({n_vars}). "
            "PC needs roughly more samples than variables; try a larger --window-ms "
            "(fewer, wider buckets) or a longer trace.",
            file=sys.stderr,
        )

    data = np.asarray(sub.values, dtype=np.float64)
    cg = pc(
        data,
        alpha=0.05,
        indep_test="fisherz",
        node_names=keep,
        verbose=False,
        show_progress=False,
    )
    G = cg.G
    nodes = G.get_nodes()
    directed: list[tuple[str, str]] = []
    for u in nodes:
        for v in nodes:
            if u is v:
                continue
            if G.is_directed_from_to(u, v):
                directed.append((u.get_name(), v.get_name()))

    edges_weighted = [(a, b, 1.0) for a, b in directed]
    return edges_weighted, directed


def main() -> int:
    parser = argparse.ArgumentParser(description="Graph over syscall channels (corr or PC).")
    parser.add_argument("csv_arg", help="Enriched or raw loader CSV")
    parser.add_argument(
        "--method",
        choices=("corr", "pc"),
        default="corr",
        help="corr=lag correlation (default); pc=PC algorithm (causal-learn)",
    )
    parser.add_argument(
        "--window-ms",
        type=float,
        default=10.0,
        help="Time bucket size in ms (default: 10). For short traces, use --auto-window or a smaller value.",
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
        help="Min |corr| for an edge when --method corr (default: 0.35)",
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

    built = build_bucket_pivot(
        df,
        pd,
        auto_window=args.auto_window,
        min_buckets=args.min_buckets,
        window_ms=args.window_ms,
    )
    pivot, cols, n_bk, span_ms = built
    if pivot is None or cols is None:
        return 1

    if args.method == "corr":
        thr = args.threshold
        edges: list[tuple[str, str, float]] = []
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

    # PC
    pc_out = run_pc_method(pivot, cols, n_bk)
    if pc_out is None:
        return 1
    weighted, directed = pc_out
    print(f"buckets: {pivot.shape[0]}  channels: {len(cols)}  directed_edges: {len(directed)}")
    for u, v, _ in weighted[:50]:
        print(f"  {u} -> {v}  (pc)")
    if len(weighted) > 50:
        print(f"  ... ({len(weighted) - 50} more)")

    if args.dot:
        args.dot.parent.mkdir(parents=True, exist_ok=True)
        write_pc_dot(args.dot, directed)
        print(f"wrote {args.dot}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
