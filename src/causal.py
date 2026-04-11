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


def write_pc_dot(
    path: Path,
    directed_edges: list[tuple[str, str]],
    undirected_edges: list[tuple[str, str]] | None = None,
) -> None:
    """Write DOT from PC/CPDAG: solid arrows (oriented) + dashed dir=none (ambiguous)."""
    lines = ["digraph G {", "  rankdir=LR;", "  node [shape=box];"]
    for u, v in directed_edges:
        lines.append(f"  {dot_label(u)} -> {dot_label(v)} [label={dot_label('pc')}];")
    for u, v in undirected_edges or []:
        lines.append(
            f"  {dot_label(u)} -> {dot_label(v)} "
            f"[label={dot_label('pc?')} dir=none style=dashed];"
        )
    lines.append("}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_bucket_pivot(
    df: "pd.DataFrame",
    pd,
    *,
    auto_window: bool,
    min_buckets: int,
    window_ms: float,
    auto_slices: int = 0,
) -> tuple["pd.DataFrame", list[str], int, float] | tuple[None, None, int, float]:
    """
    Return (pivot float64, column names, n_buckets, span_ms) or (None, None, n_bk, span_ms) on failure.
    """
    ts = df["ts_ns"].astype("uint64")
    t_min, t_max = int(ts.min()), int(ts.max())
    span_ns = max(1, t_max - t_min + 1)
    span_ms = span_ns / 1e6

    if auto_window:
        if auto_slices > 0:
            target = max(int(auto_slices), 3)
        else:
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
) -> tuple[
    list[tuple[str, str, float]], list[tuple[str, str]], list[tuple[str, str]]
] | None:
    """
    Run PC; return (weighted edges for logging, directed_edges, undirected_edges for CPDAG) or None.
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
    # Fisher-Z needs a well-conditioned correlation matrix: need n_samples > n_vars
    # and bucketed counts are often rank-deficient — cap variables and add tiny jitter.
    max_vars = max(2, min(n_vars, n_bk - 2))
    if n_vars > max_vars:
        totals = sub.sum(axis=0).sort_values(ascending=False)
        slim = list(totals.index[:max_vars])
        dropped2 = sorted(set(keep) - set(slim))
        print(
            f"pc: using top {max_vars} channel(s) by bucket totals (dropped {len(dropped2)} "
            f"so samples={n_bk} > variables; collect longer traces or widen buckets for full set)",
            file=sys.stderr,
        )
        keep = slim
        sub = pivot[keep].astype(np.float64)
        n_vars = sub.shape[1]

    if n_bk <= n_vars:
        print(
            f"pc: need more time buckets than channels (buckets={n_bk}, channels={n_vars}); "
            "try --window-ms smaller / longer trace / CAUSAL_SYSTRACE_N higher in build_real_artifacts.py",
            file=sys.stderr,
        )
        return None

    rng = np.random.default_rng(42)
    data = np.asarray(sub.values, dtype=np.float64)
    data = data + rng.normal(0.0, 1e-4, size=data.shape)

    try:
        cg = pc(
            data,
            alpha=0.05,
            indep_test="fisherz",
            node_names=keep,
            verbose=False,
            show_progress=False,
        )
    except ValueError as e:
        if "singular" in str(e).lower() or "fisherz" in str(e).lower():
            print(
                "pc: Fisher-Z failed (singular / ill-conditioned correlation on bucket counts). "
                "Try more events (-n), more buckets (smaller --window-ms), or --method corr.",
                file=sys.stderr,
            )
        else:
            print(f"pc: {e}", file=sys.stderr)
        return None
    G = cg.G
    nodes = G.get_nodes()
    directed: list[tuple[str, str]] = []
    undirected: list[tuple[str, str]] = []
    for i, u in enumerate(nodes):
        for v in nodes[i + 1 :]:
            if not G.is_adjacent_to(u, v):
                continue
            un, vn = u.get_name(), v.get_name()
            if G.is_directed_from_to(u, v):
                directed.append((un, vn))
            elif G.is_directed_from_to(v, u):
                directed.append((vn, un))
            elif G.is_undirected_from_to(u, v):
                undirected.append((un, vn))
            else:
                # partially oriented / other CPDAG marks — still show adjacency
                undirected.append((un, vn))

    edges_weighted = [(a, b, 1.0) for a, b in directed] + [
        (a, b, 0.0) for a, b in undirected
    ]
    print(
        f"pc: graph has {len(directed)} directed edge(s), {len(undirected)} undirected (CPDAG)",
        file=sys.stderr,
    )
    return edges_weighted, directed, undirected


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
        help="Pick bucket width from trace span (overrides --window-ms); width from --auto-slices or min-buckets",
    )
    parser.add_argument(
        "--auto-slices",
        type=int,
        default=0,
        metavar="N",
        help="With --auto-window, use ~N buckets across the trace span (0 = use --min-buckets+2; try 16+ for demos)",
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
        auto_slices=args.auto_slices,
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
    weighted, directed, undirected = pc_out
    n_dir, n_ud = len(directed), len(undirected)
    print(
        f"buckets: {pivot.shape[0]}  channels: {len(cols)}  "
        f"edges: {n_dir} directed + {n_ud} undirected (CPDAG)"
    )
    for u, v, w in weighted[:50]:
        tag = "pc" if w > 0.5 else "pc?"
        print(f"  {u} -> {v}  ({tag})")
    if len(weighted) > 50:
        print(f"  ... ({len(weighted) - 50} more)")

    if args.dot:
        args.dot.parent.mkdir(parents=True, exist_ok=True)
        write_pc_dot(args.dot, directed, undirected)
        print(f"wrote {args.dot}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
