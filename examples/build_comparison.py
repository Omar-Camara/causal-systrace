#!/usr/bin/env python3
"""
Run PC-based causal.py on clean + malicious enriched CSVs, render PNGs, print edge diff.

Requires: examples/clean_enriched.csv and examples/malicious_enriched.csv
  (from examples/build_real_artifacts.py on Linux, or FALLBACK synthetic).

  pip install -r requirements-causal.txt   # causal-learn + graphviz dot on PATH

Environment:
  CAUSAL_SYSTRACE_WINDOW_MS   — if set, fixed bucket width (ms); else --auto-window
  CAUSAL_SYSTRACE_AUTO_SLICES — with auto-window, target ~N thin buckets (default 16; 0 = legacy min-buckets+2)
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = Path(__file__).resolve().parent
CAUSAL = ROOT / "src" / "causal.py"
CLEAN_CSV = EXAMPLES / "clean_enriched.csv"
MAL_CSV = EXAMPLES / "malicious_enriched.csv"
CLEAN_DOT = EXAMPLES / "clean_pc.dot"
MAL_DOT = EXAMPLES / "malicious_pc.dot"
CLEAN_PNG = EXAMPLES / "clean_pc.png"
MAL_PNG = EXAMPLES / "malicious_pc.png"
CLEAN_CORR_DOT = EXAMPLES / "clean_corr.dot"
MAL_CORR_DOT = EXAMPLES / "malicious_corr.dot"
CLEAN_CORR_PNG = EXAMPLES / "clean_corr.png"
MAL_CORR_PNG = EXAMPLES / "malicious_corr.png"

# DOT lines from write_pc_dot:  "a" -> "b" [label="pc"];  or  ... [label="pc?" dir=none ...];
_DOT_EDGE_RE = re.compile(
    r'^\s*"((?:\\.|[^"\\])*)"\s*->\s*"((?:\\.|[^"\\])*)"\s*(?:\[[^\]]*\])?\s*;',
)
_DIR_NONE_RE = re.compile(r"dir\s*=\s*none", re.IGNORECASE)
_CORR_EDGE_COUNT_RE = re.compile(r"\bedges:\s*(\d+)\b")


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _causal_cmd(method: str) -> list[str]:
    w = os.environ.get("CAUSAL_SYSTRACE_WINDOW_MS", "").strip()
    cmd: list[str] = [sys.executable, str(CAUSAL), "--method", method]
    if w:
        cmd += ["--window-ms", w]
        return cmd
    cmd.append("--auto-window")
    slices_env = os.environ.get("CAUSAL_SYSTRACE_AUTO_SLICES", "16").strip()
    if slices_env and slices_env != "0":
        try:
            ns = int(slices_env)
            if ns > 0:
                cmd += ["--auto-slices", str(max(ns, 3))]
        except ValueError:
            cmd += ["--auto-slices", "16"]
    return cmd


def parse_pc_dot_edges(path: Path) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Return (directed edges, undirected pairs as canonical (min,max) lexicographic)."""
    directed: set[tuple[str, str]] = set()
    undirected: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _DOT_EDGE_RE.match(line)
        if not m:
            continue
        u, v = _unescape(m.group(1)), _unescape(m.group(2))
        if _DIR_NONE_RE.search(line):
            a, b = (u, v) if u <= v else (v, u)
            undirected.add((a, b))
        else:
            directed.add((u, v))
    return directed, undirected


def _corr_edge_count_from_stdout(stdout: str) -> int | None:
    for line in stdout.splitlines():
        if "channels:" in line and "edges:" in line and "CPDAG" not in line:
            m = _CORR_EDGE_COUNT_RE.search(line)
            if m:
                return int(m.group(1))
    return None


def _run_corr_side(
    label: str,
    csv_path: Path,
    dot_path: Path,
    png_path: Path,
) -> int | None:
    cmd = [*_causal_cmd("corr"), str(csv_path), "--dot", str(dot_path)]
    print(f"\n--- lag correlation ({label}) ---", file=sys.stderr)
    r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    sys.stderr.write(r.stderr)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        print(f"corr failed for {label}", file=sys.stderr)
        return None
    subprocess.run(
        ["dot", "-Tpng", str(dot_path), "-o", str(png_path)],
        cwd=str(ROOT),
        check=True,
    )
    print(f"wrote {png_path}", file=sys.stderr)
    return _corr_edge_count_from_stdout(r.stdout)


def main() -> int:
    ap = argparse.ArgumentParser(description="PC graphs + diff; optional lag-corr comparison.")
    ap.add_argument(
        "--with-corr",
        action="store_true",
        help="Also build lag-correlation graphs (noisy) vs PC for contrast",
    )
    args = ap.parse_args()

    if not CLEAN_CSV.is_file() or not MAL_CSV.is_file():
        print(
            "Missing clean_enriched.csv or malicious_enriched.csv. Run:\n"
            "  python3 examples/build_real_artifacts.py",
            file=sys.stderr,
        )
        return 1
    if not shutil.which("dot"):
        print("graphviz `dot` not found on PATH; install graphviz.", file=sys.stderr)
        return 1

    base_pc = _causal_cmd("pc")
    r1 = subprocess.run([*base_pc, str(CLEAN_CSV), "--dot", str(CLEAN_DOT)], cwd=str(ROOT))
    r2 = subprocess.run([*base_pc, str(MAL_CSV), "--dot", str(MAL_DOT)], cwd=str(ROOT))
    if r1.returncode != 0 or r2.returncode != 0:
        return 1

    subprocess.run(
        ["dot", "-Tpng", str(CLEAN_DOT), "-o", str(CLEAN_PNG)],
        cwd=str(ROOT),
        check=True,
    )
    subprocess.run(
        ["dot", "-Tpng", str(MAL_DOT), "-o", str(MAL_PNG)],
        cwd=str(ROOT),
        check=True,
    )
    print(f"wrote {CLEAN_PNG}")
    print(f"wrote {MAL_PNG}")

    dc, uc = parse_pc_dot_edges(CLEAN_DOT)
    dm, um = parse_pc_dot_edges(MAL_DOT)
    only_mal_d = sorted(dm - dc)
    only_mal_u = sorted(um - uc)

    n_pc_mal = len(dm) + len(um)

    print()
    print("=" * 64)
    print("  Edges unique to MALICIOUS trace (potential anomalies)")
    print("=" * 64)
    print()
    print("Directed (solid arrows in the PC graph):")
    if not only_mal_d:
        print("  (none)")
    else:
        for u, v in only_mal_d:
            print(f"  {u}  -->  {v}")
    print()
    print("Undirected pairs (dashed edges in Graphviz):")
    if not only_mal_u:
        print("  (none)")
    else:
        for u, v in only_mal_u:
            print(f"  {u}  --  {v}")
    print()
    print(
        "Why dashed?  PC often leaves an edge unoriented in the CPDAG: it signals a statistical "
        "dependency, but direction needs stronger assumptions or interventional data—not something "
        "a passive syscall trace can settle alone."
    )
    print()

    if args.with_corr:
        n_c_clean = _run_corr_side("clean", CLEAN_CSV, CLEAN_CORR_DOT, CLEAN_CORR_PNG)
        n_c_mal = _run_corr_side("malicious", MAL_CSV, MAL_CORR_DOT, MAL_CORR_PNG)
        print()
        print("=" * 64)
        print("  Correlation vs PC (same time buckets, malicious trace)")
        print("=" * 64)
        if n_c_mal is not None:
            print(
                f"  Lag-correlation edges (|r| >= threshold): {n_c_mal}\n"
                f"  PC graph edges (directed + undirected):     {n_pc_mal}\n"
                f"  (Correlation is exploratory; PC applies conditional independence tests.)"
            )
        if n_c_clean is not None:
            print(f"  Clean trace lag-correlation edge count: {n_c_clean}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
