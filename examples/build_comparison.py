#!/usr/bin/env python3
"""
Run PC-based causal.py on clean + malicious enriched CSVs, render PNGs, print edge diff.

Requires: examples/clean_enriched.csv and examples/malicious_enriched.csv
  (from examples/build_real_artifacts.py on Linux, or FALLBACK synthetic).

  pip install -r requirements-causal.txt   # causal-learn + graphviz dot on PATH
"""

from __future__ import annotations

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

# Short real loader traces (~few ms span): fixed large --window-ms collapses to 1 bucket.
# --auto-window fits min-buckets across the actual span; long synthetic traces still work.
# Override: CAUSAL_SYSTRACE_WINDOW_MS=0.5 python3 examples/build_comparison.py
def _causal_base() -> list[str]:
    w = os.environ.get("CAUSAL_SYSTRACE_WINDOW_MS", "").strip()
    if w:
        return [
            sys.executable,
            str(CAUSAL),
            "--method",
            "pc",
            "--window-ms",
            w,
        ]
    return [
        sys.executable,
        str(CAUSAL),
        "--method",
        "pc",
        "--auto-window",
    ]


# DOT lines from write_pc_dot:  "a" -> "b" [label="pc"];  or  ... [label="pc?" dir=none ...];
_DOT_EDGE_RE = re.compile(
    r'^\s*"((?:\\.|[^"\\])*)"\s*->\s*"((?:\\.|[^"\\])*)"\s*(?:\[[^\]]*\])?\s*;',
)
_DIR_NONE_RE = re.compile(r"dir\s*=\s*none", re.IGNORECASE)


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\\\", "\\")


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


def main() -> int:
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

    base = _causal_base()
    r1 = subprocess.run([*base, str(CLEAN_CSV), "--dot", str(CLEAN_DOT)], cwd=str(ROOT))
    r2 = subprocess.run([*base, str(MAL_CSV), "--dot", str(MAL_DOT)], cwd=str(ROOT))
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
    print("\nDirected edges in malicious_pc.dot but not in clean_pc.dot:")
    if not only_mal_d:
        print("  (none)")
    for u, v in only_mal_d:
        print(f"  {u} -> {v}")
    print("\nUndirected (CPDAG) pairs in malicious only (not in clean):")
    if not only_mal_u:
        print("  (none)")
    for u, v in only_mal_u:
        print(f"  {u} -- {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
