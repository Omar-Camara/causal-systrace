#!/usr/bin/env python3
"""Build synthetic enriched CSV + run causal.py for demo artifacts (no Linux ausyscall)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
CHANNELS = [
    "1859:sc:getuid",
    "1859:sc:geteuid",
    "1859:sc:faccessat",
    "1859:sc:newfstatat",
    "1859:sc:clone",
    "1859:sc:pipe2",
    "1859:sc:setpgid",
    "1859:fd:3",
    "1859:fd:255",
    "1859:fd:0",
    "1859:fd:1",
    "1859:fd:2",
    "1859:sc:openat",
    "1859:file:/dev/null",
    "1859:sc:rt_sigaction",
    "1859:sc:rt_sigprocmask",
    "1859:sc:pselect6",
    "1859:sc:close",
    "1859:sc:wait4",
    "1859:sc:brk",
    "1859:sc:chdir",
    "1859:sc:dup3",
    "1859:sc:ioctl",
    "1859:sc:fcntl",
    "1859:sc:read",
]


def main() -> int:
    rng = np.random.default_rng(42)
    t0 = 1_000_000_000_000_000
    span_ns = 12_000_000  # 12 ms
    n = 120
    ts = np.sort(rng.integers(0, span_ns, size=n, dtype=np.int64)) + t0

    # Bias draws so co-movement exists (similar to shell traces)
    weights = np.array([3 if "pselect6" in c or "rt_sig" in c else 1 for c in CHANNELS], dtype=float)
    weights /= weights.sum()
    idx = rng.choice(len(CHANNELS), size=n, p=weights)
    ch = [CHANNELS[i] for i in idx]

    df = pd.DataFrame(
        {
            "ts_ns": ts,
            "pid": 1859,
            "syscall_id": 0,
            "arg0": 0,
            "arg1": 0,
            "arg2": 0,
            "arg3": 0,
            "arg4": 0,
            "arg5": 0,
            "path": "",
            "evt_kind": 0,
            "syscall_name": "synthetic",
            "fd": pd.NA,
            "resource": pd.NA,
            "channel": ch,
        }
    )

    out_dir = Path(__file__).resolve().parent
    enriched_path = out_dir / "demo_enriched.csv"
    dot_path = out_dir / "demo_graph.dot"
    df.to_csv(enriched_path, index=False)

    cmd = [
        sys.executable,
        str(ROOT / "src/causal.py"),
        str(enriched_path),
        "--window-ms",
        "0.5",
        "--threshold",
        "0.35",
        "--dot",
        str(dot_path),
    ]
    print("running:", " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=str(ROOT))
    if r.returncode != 0:
        return r.returncode

    nuniq = df["channel"].nunique()
    print(f"\nunique channels in demo: {nuniq} (of {len(CHANNELS)} defined labels)")
    print(f"wrote {enriched_path}")
    print(f"wrote {dot_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
