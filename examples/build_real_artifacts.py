#!/usr/bin/env python3
"""
Collect real syscall traces (Linux + loader + sudo) or FALLBACK synthetic enriched CSVs.

Primary path (Lima / Linux project root):
  1. Run clean_workload.sh / malicious_workload.sh as a background process (single PID via exec).
  2. sudo build/syscall_trace_loader -p <pid> -n 500 -o /tmp/*.csv
  3. python src/analysis.py ... --enrich --export-enriched -> examples/clean_enriched.csv, malicious_enriched.csv

If the loader is missing or collection fails, prints FALLBACK and writes two structurally
different synthetic enriched CSVs (replace with real traces before final demo).

Does not modify demo_enriched.csv / demo_graph.dot (reference only).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = Path(__file__).resolve().parent
LOADER = ROOT / "build" / "syscall_trace_loader"
CLEAN_SH = EXAMPLES / "clean_workload.sh"
MAL_SH = EXAMPLES / "malicious_workload.sh"
ANALYSIS = ROOT / "src" / "analysis.py"

CLEAN_RAW = Path("/tmp/causal_systrace_clean.csv")
MAL_RAW = Path("/tmp/causal_systrace_malicious.csv")
CLEAN_OUT = EXAMPLES / "clean_enriched.csv"
MAL_OUT = EXAMPLES / "malicious_enriched.csv"


def _validate_enriched(
    path: Path,
    label: str,
    *,
    min_rows: int = 50,
    min_channels: int = 5,
) -> bool:
    """Single-PID loader traces often have ~6–10 distinct channels; do not require >8."""
    df = pd.read_csv(path)
    n = len(df)
    nu = df["channel"].nunique() if "channel" in df.columns else 0
    ok = n > min_rows and nu >= min_channels
    print(f"  {label}: rows={n} unique_channels={nu} ok={ok}")
    return ok


def _run_enrich(raw: Path, out: Path) -> int:
    cmd = [
        sys.executable,
        str(ANALYSIS),
        str(raw),
        "--enrich",
        "--export-enriched",
        str(out),
    ]
    print(" ", " ".join(cmd))
    return subprocess.run(cmd, cwd=str(ROOT)).returncode


def _collect_one(workload: Path, raw_out: Path) -> bool:
    if not LOADER.is_file():
        print(f"  loader missing: {LOADER}", file=sys.stderr)
        return False
    if not workload.is_file():
        print(f"  workload missing: {workload}", file=sys.stderr)
        return False
    # Workloads sleep ~4s first so a blocking `sudo` password prompt does not let them
    # finish before the loader attaches (otherwise CSV stays header-only forever).
    print(
        "  (If prompted, enter sudo password now; workload waits 4s before syscalling.)",
        file=sys.stderr,
    )
    proc = subprocess.Popen(
        ["/bin/bash", str(workload)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=False,
    )
    pid = proc.pid
    time.sleep(0.15)
    n_events = int(os.environ.get("CAUSAL_SYSTRACE_N", "250"))
    cmd = [
        "sudo",
        str(LOADER),
        "-p",
        str(pid),
        "-n",
        str(n_events),
        "-o",
        str(raw_out),
    ]
    print(" ", " ".join(cmd))
    # Avoid infinite hang if the PID never reaches -n events.
    timeout_s = int(os.environ.get("CAUSAL_SYSTRACE_TIMEOUT", "90"))
    try:
        rc = subprocess.run(cmd, cwd=str(ROOT), timeout=timeout_s).returncode
    except subprocess.TimeoutExpired:
        print(f"  loader timed out after {timeout_s}s (partial CSV may exist)", file=sys.stderr)
        rc = -1
    try:
        proc.wait(timeout=120)
    except subprocess.TimeoutExpired:
        proc.kill()

    if not raw_out.is_file():
        return False
    try:
        text = raw_out.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    nlines = len(text.splitlines())
    data_rows = max(0, nlines - 1)  # minus header
    if data_rows < 1:
        print(
            "  trace has header only (no syscalls matched -p). "
            "Often caused by: workload finished during `sudo` password prompt, or wrong PID.",
            file=sys.stderr,
        )
        return False
    if data_rows < 30:
        print(
            f"  warning: only {data_rows} syscall rows (increase CAUSAL_SYSTRACE_N or workload loops)",
            file=sys.stderr,
        )
    return True


def _fallback_synthetic() -> None:
    print(
        "\n*** FALLBACK: synthetic enriched CSVs (no eBPF). "
        "Re-run on Linux with `make` + sudo before the demo. ***\n",
        file=sys.stderr,
    )
    t0 = 2_000_000_000_000_000
    pid = 4242
    rng = np.random.default_rng(0)

    # Clean: broad uniform-ish channel mix (long span + many rows for PC: samples > channels)
    clean_ch = [
        "4242:sc:getuid",
        "4242:sc:geteuid",
        "4242:sc:openat",
        "4242:file:/etc/hostname",
        "4242:fd:0",
        "4242:fd:1",
        "4242:sc:read",
        "4242:sc:close",
        "4242:sc:faccessat",
        "4242:sc:newfstatat",
        "4242:sc:ioctl",
        "4242:sc:brk",
    ]
    n = 600
    span_ns = 8_000_000_000  # 8 s of synthetic timeline
    ts = np.sort(rng.integers(0, span_ns, size=n, dtype=np.int64)) + t0
    ch = rng.choice(clean_ch, size=n, p=np.ones(len(clean_ch)) / len(clean_ch))
    df_c = pd.DataFrame(
        {
            "ts_ns": ts,
            "pid": pid,
            "syscall_id": 0,
            "arg0": 0,
            "arg1": 0,
            "arg2": 0,
            "arg3": 0,
            "arg4": 0,
            "arg5": 0,
            "path": "",
            "evt_kind": 0,
            "syscall_name": "synthetic_clean",
            "fd": pd.NA,
            "resource": pd.NA,
            "channel": ch,
        }
    )
    df_c.to_csv(CLEAN_OUT, index=False)

    # Malicious: burst of passwd read + socket/exfil-like labels co-occurring
    mp = pid + 1
    mal_ch = [
        f"{mp}:sc:getuid",
        f"{mp}:sc:geteuid",
        f"{mp}:sc:openat",
        f"{mp}:file:/etc/hostname",
        f"{mp}:fd:0",
        f"{mp}:fd:1",
        f"{mp}:sc:read",
        f"{mp}:sc:close",
        f"{mp}:file:/etc/passwd",
        f"{mp}:sc:sendto",
        f"{mp}:sc:connect",
        f"{mp}:fd:99",
        f"{mp}:sc:write",
        f"{mp}:sc:socket",
        f"{mp}:sc:ioctl",
    ]
    weights = np.ones(len(mal_ch))
    for i, c in enumerate(mal_ch):
        if "passwd" in c or "sendto" in c or "connect" in c or c.endswith(":99"):
            weights[i] = 6.0
    weights /= weights.sum()
    ts2 = np.sort(rng.integers(0, span_ns, size=n, dtype=np.int64)) + t0 + span_ns + 1
    ch2 = rng.choice(len(mal_ch), size=n, p=weights)
    ch2 = [mal_ch[i] for i in ch2]
    df_m = pd.DataFrame(
        {
            "ts_ns": ts2,
            "pid": mp,
            "syscall_id": 0,
            "arg0": 0,
            "arg1": 0,
            "arg2": 0,
            "arg3": 0,
            "arg4": 0,
            "arg5": 0,
            "path": "",
            "evt_kind": 0,
            "syscall_name": "synthetic_mal",
            "fd": pd.NA,
            "resource": pd.NA,
            "channel": ch2,
        }
    )
    df_m.to_csv(MAL_OUT, index=False)


def main() -> int:
    print(f"ROOT={ROOT}")
    use_real = os.environ.get("CAUSAL_SYSTRACE_FORCE_FALLBACK", "").lower() not in (
        "1",
        "true",
        "yes",
    )

    if use_real and sys.platform.startswith("linux") and LOADER.is_file():
        print("Attempting real trace collection…")
        ok_c = _collect_one(CLEAN_SH, CLEAN_RAW)
        ok_m = _collect_one(MAL_SH, MAL_RAW)
        if ok_c and ok_m:
            if _run_enrich(CLEAN_RAW, CLEAN_OUT) != 0:
                print("enrich clean failed", file=sys.stderr)
                ok_c = False
            if _run_enrich(MAL_RAW, MAL_OUT) != 0:
                print("enrich malicious failed", file=sys.stderr)
                ok_m = False
        if ok_c and ok_m:
            if _validate_enriched(CLEAN_OUT, "clean") and _validate_enriched(
                MAL_OUT, "malicious"
            ):
                print("Real-trace artifacts OK.")
                return 0
            print(
                "  Real CSVs were written but failed validation; "
                "not overwriting with FALLBACK (fix trace size or min_channels).",
                file=sys.stderr,
            )
            return 1

        print("Real trace collection or enrich failed; using FALLBACK.", file=sys.stderr)

    _fallback_synthetic()
    ok1 = _validate_enriched(CLEAN_OUT, "clean (fallback)")
    ok2 = _validate_enriched(MAL_OUT, "malicious (fallback)")
    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    raise SystemExit(main())
