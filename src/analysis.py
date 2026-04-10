#!/usr/bin/env python3
"""
Load CSV produced by syscall_trace_loader (-o FILE) and print summary stats.

Example:
  python src/analysis.py trace.csv
  python src/analysis.py trace.csv --enrich --head 10
  python src/analysis.py trace.csv --enrich --export-enriched data/enriched.csv

Loader CSV may include path,evt_kind (evt_kind=1: open/openat resolved with fd in arg0).
Enrichment maps fd -> pathname for subsequent syscalls that carry an fd (read, write, …).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

import numpy as np

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


# Linux: which arg slot holds an fd for common syscalls (sys_enter args match the syscall ABI).
_FD_ARG: dict[str, int] = {
    "read": 0,
    "write": 0,
    "close": 0,
    "readv": 0,
    "writev": 0,
    "pread64": 0,
    "pwrite64": 0,
    "ioctl": 0,
    "fsync": 0,
    "fdatasync": 0,
    "recvfrom": 0,
    "sendto": 0,
    "mmap": 4,
}


def shorten_path_label(path: str, max_len: int = 56) -> str:
    p = (path or "").strip()
    if not p:
        return "?"
    if len(p) <= max_len:
        return p
    return "..." + p[-(max_len - 3) :]


def infer_fd_for_name(name: str, row) -> int | None:
    if name == "?" or not name:
        return None
    idx = _FD_ARG.get(name)
    if idx is None:
        return None
    key = f"arg{idx}"
    if key not in row.index:
        return None
    try:
        v = int(row[key])
    except (TypeError, ValueError):
        return None
    return v


def infer_fd_from_args(name: str, argrow: np.ndarray) -> int | None:
    if name == "?" or not name:
        return None
    idx = _FD_ARG.get(name)
    if idx is None or idx > 5:
        return None
    try:
        return int(argrow[idx])
    except (TypeError, ValueError, IndexError):
        return None


def enrich_dataframe(df, sc_map: dict[int, str], pd):
    """Add syscall_name, fd (when inferrable), channel (for grouping).

    If columns path / evt_kind exist (new loader), resolves fd -> file path over time
    and uses pid:file:<path> channels when known.
    """
    out = df.copy()
    if "path" not in out.columns:
        out["path"] = ""
    if "evt_kind" not in out.columns:
        out["evt_kind"] = 0
    out["evt_kind"] = out["evt_kind"].fillna(0).astype(np.int64)
    out["path"] = out["path"].fillna("").astype(str)

    sid = pd.to_numeric(out["syscall_id"], errors="coerce").fillna(-1).astype(np.int64)
    out["syscall_name"] = sid.map(sc_map).fillna("?").astype(str)

    n = len(out)
    out["_rowid"] = np.arange(n, dtype=np.int64)
    work = out.sort_values(["ts_ns", "evt_kind", "_rowid"], kind="stable")

    pids = work["pid"].to_numpy(dtype=np.int64, copy=False)
    names = work["syscall_name"].astype(str).to_numpy(dtype=object, copy=False)
    evt_kinds = work["evt_kind"].to_numpy(dtype=np.int64, copy=False)
    paths = work["path"].to_numpy(dtype=object, copy=False)
    rowids = work["_rowid"].to_numpy(dtype=np.int64, copy=False)
    args = work[[f"arg{i}" for i in range(6)]].to_numpy(dtype=np.int64, copy=False)

    ch_out: list[object] = [pd.NA] * n
    res_out: list[object] = [pd.NA] * n
    fd_out: list[object] = [pd.NA] * n

    fd_map: dict[tuple[int, int], str] = {}
    wlen = len(work)

    for j in range(wlen):
        pid = int(pids[j])
        name = str(names[j])
        ek = int(evt_kinds[j])
        rid = int(rowids[j])
        argrow = args[j]

        if ek == 1:
            fd_new = int(argrow[0])
            pv = paths[j]
            path = "" if pd.isna(pv) else str(pv).strip()
            if fd_new >= 0 and path:
                fd_map[(pid, fd_new)] = path
            lab = shorten_path_label(path) if path else "?"
            ch_out[rid] = f"{pid}:file:{lab}"
            res_out[rid] = path if path else pd.NA
            fd_out[rid] = fd_new if fd_new >= 0 else pd.NA
            continue

        if name == "close":
            fd_close = infer_fd_from_args(name, argrow)
            if fd_close is not None:
                fd_map.pop((pid, int(fd_close)), None)
            ch_out[rid] = f"{pid}:sc:{name}"
            res_out[rid] = pd.NA
            fd_out[rid] = int(fd_close) if fd_close is not None else pd.NA
            continue

        fd_val = infer_fd_from_args(name, argrow)
        if fd_val is not None:
            fdi = int(fd_val)
            if (pid, fdi) in fd_map:
                p = fd_map[(pid, fdi)]
                lab = shorten_path_label(p)
                ch_out[rid] = f"{pid}:file:{lab}"
                res_out[rid] = p
                fd_out[rid] = fdi
                continue
            ch_out[rid] = f"{pid}:fd:{fdi}"
            res_out[rid] = pd.NA
            fd_out[rid] = fdi
            continue

        ch_out[rid] = f"{pid}:sc:{name}"
        res_out[rid] = pd.NA
        fd_out[rid] = pd.NA

    out["fd"] = fd_out
    try:
        out["fd"] = out["fd"].astype("Int64")
    except (TypeError, ValueError):
        pass
    out["resource"] = res_out
    out["channel"] = ch_out
    return out.drop(columns=["_rowid"], errors="ignore")


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
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Add syscall_name, fd, resource (if known), channel (pid:file:… / pid:fd:… / pid:sc:NAME)",
    )
    parser.add_argument(
        "--export-enriched",
        metavar="PATH",
        default="",
        help="Write enriched CSV (requires --enrich and syscall names)",
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
    else:
        sc_map = {}

    try:
        peek = pd.read_csv(args.csv, nrows=0)
        colset = set(peek.columns)
        dtype_map = {
            c: "int64"
            for c in (
                "ts_ns",
                "pid",
                "syscall_id",
                "arg0",
                "arg1",
                "arg2",
                "arg3",
                "arg4",
                "arg5",
            )
            if c in colset
        }
        if "evt_kind" in colset:
            dtype_map["evt_kind"] = "int64"
        df = pd.read_csv(args.csv, dtype=dtype_map)
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

    extra = [c for c in ("path", "evt_kind") if c in df.columns]
    if extra:
        print(f"optional loader columns: {', '.join(extra)}", file=sys.stderr)

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

    enriched = None
    if args.enrich:
        if not sc_map:
            print(
                "enrich needs syscall names (drop --no-syscall-names)",
                file=sys.stderr,
            )
            return 1
        enriched = enrich_dataframe(df, sc_map, pd)
        top_ch = enriched["channel"].value_counts().head(12)
        print("top channel (count) [pid:fd:… or pid:sc:NAME]:")
        for ch, cnt in top_ch.items():
            print(f"  {ch}: {int(cnt)}")

    if args.export_enriched:
        if enriched is None:
            print("--export-enriched requires --enrich", file=sys.stderr)
            return 1
        try:
            enriched.to_csv(args.export_enriched, index=False)
        except OSError as e:
            print(f"export failed: {e}", file=sys.stderr)
            return 1
        print(f"wrote {args.export_enriched}", file=sys.stderr)

    if args.head > 0:
        print(f"\nfirst {args.head} rows:")
        if enriched is not None:
            show = enriched.head(args.head)
        else:
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
