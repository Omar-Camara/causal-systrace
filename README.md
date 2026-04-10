# Causal-SysTrace

eBPF **syscall enter** tracing (CO-RE **libbpf**), CSV export, pandas **enrichment** (syscall names, `channel`), and a **lag-correlation** Graphviz sketch—not a formal causal proof, but a pipeline toward causal discovery.

## Requirements

- Linux with **BTF** (`/sys/kernel/btf/vmlinux`)
- `clang`, `bpftool`, `libbpf-dev`, `gcc`
- Python 3.10+ for analysis

## Build

```bash
make clean && make
```

Artifacts: `build/syscall_trace_loader`, `build/syscall_trace.bpf.o`.

## Collect (needs root)

**Quick smoke test (all PIDs, stops automatically — can be noisy):**

```bash
mkdir -p data
sudo ./build/syscall_trace_loader -p 0 -n 800 -o data/raw.csv
```

**Trace one shell you control (replace `4182` with a real PID):**

1. In the shell you want to trace, run `echo $$` (example output: `4182`).
2. In another terminal, while you use that first shell (run `ls`, `cat` a file, etc.):

```bash
mkdir -p data
sudo ./build/syscall_trace_loader -p 4182 -n 2000 -o data/raw.csv
```

The loader prints the CSV header, then one line per event; it looks idle until syscalls occur. Stop early with **Ctrl+C**, or let **`-n`** finish the run.

Same thing via the Python wrapper:

```bash
python3 src/collector.py -p 0 -n 800 -o data/raw.csv
```

## Full pipeline (concrete example)

From the repo root (after `make`), with a venv and deps:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

make clean && make

mkdir -p data
sudo ./build/syscall_trace_loader -p 0 -n 800 -o data/raw.csv

python src/analysis.py data/raw.csv --enrich --export-enriched data/enriched.csv
python src/causal.py data/enriched.csv --auto-window --threshold 0.35 --dot data/graph.dot
dot -Tpng data/graph.dot -o data/graph.png
```

Use **`-p 0`** only for short tests. For a cleaner graph, prefer **`-p <one_pid>`** and generate activity in that process while the loader runs.

## Analyze & enrich

```bash
python src/analysis.py data/raw.csv --enrich --export-enriched data/enriched.csv
```

## Causal preview (bucketed counts + lag-corr edges)

```bash
python src/causal.py data/enriched.csv --auto-window --threshold 0.35 --dot data/graph.dot
# Short traces (< few ms): --auto-window or a tiny --window-ms (e.g. 0.0005); see tool hints.
dot -Tpng data/graph.dot -o data/graph.png   # needs system graphviz
```

Raw CSV + `--auto-enrich` is supported if `ausyscall` or kernel headers are available.

## Layout

| Path | Role |
|------|------|
| `probes/syscall_trace.bpf.c` | eBPF: `raw_syscalls/sys_enter`, ringbuf |
| `src/loader.c` | libbpf loader, `-o` CSV, `-n` cap, quiet libbpf by default |
| `src/collector.py` | `sudo` + loader wrapper |
| `src/analysis.py` | Summary, syscall names, `--enrich`, export |
| `src/causal.py` | Time buckets, lag-corr edges, `.dot` |
| `requirements.txt` | pandas / numpy / networkx |
| `requirements-causal.txt` | Optional **cdt**/torch (commented) |

## Note on VMs (e.g. Lima)

If `/Users/...` is read-only in the guest, clone under **`~`** and run `make` there, or `make BUILD_DIR=/tmp/build`.

If **`python src/analysis.py …` exits with `Killed`** (no traceback), the guest likely ran out of RAM (OOM killer). Give the VM more memory in `lima.yaml`, close other apps, or run analysis on a smaller `raw.csv` (e.g. lower **`-n`** when collecting).

For machine-specific notes, use **`LOCAL_SETUP.md`** (gitignored if configured in `.gitignore`).
