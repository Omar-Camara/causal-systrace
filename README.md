# Causal-SysTrace

eBPF **syscall enter** tracing (CO-RE **libbpf**), CSV export, pandas **enrichment** (syscall names, `channel`), and a **lag-correlation** Graphviz sketch—not a formal causal proof, but a pipeline toward causal discovery.

## Requirements

- Linux with **BTF** (`/sys/kernel/btf/vmlinux`)
- `clang`, `bpftool`, `libbpf-dev`, `gcc`
- Python 3.10+ for analysis

## Build

```bash
make
```

Artifacts: `build/syscall_trace_loader`, `build/syscall_trace.bpf.o`.

## Collect (needs root)

```bash
sudo ./build/syscall_trace_loader -p 0 -n 1000 -o data/raw.csv
```

Or:

```bash
python3 src/collector.py -p 0 -n 1000 -o data/raw.csv
```

## Analyze & enrich

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

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

For machine-specific notes, use **`LOCAL_SETUP.md`** (gitignored if configured in `.gitignore`).
