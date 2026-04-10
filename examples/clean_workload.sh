#!/usr/bin/env bash
# Benign single-process workload (exec keeps one PID for syscall_trace_loader -p).
set -euo pipefail
exec python3 - <<'PY'
import pathlib
import time
import urllib.error
import urllib.request

# Let the parent start `sudo syscall_trace_loader` (password prompt) before we syscall.
time.sleep(4)

pathlib.Path("/etc/hostname").read_text()
print(pathlib.Path("/etc/hostname").read_text().strip())
for p in list(sorted(pathlib.Path("/tmp").iterdir()))[:30]:
    _ = str(p)
for _ in range(80):
    pathlib.Path("/etc/hostname").read_text()
try:
    urllib.request.urlopen("http://127.0.0.1:9/", timeout=0.3)
except (urllib.error.URLError, OSError, TimeoutError):
    pass
PY
