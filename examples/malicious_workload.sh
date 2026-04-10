#!/usr/bin/env bash
# Suspicious single-process pattern: read sensitive-ish file, push bytes to a TCP socket.
# Uses localhost discard port (often closed); connection may fail but syscalls still occur.
set -euo pipefail
exec python3 - <<'PY'
import pathlib
import socket

data = pathlib.Path("/etc/passwd").read_text()[:4000]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", 9))
    s.sendall(data.encode())
except OSError:
    pass
finally:
    s.close()
for _ in range(60):
    pathlib.Path("/etc/passwd").read_text()[:500]
PY
