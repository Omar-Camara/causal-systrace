SHELL := /bin/bash

# Causal-SysTrace: CO-RE eBPF build with libbpf skeleton generation
#
# Requirements (Ubuntu 22.04+ suggested):
#   - clang, llvm (for bpftool + clang)
#   - bpftool (usually from linux-tools-$(uname -r) / linux-tools-generic)
#   - libbpf headers (libbpf-dev) OR a vendored libbpf in ./libbpf (optional)
#   - kernel BTF available at /sys/kernel/btf/vmlinux
#
# Common install:
#   sudo apt-get update
#   sudo apt-get install -y clang llvm libbpf-dev linux-tools-common linux-tools-generic linux-tools-$(uname -r)
#
# Build:
#   make
#
# Output:
#   build/syscall_trace.bpf.o
#   build/syscall_trace.skel.h

.PHONY: all clean check-env dirs

APP           ?= syscall_trace
BPF_PROG      ?= probes/$(APP).bpf.c
BUILD_DIR     ?= build

VMLINUX_BTF   ?= /sys/kernel/btf/vmlinux
SKIP_BTF_CHECK ?= 0

CLANG         ?= clang
LLC           ?= llc
BPFOOL        ?= bpftool

# If you vendor libbpf into ./libbpf (with src/ and include/),
# set LIBBPF_DIR=libbpf when invoking make.
LIBBPF_DIR    ?=

ifeq ($(strip $(LIBBPF_DIR)),)
LIBBPF_INC    ?=
else
LIBBPF_INC    ?= -I$(LIBBPF_DIR)/src -I$(LIBBPF_DIR)/include/uapi
endif

# Prefer system include paths. On Ubuntu with libbpf-dev:
#   /usr/include/bpf/*.h and /usr/include/linux/*.h exist.
INCLUDES      ?= -I$(BUILD_DIR) -I/usr/include -I/usr/include/bpf -I/usr/include/linux $(LIBBPF_INC)

# Minimal, portable BPF CFLAGS. We rely on CO-RE + BTF for kernel struct layouts.
BPF_CFLAGS    ?= -O2 -g -target bpf -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/ppc64le/powerpc/') \
                 -Wall -Wextra -Werror \
                 $(INCLUDES)

VMLINUX_H     := $(BUILD_DIR)/vmlinux.h
BPF_OBJ       := $(BUILD_DIR)/$(APP).bpf.o
SKEL_H        := $(BUILD_DIR)/$(APP).skel.h

all: check-env dirs $(SKEL_H)

dirs:
	@mkdir -p $(BUILD_DIR)

check-env:
	@if [[ "$(SKIP_BTF_CHECK)" != "1" ]]; then \
		test -r "$(VMLINUX_BTF)" || (echo "ERROR: missing kernel BTF at $(VMLINUX_BTF). Override VMLINUX_BTF=... or set SKIP_BTF_CHECK=1 (not recommended for real builds)." && exit 1); \
	else \
		echo "WARNING: SKIP_BTF_CHECK=1 set; build may fail without a valid vmlinux BTF."; \
	fi
	@command -v $(CLANG) >/dev/null || (echo "ERROR: clang not found" && exit 1)
	@command -v $(BPFOOL) >/dev/null || (echo "ERROR: bpftool not found (install linux-tools-$(shell uname -r))" && exit 1)

$(VMLINUX_H): | dirs
	@echo "Generating vmlinux.h from $(VMLINUX_BTF)"
	@$(BPFOOL) btf dump file "$(VMLINUX_BTF)" format c > "$@"

$(BPF_OBJ): $(BPF_PROG) $(VMLINUX_H) | dirs
	@echo "Compiling BPF program $<"
	@$(CLANG) $(BPF_CFLAGS) -c "$<" -o "$@"

$(SKEL_H): $(BPF_OBJ) | dirs
	@echo "Generating skeleton header $@"
	@$(BPFOOL) gen skeleton "$<" > "$@"

clean:
	@rm -rf "$(BUILD_DIR)"
