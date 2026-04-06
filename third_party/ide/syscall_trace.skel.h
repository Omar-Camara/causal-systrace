/*
 * Minimal stub for editor IntelliSense only. The real file is generated at
 * build/syscall_trace.skel.h by: bpftool gen skeleton build/syscall_trace.bpf.o
 * Keep field names aligned with the generated skeleton.
 */
#ifndef __SYSCALL_TRACE_SKEL_STUB_H
#define __SYSCALL_TRACE_SKEL_STUB_H

#include <bpf/libbpf.h>
#include <stdint.h>

struct syscall_trace_bpf__rodata {
	uint32_t target_pid;
};

struct syscall_trace_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *events;
	} maps;
	struct syscall_trace_bpf__rodata *rodata;
};

struct syscall_trace_bpf *syscall_trace_bpf__open(void);
int syscall_trace_bpf__load(struct syscall_trace_bpf *skel);
int syscall_trace_bpf__attach(struct syscall_trace_bpf *skel);
void syscall_trace_bpf__destroy(struct syscall_trace_bpf *skel);

#endif
