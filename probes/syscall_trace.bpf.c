#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
	__u64 ts_ns;
	__u32 pid;
	__u32 syscall_id;
	__u64 args[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

/*
 * Set from user-space via bpf_object__find_variable("target_pid") and update.
 * If 0, no filtering is applied.
 */
const volatile __u32 target_pid = 0;

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);

	if (target_pid != 0 && pid != target_pid)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->syscall_id = (__u32)ctx->id;

#pragma unroll
	for (int i = 0; i < 6; i++)
		e->args[i] = ctx->args[i];

	bpf_ringbuf_submit(e, 0);
	return 0;
}
