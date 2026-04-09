#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* evt_kind: 0 = raw sys_enter row; 1 = open/openat resolved (emitted from sys_exit). */
struct event {
	__u64 ts_ns;
	__u32 pid;
	__u32 syscall_id;
	__u64 args[6];
	__u8 evt_kind;
	__u8 _pad[7];
	char path[256];
};

struct pending_path {
	char path[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");

/*
 * One pending pathname per thread (pid_tgid). Concurrent opens on the same
 * thread without interleaving exits are rare; overlapping opens can mis-associate.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct pending_path);
} open_pending SEC(".maps");

/*
 * Set from user-space via rodata before load.
 * nr_open may be 0 on arches where only openat exists.
 */
const volatile __u32 target_pid = 0;
const volatile __u32 nr_open = 0;
const volatile __u32 nr_openat = 0;

static __always_inline void clear_path(struct event *e)
{
	e->path[0] = '\0';
}

SEC("tracepoint/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);

	if (target_pid != 0 && pid != target_pid)
		return 0;

	__u32 sc = (__u32)ctx->id;

	if (nr_openat && sc == nr_openat) {
		struct pending_path pending = {};
		long n = bpf_probe_read_user_str(
			pending.path, sizeof(pending.path),
			(const void *)ctx->args[1]);
		if (n > 0)
			bpf_map_update_elem(&open_pending, &pid_tgid, &pending, BPF_ANY);
	} else if (nr_open && sc == nr_open) {
		struct pending_path pending = {};
		long n = bpf_probe_read_user_str(
			pending.path, sizeof(pending.path),
			(const void *)ctx->args[0]);
		if (n > 0)
			bpf_map_update_elem(&open_pending, &pid_tgid, &pending, BPF_ANY);
	}

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->syscall_id = sc;
	e->args[0] = ctx->args[0];
	e->args[1] = ctx->args[1];
	e->args[2] = ctx->args[2];
	e->args[3] = ctx->args[3];
	e->args[4] = ctx->args[4];
	e->args[5] = ctx->args[5];
	e->evt_kind = 0;
	clear_path(e);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = (__u32)(pid_tgid >> 32);

	if (target_pid != 0 && pid != target_pid)
		return 0;

	long id = BPF_CORE_READ(ctx, id);
	long ret = BPF_CORE_READ(ctx, ret);

	__u32 sc = (__u32)id;
	if (nr_openat && sc == nr_openat)
		;
	else if (nr_open && sc == nr_open)
		;
	else
		return 0;

	if (ret < 0) {
		bpf_map_delete_elem(&open_pending, &pid_tgid);
		return 0;
	}

	struct pending_path *pb = bpf_map_lookup_elem(&open_pending, &pid_tgid);
	if (!pb)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->syscall_id = sc;
	e->args[0] = (__u64)ret;
	e->args[1] = 0;
	e->args[2] = 0;
	e->args[3] = 0;
	e->args[4] = 0;
	e->args[5] = 0;
	e->evt_kind = 1;
	__builtin_memcpy(e->path, pb->path, sizeof(e->path));

	bpf_map_delete_elem(&open_pending, &pid_tgid);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
