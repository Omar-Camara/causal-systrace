/*
 * Loads syscall_trace BPF (CO-RE skeleton), sets target PID filter, attaches
 * raw_syscalls:sys_enter, and prints ring buffer events. Run as root.
 *
 * Usage: sudo ./build/syscall_trace_loader -p PID [-n MAX_EVENTS]
 *   PID 0 = trace all PIDs (heavy).
 */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <stdarg.h>
#include <sys/resource.h>

#include "syscall_trace.skel.h"

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	(void)level;
	return vfprintf(stderr, fmt, ap);
}

/* Must match struct event in probes/syscall_trace.bpf.c */
struct event {
	uint64_t ts_ns;
	uint32_t pid;
	uint32_t syscall_id;
	uint64_t args[6];
};

static volatile sig_atomic_t stop;

static void on_sigint(int sig)
{
	(void)sig;
	stop = 1;
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim) && errno != EPERM)
		fprintf(stderr, "warning: setrlimit(RLIMIT_MEMLOCK): %s\n", strerror(errno));
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	uint64_t *count = ctx;
	const struct event *e = data;

	if (data_sz < sizeof(*e)) {
		fprintf(stderr, "short ringbuf sample: %zu\n", data_sz);
		return 0;
	}

	printf("%" PRIu64 " %u %u", e->ts_ns, e->pid, e->syscall_id);
	for (int i = 0; i < 6; i++)
		printf(" %" PRIu64, e->args[i]);
	printf("\n");

	if (count) {
		(*count)--;
		if (*count == 0)
			stop = 1;
	}
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s -p PID [-n MAX_EVENTS]\n", argv0);
	fprintf(stderr, "  -p PID          filter to this PID (0 = all PIDs)\n");
	fprintf(stderr, "  -n MAX_EVENTS   exit after this many events (default: run until Ctrl+C)\n");
}

int main(int argc, char **argv)
{
	struct syscall_trace_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	uint32_t target_pid = (uint32_t)-1;
	uint64_t remain = 0;
	int opt;
	int err;

	while ((opt = getopt(argc, argv, "p:n:h")) != -1) {
		switch (opt) {
		case 'p':
			target_pid = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		case 'n':
			remain = strtoull(optarg, NULL, 10);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (target_pid == (uint32_t)-1) {
		usage(argv[0]);
		return 1;
	}

	bump_memlock_rlimit();
	libbpf_set_print(libbpf_print);

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	skel = syscall_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "syscall_trace_bpf__open failed\n");
		return 1;
	}

	skel->rodata->target_pid = target_pid;

	err = syscall_trace_bpf__load(skel);
	if (err) {
		fprintf(stderr, "syscall_trace_bpf__load failed: %d\n", err);
		goto cleanup;
	}

	err = syscall_trace_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "syscall_trace_bpf__attach failed: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event,
			      remain ? &remain : NULL, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "ring_buffer__new failed: %d\n", err);
		goto cleanup;
	}

	printf("# ts_ns pid syscall_id arg0 arg1 arg2 arg3 arg4 arg5\n");
	while (!stop) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "ring_buffer__poll: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	syscall_trace_bpf__destroy(skel);
	return err < 0 ? 1 : 0;
}
