/*
 * Loads syscall_trace BPF (CO-RE skeleton), sets target PID filter, attaches
 * raw_syscalls:sys_enter, and prints ring buffer events. Run as root.
 *
 * Usage: sudo ./build/syscall_trace_loader -p PID [-n MAX_EVENTS] [-o FILE] [-v]
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
#include <sys/syscall.h>

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
	uint8_t evt_kind;
	uint8_t _pad[7];
	char path[256];
};

struct rb_ctx {
	uint64_t *remain;
	FILE *out;
	int csv;
};

static volatile sig_atomic_t stop;

static void on_sigint(int sig)
{
	(void)sig;
	stop = 1;
}

static void setup_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_sigint;
	sigemptyset(&sa.sa_mask);
	/*
	 * No SA_RESTART: interrupted epoll_wait/poll returns EINTR so we exit
	 * the ring buffer loop promptly on Ctrl+C.
	 */
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) != 0 || sigaction(SIGTERM, &sa, NULL) != 0)
		perror("warning: sigaction");
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

static void fputc_csv_escaped(FILE *out, const char *s)
{
	int need_quote = 0;

	if (!s || !s[0]) {
		return;
	}
	for (const char *p = s; *p; ++p) {
		if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
			need_quote = 1;
			break;
		}
	}
	if (!need_quote) {
		fputs(s, out);
		return;
	}
	fputc('"', out);
	for (; *s; ++s) {
		if (*s == '"')
			fputs("\"\"", out);
		else
			fputc(*s, out);
	}
	fputc('"', out);
}

static void print_path_space(FILE *out, const char *s)
{
	fputc(' ', out);
	if (!s || !s[0]) {
		fputc('-', out);
		return;
	}
	fputc('"', out);
	for (; *s; ++s) {
		if (*s == '"' || *s == '\\') {
			fputc('\\', out);
			fputc(*s, out);
		} else if (*s == '\n') {
			fputs("\\n", out);
		} else if (*s == '\r') {
			fputs("\\r", out);
		} else {
			fputc(*s, out);
		}
	}
	fputc('"', out);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct rb_ctx *c = ctx;
	uint64_t *remain = c->remain;
	const struct event *e = data;
	FILE *out = c->out;

	/*
	 * ring_buffer__poll may drain many samples in one call; without this,
	 * Ctrl+C sets stop but we do not observe it until the batch finishes.
	 */
	if (stop)
		return 1;

	if (data_sz < sizeof(*e)) {
		fprintf(stderr, "short ringbuf sample: %zu (expected %zu)\n", data_sz,
			sizeof(*e));
		return 0;
	}

	/*
	 * libbpf may deliver many samples in one ring_buffer__poll(); returning
	 * non-zero stops further callbacks in this batch. Without that, we'd
	 * print past N and uint64_t *remain would underflow after hitting 0.
	 */
	if (remain && *remain == 0) {
		stop = 1;
		return 1;
	}

	if (c->csv) {
		fprintf(out, "%" PRIu64 ",%u,%u", e->ts_ns, e->pid, e->syscall_id);
		for (int i = 0; i < 6; i++)
			fprintf(out, ",%" PRIu64, e->args[i]);
		fputc(',', out);
		fputc_csv_escaped(out, e->path);
		fprintf(out, ",%u\n", (unsigned int)e->evt_kind);
	} else {
		fprintf(out, "%" PRIu64 " %u %u", e->ts_ns, e->pid, e->syscall_id);
		for (int i = 0; i < 6; i++)
			fprintf(out, " %" PRIu64, e->args[i]);
		print_path_space(out, e->path);
		fprintf(out, " %u\n", (unsigned int)e->evt_kind);
	}
	fflush(out);

	if (remain) {
		(*remain)--;
		if (*remain == 0) {
			stop = 1;
			return 1;
		}
	}
	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr, "usage: %s -p PID [-n MAX_EVENTS] [-o FILE] [-v]\n", argv0);
	fprintf(stderr, "  -p PID          filter to this PID (0 = all PIDs)\n");
	fprintf(stderr, "  -n MAX_EVENTS   exit after this many events (>=1; 0 = unlimited)\n");
	fprintf(stderr, "  -o FILE         write CSV to FILE (use - for stdout CSV)\n");
	fprintf(stderr, "  -v              verbose libbpf messages (default: quiet)\n");
}

int main(int argc, char **argv)
{
	struct syscall_trace_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct rb_ctx rb_ctx = { .remain = NULL, .out = stdout, .csv = 0 };
	FILE *out_file = NULL;
	int out_needs_fclose = 0;
	int verbose = 0;
	uint32_t target_pid = (uint32_t)-1;
	uint64_t remain = 0;
	int opt;
	int err;

	while ((opt = getopt(argc, argv, "p:n:o:vh")) != -1) {
		switch (opt) {
		case 'p':
			target_pid = (uint32_t)strtoul(optarg, NULL, 10);
			break;
		case 'n':
			remain = strtoull(optarg, NULL, 10);
			break;
		case 'o':
			if (strcmp(optarg, "-") == 0) {
				rb_ctx.out = stdout;
				rb_ctx.csv = 1;
			} else {
				out_file = fopen(optarg, "w");
				if (!out_file) {
					fprintf(stderr, "%s: ", optarg);
					perror("fopen");
					return 1;
				}
				setvbuf(out_file, NULL, _IOLBF, 0);
				rb_ctx.out = out_file;
				rb_ctx.csv = 1;
			}
			break;
		case 'v':
			verbose = 1;
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

	rb_ctx.remain = remain ? &remain : NULL;

	bump_memlock_rlimit();
	libbpf_set_print(verbose ? libbpf_print : NULL);

	setup_signals();

	skel = syscall_trace_bpf__open();
	if (!skel) {
		fprintf(stderr, "syscall_trace_bpf__open failed\n");
		err = -1;
		goto cleanup;
	}

	skel->rodata->target_pid = target_pid;
#ifdef __NR_open
	skel->rodata->nr_open = (unsigned int)__NR_open;
#else
	skel->rodata->nr_open = 0;
#endif
	skel->rodata->nr_openat = (unsigned int)__NR_openat;

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

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &rb_ctx,
			      NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "ring_buffer__new failed: %d\n", err);
		goto cleanup;
	}

	if (rb_ctx.csv)
		fprintf(rb_ctx.out,
			"ts_ns,pid,syscall_id,arg0,arg1,arg2,arg3,arg4,arg5,path,evt_kind\n");
	else
		fprintf(rb_ctx.out,
			"# ts_ns pid syscall_id arg0..arg5 path evt_kind (evt_kind 1 = open fd+path)\n");
	fflush(rb_ctx.out);

	while (!stop) {
		/* Short timeout so we re-check stop often even between poll calls. */
		err = ring_buffer__poll(rb, 50);
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
	if (out_needs_fclose && out_file)
		fclose(out_file);
	return err < 0 ? 1 : 0;
}
