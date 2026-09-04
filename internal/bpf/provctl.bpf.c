// SPDX-License-Identifier: MIT
// provctl.bpf.c — the capture engine. Five hooks feed one ring buffer:
//
//   sched_process_fork  -> EVENT_FORK      (parent/child pid lineage)
//   sched_process_exec  -> EVENT_EXEC      (execve, resolved path)
//   sched_process_exit  -> EVENT_EXIT      (exit code)
//   security_file_open  -> EVENT_FILE_OPEN (every file open, path via bpf_d_path)
//   tcp_v4/v6_connect   -> EVENT_CONNECT   (outbound connection attempts)
//
// Every downstream view (provenance graph, flight-recorder timeline, live
// watch) is a userspace query over this one event stream — the kernel side
// stays deliberately dumb: capture, tag with identity, hand to userspace.
//
// CO-RE (Compile Once – Run Everywhere): built against this machine's
// /sys/kernel/btf/vmlinux, but relocations are resolved at load time against
// the *running* kernel's BTF, so a compiled object is portable across kernel
// versions that expose the same fields.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "provctl.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

// set once from userspace after load so probes can skip provctl's own
// syscalls (otherwise the daemon endlessly traces itself opening its own
// database file, log lines, etc).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} self_pid SEC(".maps");

static __always_inline bool is_self(__u32 pid)
{
	__u32 key = 0;
	__u32 *self = bpf_map_lookup_elem(&self_pid, &key);
	return self && *self != 0 && *self == pid;
}

static __always_inline void fill_identity(struct event *e)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;

	__u64 uid_gid = bpf_get_current_uid_gid();
	e->uid = uid_gid & 0xFFFFFFFF;
	e->gid = uid_gid >> 32;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct task_struct *parent = BPF_CORE_READ(task, real_parent);
	e->ppid = parent ? BPF_CORE_READ(parent, tgid) : 0;
}

// ---------------------------------------------------------------------
// sched_process_fork — parent/child edges for the process tree.
// ---------------------------------------------------------------------
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	__u32 parent_pid = ctx->parent_pid;
	if (is_self(parent_pid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_FORK;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->ppid = parent_pid;
	e->pid = ctx->child_pid; // the newly created pid

	unsigned int comm_off = ctx->__data_loc_child_comm & 0xFFFF;
	bpf_probe_read_str(&e->comm, sizeof(e->comm), (void *)ctx + comm_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---------------------------------------------------------------------
// sched_process_exec — execve()/execveat() completion, gives us the
// resolved binary path plus fresh comm/uid for the new image.
// ---------------------------------------------------------------------
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (is_self(pid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_EXEC;
	e->timestamp_ns = bpf_ktime_get_ns();
	fill_identity(e);

	unsigned int fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---------------------------------------------------------------------
// sched_process_exit — process teardown, closes the timeline.
// ---------------------------------------------------------------------
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	// only report the group-leader exit (thread exits are noisy and not
	// interesting for a process-level provenance/timeline view).
	__u32 pid = BPF_CORE_READ(task, tgid);
	__u32 tid = BPF_CORE_READ(task, pid);
	if (pid != tid)
		return 0;
	if (is_self(pid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_EXIT;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->exit_code = (__u32)BPF_CORE_READ(task, exit_code) >> 8;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---------------------------------------------------------------------
// security_file_open — fires on every file open (LSM hook point, but we
// attach via fentry since we're observational only, not enforcing). This
// is what lets us answer "who wrote/read this path, and when" for the
// provenance graph.
// ---------------------------------------------------------------------
SEC("fentry/security_file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (is_self(pid))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_FILE_OPEN;
	e->timestamp_ns = bpf_ktime_get_ns();
	fill_identity(e);

	long n = bpf_d_path((struct path *)&file->f_path, e->filename, sizeof(e->filename));
	if (n < 0) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// ---------------------------------------------------------------------
// tcp_v4_connect / tcp_v6_connect — outbound connection attempts. Hooked
// on entry so we read the destination straight from the sockaddr the
// caller supplied, before connect() has a chance to fail or block.
// ---------------------------------------------------------------------
SEC("fentry/tcp_v4_connect")
int BPF_PROG(handle_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (is_self(pid))
		return 0;
	if (addr_len < (int)sizeof(struct sockaddr_in))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_CONNECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	fill_identity(e);
	e->family = PROVCTL_AF_INET;

	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	bpf_core_read(&e->daddr_v4, sizeof(e->daddr_v4), &addr->sin_addr.s_addr);
	__u16 dport_be;
	bpf_core_read(&dport_be, sizeof(dport_be), &addr->sin_port);
	e->dport = bpf_ntohs(dport_be);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(handle_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	if (is_self(pid))
		return 0;
	if (addr_len < (int)sizeof(struct sockaddr_in6))
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EVENT_CONNECT;
	e->timestamp_ns = bpf_ktime_get_ns();
	fill_identity(e);
	e->family = PROVCTL_AF_INET6;

	struct sockaddr_in6 *addr = (struct sockaddr_in6 *)uaddr;
	bpf_core_read(&e->daddr_v6, sizeof(e->daddr_v6), &addr->sin6_addr.in6_u.u6_addr8);
	__u16 dport_be;
	bpf_core_read(&dport_be, sizeof(dport_be), &addr->sin6_port);
	e->dport = bpf_ntohs(dport_be);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
