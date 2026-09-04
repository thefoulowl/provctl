// SPDX-License-Identifier: MIT
// provctl.h — event ABI shared between the eBPF probes (provctl.bpf.c) and
// the Go userspace ring-buffer reader (internal/engine). Keep this struct
// layout stable and explicit (fixed-width types, no implicit padding
// surprises) since both sides parse it independently.
#ifndef PROVCTL_H
#define PROVCTL_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 264

enum event_type {
	EVENT_EXEC = 1,
	EVENT_EXIT = 2,
	EVENT_FORK = 3,
	EVENT_FILE_OPEN = 4,
	EVENT_CONNECT = 5,
};

// address family tag used in event.family (mirrors AF_INET / AF_INET6)
#define PROVCTL_AF_INET 2
#define PROVCTL_AF_INET6 10

struct event {
	__u64 timestamp_ns; // CLOCK_MONOTONIC, ns since boot (bpf_ktime_get_ns)
	__u32 pid;			// thread-group id (userspace "pid")
	__u32 ppid;			// parent pid, 0 if unknown/unavailable
	__u32 uid;
	__u32 gid;
	__u32 exit_code; // EVENT_EXIT only
	__u32 daddr_v4;	 // EVENT_CONNECT only, network byte order
	__u8 daddr_v6[16]; // EVENT_CONNECT only, set when family == AF_INET6
	__u16 dport;	   // EVENT_CONNECT only, host byte order
	__u8 type;		   // enum event_type
	__u8 family;	   // PROVCTL_AF_INET / PROVCTL_AF_INET6, EVENT_CONNECT only
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN]; // exec path / opened path, best-effort
};

#endif // PROVCTL_H
