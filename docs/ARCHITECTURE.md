# Architecture

provctl is one capture engine with several query views on top of it. The
design goal: the kernel side stays dumb (capture + tag with identity, hand to
userspace), and every interesting question — "where did this file come
from", "what did this process do" — is a query over one durable event log,
not a separate subsystem.

```
                     kernel                          userspace
        ┌─────────────────────────────┐   ┌──────────────────────────────┐
        │ tp/sched_process_fork        │   │                              │
        │ tp/sched_process_exec        │   │  engine.Engine               │
        │ tp/sched_process_exit        │──▶│   - loads probes (bpf2go)    │
        │ fentry/security_file_open    │   │   - attaches all hooks       │
        │ fentry/tcp_v4_connect        │   │   - reads BPF ring buffer    │
        │ fentry/tcp_v6_connect        │   │   - decodes -> model.Event   │
        └──────────────┬────────────────┘   └───────────────┬──────────────┘
                        │ BPF ring buffer                    │
                        │ (struct event, provctl.h)          ▼
                        │                          ┌──────────────────────┐
                        │                          │ store.Store (SQLite) │
                        └─────────────────────────▶│  processes           │
                                                    │  file_events         │
                                                    │  net_events          │
                                                    │  activity_log        │
                                                    └──────────┬────────────┘
                                                               │
                            ┌──────────────────┬───────────────┼───────────────────┬──────────────────┐
                            ▼                  ▼               ▼                   ▼
                     `provctl trace`   `provctl timeline`  `provctl ps`      `provctl top`
                     file provenance    process flight      process tree     live TUI (separate
                                          recorder                            process, polls the
                                                                              same store)
```

## Why these five hooks

| Hook | Why |
|---|---|
| `sched_process_fork` | Parent → child edges. This is the process tree's backbone. |
| `sched_process_exec` | Resolves the binary path + fresh identity (comm/uid) after `execve()`. |
| `sched_process_exit` | Closes a process's timeline with an exit code. |
| `security_file_open` (fentry) | Fires on *every* file open — this is what lets `trace` answer "who touched this path, and when". Attached via fentry (observational), not as an LSM enforcement hook. |
| `tcp_v4_connect` / `tcp_v6_connect` (fentry) | Outbound connection attempts, read directly from the `sockaddr` the caller supplied — this is the "downloaded from" / "called out to" signal. |

CO-RE (Compile Once – Run Everywhere): the object is compiled against one
machine's `/sys/kernel/btf/vmlinux`, but field-offset relocations are
resolved at *load* time against whatever kernel provctl actually runs on.
That's what lets a single compiled binary run across kernel versions that
expose the same fields, without recompiling per-target.

## Event flow

0. At startup, `watch` snapshots `/proc` (`internal/procscan`) and seeds the
   store with one synthetic exec record per already-running process, using
   each process's real start time (`btime` + `starttime`). Without this, the
   first events a fresh daemon sees come from pids it never watched start —
   so `trace` could report that a path was opened but not by whom, which is
   the whole question it exists to answer. Most activity right after startup
   comes from long-lived processes (shells, browsers, desktop apps).
1. Each hook fills a `struct event` (`internal/bpf/provctl.h`) with a
   timestamp, identity (pid/ppid/uid/gid/comm), and a type-specific payload
   (exec path, opened path, or destination address), and submits it to a
   `BPF_RINGBUF` map.
2. `engine.Engine` (Go, via [cilium/ebpf](https://github.com/cilium/ebpf))
   reads the ring buffer and decodes each record by explicit byte offset —
   deliberately not relying on Go struct layout matching C struct layout,
   so the two representations can't silently drift apart without a hard
   decode error.
3. `store.Store` persists every event to SQLite: one `processes` row per
   process *lifetime* (keyed by `(pid, started_ns)` since pids get reused),
   plus append-only `file_events` and `net_events` logs. The database runs
   in WAL mode with `synchronous=NORMAL`, and `watch` batches events into
   one transaction per 150ms (or 256 events, whichever comes first) instead
   of committing each event individually — a single `execve()` can produce
   dozens of file-open events in the same millisecond, and per-event fsync
   would otherwise make the store the bottleneck.
4. The CLI subcommands are pure queries over that store:
   - **`trace <path>`** — find the earliest open of the path, the process
     that did it, and what that process connected to just before (the
     likely download source); then follow later opens (copy/extract) and
     any execution of the path, including what *that* process connected to
     or spawned.
   - **`timeline <pid>`** — merge that process's own start/exit with every
     file it opened, every connection it made, and every child it spawned,
     sorted by time.
   - **`ps`** — the process tree reconstructed from `processes.ppid`.
   - **`top`** — a live TUI (bubbletea/lipgloss) that polls the same store
     from a separate process while `watch` writes to it: a process tree
     (from `AllProcesses`, shared with `ps`'s rendering) alongside a
     scrolling `activity_log` feed. `activity_log` is a plain append-only
     table — one rendered line per live-observed event, via the same
     `model.Event.Describe()` `watch`'s own scrolling output uses — kept
     separate from `processes`/`file_events`/`net_events` specifically so
     `top` doesn't have to re-derive a chronological feed from tables whose
     rows mutate in place (a process's row is updated by EXEC, then again
     by EXIT). The `/proc` startup backfill (step 0 above) does **not**
     write to `activity_log` — those are synthetic, not live-observed, and
     logging hundreds of them at every `watch` startup would flood the feed.
     `top`'s incremental poll query is intentionally *not* capped at the
     same small limit as what's displayed: a single chatty process (a
     browser polling `/proc`, observed in testing generating 1000+ events
     well under a second) can otherwise outpace a tightly-bounded fetch,
     permanently widening the gap between the feed and "now" instead of
     catching up between bursts.

## Known limitations (v1)

- **No inode/rename tracking.** `trace` matches by exact path string. A file
  extracted or renamed to a new path shows up as an unrelated path, not a
  continuation of the same chain — the flagship "malware.zip → extracted →
  malware.exe" example only chains correctly if the tool watches the
  extraction happen (it opens both paths, so it *does* — but a `mv` outside
  provctl's view would break the link).
- **No library-load tracking.** Only the top-level `execve()` target is
  recorded, not `dlopen()`/dynamic linker activity.
- **PID reuse is handled, but coarsely.** `processes` is keyed by
  `(pid, started_ns)`, so distinct lifetimes of a recycled pid don't
  collide — but nothing currently prunes old rows, so the database grows
  without bound under `provctl watch`.
- **Requires root** (or `CAP_BPF` + `CAP_PERFMON`) and a kernel exposing BTF
  at `/sys/kernel/btf/vmlinux` (5.8+, most distro kernels since ~2021).
- **Single-host, no container/namespace awareness.** A `pid` is a host pid;
  events aren't tagged with cgroup or mount namespace, so container-to-
  container provenance isn't distinguished.
