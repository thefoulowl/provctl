# provctl

[![CI](https://img.shields.io/github/actions/workflow/status/thefoulowl/provctl/ci.yml?branch=main&label=CI)](https://github.com/thefoulowl/provctl/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/thefoulowl/provctl.svg)](https://pkg.go.dev/github.com/thefoulowl/provctl)
[![License: MIT](https://img.shields.io/github/license/thefoulowl/provctl)](LICENSE)
[![Latest tag](https://img.shields.io/github/v/tag/thefoulowl/provctl)](https://github.com/thefoulowl/provctl/tags)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/thefoulowl)

An eBPF process/file/network **provenance tracker and flight recorder** for
Linux. One capture engine answers two questions:

- **"Where did this file come from?"** — `provctl trace <path>`
- **"What did this process do?"** — `provctl timeline <pid>`

![provctl demo: tracing a payload's provenance, then the live top dashboard](docs/assets/demo.gif)

The recording above runs real commands against a real, live `provctl watch`
on the developer's own machine — the output is genuine capture, not mocked
data. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how it's
reconstructed and what it can't yet track.

## How it works

Five eBPF hooks (`sched_process_{fork,exec,exit}`, `security_file_open`,
`tcp_v4_connect`/`tcp_v6_connect`) feed one ring buffer. A Go daemon decodes
that stream and persists it to SQLite. Every CLI command — `trace`,
`timeline`, `ps` — is a query over that same store; there's no separate
subsystem per feature. On startup `watch` also seeds the store from `/proc`,
so events from processes that were already running (your shell, your browser)
are attributed to a named process rather than a bare pid. Full write-up:
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

CO-RE (Compile Once – Run Everywhere) means the shipped, precompiled probes
attach against your running kernel's BTF without needing to recompile —
you only need a kernel exposing BTF at `/sys/kernel/btf/vmlinux` (default on
most distro kernels since ~5.8 / 2021).

## Install

```sh
git clone https://github.com/thefoulowl/provctl
cd provctl
go build -trimpath -o provctl ./cmd/provctl
sudo install -Dm755 provctl /usr/local/bin/provctl
```

This makes `provctl` available globally — for every user, and for `sudo` —
in one step: `/usr/local/bin` is both on a normal user's default `$PATH`
*and* in `sudo`'s `secure_path`. That second part is the one that actually
matters here: `sudo` resets `PATH` to its own fixed `secure_path` and
ignores your shell's, so `sudo provctl watch` (below) would not find the
binary if it only lived somewhere user-specific like `~/go/bin` — it has to
be installed to a system location like `/usr/local/bin` to work under
`sudo` at all.

No `clang`/`bpftool` needed to build — the compiled eBPF object and its Go
bindings are committed (`internal/engine/probes_x86_bpfel.{go,o}`). You only
need those tools if you're modifying `internal/bpf/provctl.bpf.c` itself
(see [Modifying the BPF probes](#modifying-the-bpf-probes)).

**Alternative: `go install`.** If you have Go set up and just want the
binary without cloning:

```sh
go install github.com/thefoulowl/provctl/cmd/provctl@latest
```

This puts it in `$(go env GOPATH)/bin` (usually `~/go/bin`) — make sure
that's on your `$PATH` for your own `provctl trace/timeline/ps` to resolve,
and note it will **not** work with `sudo provctl watch` for the reason
above (`~/go/bin` isn't in `secure_path`); either run
`sudo $(go env GOPATH)/bin/provctl watch`, or additionally copy/symlink the
binary into `/usr/local/bin` if you want the plain `sudo provctl watch`
form to work too.

Requires: Linux x86_64, kernel with BTF (`/sys/kernel/btf/vmlinux` must
exist), root or `CAP_BPF`+`CAP_PERFMON` to run `watch`.

## Usage

```sh
# 1. Start capturing (needs root):
sudo provctl watch

# 2. In another terminal, ask questions (no root needed):
provctl trace /home/you/Downloads/something.zip
provctl timeline 12345
provctl ps
provctl top    # live dashboard: process tree + scrolling activity feed
```

(If you skipped the `sudo install` step above: use `sudo ./provctl watch`
for step 1, and `./provctl trace/timeline/ps/top` for step 2.)

| Command | Needs root? | What it does |
|---|---|---|
| `provctl watch [--db path] [--quiet]` | yes | Attaches the probes, streams events to stdout, persists them to SQLite. |
| `provctl trace <path> [--db path]` | no | Reconstructs a file's provenance: who created it, who reopened it, who executed it, what that run did next. |
| `provctl timeline <pid> [--db path]` | no | Every recorded event for one process, merged and time-sorted. |
| `provctl ps [--db path] [--all]` | no | The recorded process tree (live only by default; `--all` includes exited processes). |
| `provctl top [--db path]` | no | A live TUI: process tree on the left, scrolling activity feed on the right — reads the same database `watch` is writing to, from a separate process. `tab` switches pane focus, `↑`/`↓`/`j`/`k`/page keys scroll, `q` quits. |

`watch`'s own scrolling output is colorized when attached to a terminal
(auto-plain when piped to a file or run under systemd/journald, and honors
`NO_COLOR`).

Database path defaults to `/var/lib/provctl/events.db`, override with
`--db` or `$PROVCTL_DB`. `trace`/`timeline`/`ps` only need read access to
that file — they don't touch eBPF at all.

## Modifying the BPF probes

```sh
sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel bpftool   # Fedora
# or: sudo apt install clang libbpf-dev bpftool                         # Debian/Ubuntu

make generate   # regenerates vmlinux.h from your kernel's BTF, recompiles
                # provctl.bpf.c, regenerates internal/engine/probes_x86_bpfel.{go,o}
make build
```

## Limitations

v1 matches file provenance by exact path string (no inode/rename tracking),
doesn't track dynamic library loads, and isn't container/namespace-aware.
Full list in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#known-limitations-v1).

## Support

If provctl is useful to you, a [coffee](https://www.buymeacoffee.com/thefoulowl)
helps keep it maintained.

## License

MIT — see [`LICENSE`](LICENSE).
