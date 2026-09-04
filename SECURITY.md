# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in provctl, please report it privately rather than opening a public issue.

**Contact:** thefoulowl@proton.me

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce (a minimal repro is ideal)
- The affected version/commit
- Your kernel version and distro, if relevant (provctl's attack surface includes eBPF verifier behavior, which is kernel-version-sensitive)

You should expect an initial response within 5 business days. Please give a reasonable amount of time to address the issue before any public disclosure.

## Supported Versions

Only the latest tagged release is supported with security fixes.

## Scope and Threat Model

provctl loads eBPF programs into the kernel and requires root (or `CAP_BPF`+`CAP_PERFMON`) to run `provctl watch`. Relevant areas for security review:

- **eBPF probes** (`internal/bpf/provctl.bpf.c`) — kernel-side code; a bug here is a kernel-level bug. The verifier rejects unsafe programs at load time, but logic errors (e.g. reading attacker-influenced memory unsafely) are still possible within what the verifier permits.
- **Event decoding** (`internal/model`) — parses fixed-width byte records from the kernel; malformed or truncated records must fail closed (return an error), not panic or read out of bounds.
- **SQLite storage** (`internal/store`) — all queries are parameterized; if you find a path where untrusted data (a filename, comm string, etc.) reaches raw SQL, that's a vulnerability.
- **Privilege boundary** — `provctl trace`, `timeline`, and `ps` are designed to run unprivileged and only read the database `watch` already wrote. If any of them can be made to require or silently use elevated privileges, or to write to the database, that's out of design intent.
- **Not in scope:** the underlying kernel's eBPF verifier itself, or vulnerabilities that require an attacker who already has root (provctl does not claim to defend against a fully compromised host).

## Known Limitations (not vulnerabilities, but relevant context)

See [Known Limitations & Roadmap](https://github.com/thefoulowl/provctl/wiki/Known-Limitations-and-Roadmap) — in particular, provctl does not track file provenance by inode (path-string matching only), which means it can be evaded by an adversary who renames or moves files outside its view. This is a forensic accuracy limitation, not a security hole in provctl itself, but it's relevant if you're evaluating provctl as a detection tool.
