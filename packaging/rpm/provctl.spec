Name:           provctl
Version:        0.1.1
Release:        1%{?dist}
Summary:        eBPF process/file/network provenance tracker and flight recorder

License:        MIT
URL:            https://github.com/thefoulowl/provctl
Source0:        https://github.com/thefoulowl/provctl/archive/refs/tags/v%{version}.tar.gz

BuildRequires:  golang >= 1.25
Requires:       kernel >= 5.8

%description
provctl captures process, file, and network events via eBPF (CO-RE:
sched_process_fork/exec/exit, security_file_open, tcp_v4/v6_connect) and
persists them to SQLite, so you can later ask "where did this file come
from" (provctl trace) and "what did this process do" (provctl timeline).

The eBPF probes are precompiled and committed upstream, so building this
package only requires a Go toolchain, not clang/bpftool. Running
`provctl watch` requires root (or CAP_BPF+CAP_PERFMON) and a kernel
exposing BTF at /sys/kernel/btf/vmlinux.

%prep
%autosetup -n %{name}-%{version}

%build
CGO_ENABLED=0 go build -o provctl ./cmd/provctl

%install
install -Dm755 provctl %{buildroot}%{_bindir}/provctl
install -Dm644 packaging/systemd/provctl.service %{buildroot}%{_unitdir}/provctl.service
install -Dm644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -Dm644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md

%files
%{_bindir}/provctl
%{_unitdir}/provctl.service
%license LICENSE
%doc README.md

%post
%systemd_post provctl.service

%preun
%systemd_preun provctl.service

%postun
%systemd_postun_with_restart provctl.service

%changelog
* Fri Sep 04 2026 thefoulowl <thefoulowl@proton.me> - 0.1.1-1
- First installable release. 0.1.0 declared a Go toolchain constraint it
  could not satisfy and carried a pid-reuse misattribution bug; do not
  package it.

* Fri Sep 04 2026 thefoulowl <thefoulowl@proton.me> - 0.1.0-1
- Initial package.
