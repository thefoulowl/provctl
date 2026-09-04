package engine

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-D__TARGET_ARCH_x86 -Wno-missing-declarations" Probes ../bpf/provctl.bpf.c -- -I../bpf
