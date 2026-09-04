GO      ?= go
CLANG   ?= clang
BPFTOOL ?= bpftool

.PHONY: all build generate vmlinux-header vet fmt test clean install

all: build

# Regenerates internal/bpf/vmlinux.h from the *running* kernel's BTF. Only
# needed when you change provctl.bpf.c and want to recompile it — the
# committed internal/engine/probes_x86_bpfel.{go,o} are already built and
# `make build` does not require this.
vmlinux-header:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > internal/bpf/vmlinux.h

# Recompiles the eBPF C and regenerates the Go bindings via bpf2go. Requires
# clang, libbpf headers (libbpf-devel / libbpf-dev), and vmlinux-header.
generate: vmlinux-header
	cd internal/engine && GOPACKAGE=engine $(GO) generate ./...

build:
	$(GO) build -o provctl ./cmd/provctl

vet:
	$(GO) vet ./...

fmt:
	gofmt -l .

test:
	$(GO) test ./...

install: build
	install -Dm755 provctl $(DESTDIR)/usr/bin/provctl

clean:
	rm -f provctl internal/bpf/vmlinux.h
