# ============================================================
# CloudLab eBPF/XDP Makefile
#
# Usage:
#
#   make setup
#   make build SRC=./kern_v1.c
#   make run SRC=./kern_v1.c IFACE=eno1
#   make measure
#   make stop IFACE=eno1
#   make status IFACE=eno1
#   make clean
#
# ============================================================

# -------------------------
# Configuration
# -------------------------

SRC ?= kern_v1.c
IFACE ?= eno1

# Automatically derive object filename from source filename
OBJ := $(basename $(notdir $(SRC))).o

CLANG ?= clang
LLVM_OBJDUMP ?= llvm-objdump
BPFTOOL ?= bpftool

CFLAGS := -O2 -g -target bpf

# ============================================================
# INITIAL SETUP
# ============================================================

.PHONY: setup

setup:
	@echo "========================================"
	@echo "Installing eBPF/XDP dependencies"
	@echo "========================================"

	sudo apt update

	sudo apt install -y \
		clang \
		llvm \
		libbpf-dev \
		linux-tools-common

	@echo ""
	@echo "Trying to install kernel-specific Linux tools..."
	sudo apt install -y linux-tools-$$(uname -r) 2>/dev/null || \
		echo "WARNING: linux-tools-$$(uname -r) unavailable."

	@echo ""
	@echo "========================================"
	@echo "Checking installation"
	@echo "========================================"

	$(CLANG) --version
	$(BPFTOOL) version || true

	@echo ""
	@echo "Kernel:"
	uname -r

	@echo ""
	@echo "Network interfaces:"
	ip -br link

	@echo ""
	@echo "========================================"
	@echo "Generating vmlinux.h"
	@echo "========================================"

	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

	@echo "Generated vmlinux.h"

# ============================================================
# BUILD
# ============================================================

.PHONY: build

build: vmlinux.h
	@echo "========================================"
	@echo "Building $(SRC)"
	@echo "========================================"

	$(CLANG) $(CFLAGS) \
		-c $(SRC) \
		-o $(OBJ)

	@echo ""
	@echo "Built: $(OBJ)"

	file $(OBJ)

# ============================================================
# ATTACH / RUN
# ============================================================

.PHONY: run

run: build
	@echo "========================================"
	@echo "Attaching XDP program"
	@echo "========================================"
	@echo "Source : $(SRC)"
	@echo "Object : $(OBJ)"
	@echo "Interface : $(IFACE)"
	@echo ""

	sudo ip link set dev $(IFACE) xdpgeneric obj $(OBJ) sec xdp

	@echo ""
	@echo "========================================"
	@echo "XDP program attached"
	@echo "========================================"

	ip -details link show $(IFACE)

# ============================================================
# DETACH
# ============================================================

.PHONY: stop

stop:
	@echo "Detaching XDP from $(IFACE)..."

	sudo ip link set dev $(IFACE) xdpgeneric off 2>/dev/null || \
	sudo ip link set dev $(IFACE) xdp off

	@echo ""
	@echo "Current status:"
	ip -details link show $(IFACE)

# ============================================================
# STATUS
# ============================================================

.PHONY: status

status:
	@echo "========================================"
	@echo "Interface: $(IFACE)"
	@echo "========================================"

	ip -details link show $(IFACE)

	@echo ""
	@echo "========================================"
	@echo "BPF networking attachments"
	@echo "========================================"

	sudo $(BPFTOOL) net show

# ============================================================
# MEASUREMENT / DEBUG OUTPUT
# ============================================================

.PHONY: measure

measure:
	@echo "========================================"
	@echo "eBPF trace output"
	@echo "========================================"
	@echo ""
	@echo "Run traffic from another terminal."
	@echo "Press Ctrl+C to stop."
	@echo ""

	sudo cat /sys/kernel/debug/tracing/trace_pipe

# ============================================================
# SHOW LOADED BPF PROGRAMS
# ============================================================

.PHONY: programs

programs:
	sudo $(BPFTOOL) prog list

# ============================================================
# INSPECT BPF OBJECT
# ============================================================

.PHONY: inspect

inspect: build
	$(LLVM_OBJDUMP) -S $(OBJ)

# ============================================================
# CLEAN
# ============================================================

.PHONY: clean

clean:
	rm -f *.o
	rm -f vmlinux.h

# ============================================================
# HELP
# ============================================================

.PHONY: help

help:
	@echo ""
	@echo "CloudLab eBPF/XDP Makefile"
	@echo ""
	@echo "Setup:"
	@echo "  make setup"
	@echo ""
	@echo "Build:"
	@echo "  make build SRC=kern_v1.c"
	@echo ""
	@echo "Run:"
	@echo "  make run SRC=kern_v1.c IFACE=eno1"
	@echo ""
	@echo "Measure/debug:"
	@echo "  make measure"
	@echo ""
	@echo "Status:"
	@echo "  make status IFACE=eno1"
	@echo ""
	@echo "Detach:"
	@echo "  make stop IFACE=eno1"
	@echo ""
	@echo "Inspect BPF instructions:"
	@echo "  make inspect SRC=kern_v1.c"
	@echo ""
	@echo "Loaded BPF programs:"
	@echo "  make programs"
	@echo ""
	@echo "Clean:"
	@echo "  make clean"
	@echo ""