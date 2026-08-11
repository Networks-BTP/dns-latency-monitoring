# CloudLab eBPF/XDP Makefile

A simple Makefile-based workflow for setting up an eBPF/XDP development environment on a CloudLab Ubuntu node, compiling eBPF programs, attaching them to a network interface, monitoring output, and detaching them.

## Requirements

- Ubuntu-based CloudLab node
- `sudo` access
- A BTF-enabled kernel with:
  ```bash
  /sys/kernel/btf/vmlinux
  ```
- A network interface to attach XDP to

The Makefile assumes `eno1` by default, but the interface can be changed with `IFACE`.

---

## Quick Start

### 1. Setup a fresh CloudLab node

```bash
make setup
```

This will:

- Update apt package lists
- Install Clang and LLVM
- Install libbpf development headers
- Install Linux tools
- Generate `vmlinux.h` from the running kernel's BTF
- Display basic environment information

---

### 2. Build an eBPF program

For example, if your source file is:

```text
kern_v1.c
```

run:

```bash
make build SRC=kern_v1.c
```

This produces:

```text
kern_v1.o
```

The source is compiled using:

```bash
clang -O2 -g -target bpf
```

---

### 3. Attach the XDP program

```bash
make run SRC=kern_v1.c IFACE=eno1
```

This:

1. Builds the program.
2. Attaches it using generic XDP (`xdpgeneric`).
3. Displays the interface status.

You can verify the attachment with:

```bash
make status IFACE=eno1
```

You should see something similar to:

```text
prog/xdp id XX
```

### SSH warning

If `eno1` is the interface being used for your SSH connection, this workflow is still usable for the current test program because it returns:

```c
return XDP_PASS;
```

However, be careful when experimenting with `XDP_DROP`, redirects, or programs that may cause packets to be discarded. A bad XDP program can terminate your SSH connection.

---

## Measuring / Debugging

For programs using:

```c
bpf_printk("Packet Received\n");
```

run:

```bash
make measure
```

This reads:

```text
/sys/kernel/debug/tracing/trace_pipe
```

Keep this running in one terminal.

Then generate traffic from another terminal:

```bash
ping -c 10 8.8.8.8
```

You should see messages such as:

```text
bpf_trace_printk: Packet Received
```

### Important

`make measure` is intended for **debugging**.

`bpf_printk()` should not be used for high-rate performance measurements because the tracing mechanism itself can add significant overhead and distort latency measurements.

For actual experiments, use a BPF ring buffer/perf buffer and a userspace collector instead.

---

## Detaching the Program

When finished:

```bash
make stop IFACE=eno1
```

This removes the XDP program from the interface.

Verify:

```bash
make status IFACE=eno1
```

There should no longer be an XDP program attached.

If necessary, the Makefile also attempts the standard XDP detach command as a fallback.

---

## Checking Loaded BPF Programs

To see currently loaded BPF programs:

```bash
make programs
```

This runs:

```bash
sudo bpftool prog list
```

To see networking-related BPF attachments:

```bash
make status IFACE=eno1
```

This also runs:

```bash
sudo bpftool net show
```

---

## Inspecting the Compiled Program

To inspect the generated BPF instructions:

```bash
make inspect SRC=kern_v1.c
```

This builds the program and runs:

```bash
llvm-objdump -S kern_v1.o
```

---

## Using a Different eBPF Program

You do not need to modify the Makefile.

For example, if you have:

```text
dns_latency.c
```

build it with:

```bash
make build SRC=dns_latency.c
```

Run it on `eno1`:

```bash
make run SRC=dns_latency.c IFACE=eno1
```

Or use another interface:

```bash
make run SRC=dns_latency.c IFACE=enp9s0
```

The object filename is automatically derived from the source filename.

For example:

```text
dns_latency.c
    ↓
dns_latency.o
```

---

## Useful Commands

### Setup

```bash
make setup
```

### Build

```bash
make build SRC=kern_v1.c
```

### Run

```bash
make run SRC=kern_v1.c IFACE=eno1
```

### Measure/debug

```bash
make measure
```

### Status

```bash
make status IFACE=eno1
```

### Detach

```bash
make stop IFACE=eno1
```

### List BPF programs

```bash
make programs
```

### Inspect generated BPF

```bash
make inspect SRC=kern_v1.c
```

### Clean generated files

```bash
make clean
```

### Show available Makefile commands

```bash
make help
```

---

## Current Test Program

A minimal XDP program for testing whether packets reach the eBPF hook looks like:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    bpf_printk("Packet Received\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
```

This program does not modify packets. It simply prints a trace message and returns `XDP_PASS`, allowing the packet to continue through the normal network stack.

---

## Workflow

The intended workflow is:

```text
Fresh CloudLab Node
        │
        ▼
   make setup
        │
        ├── Install Clang/LLVM
        ├── Install libbpf
        ├── Install Linux tools
        └── Generate vmlinux.h
        │
        ▼
   make build SRC=program.c
        │
        ▼
      program.o
        │
        ▼
   make run SRC=program.c IFACE=eno1
        │
        ▼
     XDP attached
        │
        ▼
     make measure
        │
        ▼
    Generate traffic
        │
        ▼
    Observe eBPF output
        │
        ▼
   make stop IFACE=eno1
```

---

## Troubleshooting

### `clang: command not found`

Run:

```bash
make setup
```

or verify:

```bash
clang --version
```

### `bpf/bpf_helpers.h: file not found`

The libbpf development headers are missing. On a node where you have sudo access:

```bash
sudo apt install libbpf-dev
```

Then retry:

```bash
make build SRC=kern_v1.c
```

### `bpftool: command not found`

Check:

```bash
uname -r
```

and try:

```bash
sudo apt install linux-tools-$(uname -r)
```

The exact package depends on the kernel running on the CloudLab node.

### `vmlinux.h` generation fails

Check:

```bash
ls -lh /sys/kernel/btf/vmlinux
```

If that file exists, try:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### XDP does not attach

Check:

```bash
ip -details link show eno1
sudo bpftool net show
```

Also verify that the source compiled successfully:

```bash
make build SRC=kern_v1.c
```

### SSH connection is lost

If you attach XDP to the interface carrying your SSH connection, a faulty program can block or redirect traffic. Use `XDP_PASS` during initial testing and avoid `XDP_DROP` on your SSH interface.

