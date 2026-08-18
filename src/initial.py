#!/usr/bin/env python3
from bcc import BPF
from pyroute2 import IPRoute
import datetime
import sys
import atexit

# CHANGED: Target loopback ('lo') where systemd-resolved handles local DNS
INTERFACE = "lo" 

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct bpf_timer {
    u64 :64;
    u64 :64;
};
#ifndef BPF_PSEUDO_FUNC
#define BPF_PSEUDO_FUNC 4
#endif
#ifndef BPF_F_BROADCAST
#define BPF_F_BROADCAST (1ull << 3)
#endif

#include <net/sock.h>
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

struct app_state_t {
    u64 app_start;
    u64 sock_start;
    u64 sock_end;
    u16 src_port;
    char domain[128];
};

struct wire_state_t {
    u64 wire_start;
    u64 wire_end;
};

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char domain[128];
    u64 app_latency_ns;
    u64 sock_latency_ns;
    u64 wire_latency_ns;
};

BPF_HASH(app_map, u32, struct app_state_t);
BPF_HASH(wire_map, u16, struct wire_state_t);
BPF_PERCPU_ARRAY(event_scratch, struct event_t, 1);
BPF_PERF_OUTPUT(events);

/* LAYER 1: UPROBE (Smart filter to ignore service-only lookups like 'https') */
int trace_getaddrinfo_entry(struct pt_regs *ctx) {
    const char *node = (const char *)PT_REGS_PARM1(ctx);
    if (!node) return 0; // Ignore if node is NULL (service-only lookup)
    
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct app_state_t s = {};
    
    s.app_start = bpf_ktime_get_ns();
    
    // Safely check if string starts with letters/numbers, ignore if it's a port/service
    char first_char = 0;
    bpf_probe_read_user(&first_char, 1, node);
    if (first_char == ':' || (first_char >= '0' && first_char <= '9')) {
        return 0; 
    }

    bpf_probe_read_user_str(&s.domain, sizeof(s.domain), (void *)node);
    
    // Filter out accidental service lookups[]
    if (s.domain[0] == 'h' && s.domain[1] == 't' && s.domain[2] == 't' && s.domain[3] == 'p') {
        return 0;
    }

    app_map.update(&pid, &s);
    return 0;
}

/* LAYER 2: KPROBE */
int trace_udp_sendmsg(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct app_state_t *s = app_map.lookup(&pid);
    if (s) {
        s->sock_start = bpf_ktime_get_ns();
        struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
        u16 sport = 0;
        bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        s->src_port = sport; 
    }
    return 0;
}

/* LAYER 3: TC EGRESS (Captures local loopback packet to 127.0.0.53) */
int tc_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    // Check port 53 (DNS / systemd-resolved stub)
    if (udp->dest == bpf_htons(53)) {
        u16 sport = bpf_ntohs(udp->source);
        struct wire_state_t w = {};
        w.wire_start = bpf_ktime_get_ns();
        wire_map.update(&sport, &w);
    }
    return TC_ACT_OK;
}

/* LAYER 3: TC INGRESS */
int tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    if (udp->source == bpf_htons(53)) {
        u16 dport = bpf_ntohs(udp->dest);
        struct wire_state_t *w = wire_map.lookup(&dport);
        if (w) {
            w->wire_end = bpf_ktime_get_ns();
        }
    }
    return TC_ACT_OK;
}

/* LAYER 2: KRETPROBE */
int trace_udp_recvmsg_ret(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct app_state_t *s = app_map.lookup(&pid);
    if (s && s->sock_start > 0) {
        s->sock_end = bpf_ktime_get_ns();
    }
    return 0;
}

/* LAYER 1: URETPROBE */
int trace_getaddrinfo_return(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct app_state_t *s = app_map.lookup(&pid);
    
    if (s) {
        u32 zero = 0;
        struct event_t *event = event_scratch.lookup(&zero);
        if (event) {
            event->pid = pid;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(&event->domain, s->domain, sizeof(event->domain));
            
            event->app_latency_ns = bpf_ktime_get_ns() - s->app_start;
            event->sock_latency_ns = (s->sock_end > s->sock_start) ? (s->sock_end - s->sock_start) : 0;
            
            struct wire_state_t *w = wire_map.lookup(&s->src_port);
            event->wire_latency_ns = (w && w->wire_end > w->wire_start) ? (w->wire_end - w->wire_start) : 0;
            
            events.perf_submit(ctx, event, sizeof(*event));
            
            if (s->src_port > 0) wire_map.delete(&s->src_port);
        }
        app_map.delete(&pid);
    }
    return 0;
}
"""

print(f"Compiling Full-Stack eBPF program on interface: {INTERFACE}...")
try:
    b = BPF(text=bpf_text)
    b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo_entry")
    b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo_return")
    b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
    b.attach_kretprobe(event="udp_recvmsg", fn_name="trace_udp_recvmsg_ret")
    
    ip = IPRoute()
    if_idx = ip.link_lookup(ifname=INTERFACE)[0]
    
    try:
        ip.tc("add", "clsact", if_idx)
    except Exception as e:
        if e.code != 17:
            raise
            
    fn_egress = b.load_func("tc_egress", BPF.SCHED_CLS)
    fn_ingress = b.load_func("tc_ingress", BPF.SCHED_CLS)
    
    ip.tc("add-filter", "bpf", if_idx, ":1", fd=fn_ingress.fd, name=fn_ingress.name, parent="ffff:fff2", classid=1, direct_action=True)
    ip.tc("add-filter", "bpf", if_idx, ":1", fd=fn_egress.fd, name=fn_egress.name, parent="ffff:fff3", classid=1, direct_action=True)
    
    def cleanup():
        print(f"\nCleaning up TC hooks on {INTERFACE}...")
        ip.tc("del", "clsact", if_idx)
    atexit.register(cleanup)

except Exception as e:
    print(f"\n[!] Failed to load eBPF program: {e}")
    sys.exit(1)

LOG_FILE = "dns_3layer.log"
header = f"{'TIMESTAMP':<24} {'PID':<8} {'COMM':<16} {'APP LAT(ms)':<15} {'SOCK LAT(ms)':<15} {'WIRE LAT(ms)':<15} {'DOMAIN'}"

print(f"Logging Full-Stack latency to {LOG_FILE}...\n" + "-" * 115 + "\n" + header + "\n" + "-" * 115)

with open(LOG_FILE, "w") as f:
    f.write(header + "\n" + "-" * 115 + "\n")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    
    app_ms = event.app_latency_ns / 1000000.0
    sock_ms = event.sock_latency_ns / 1000000.0
    wire_ms = event.wire_latency_ns / 1000000.0
    
    domain = event.domain.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')
    
    if sock_ms == 0 and wire_ms == 0:
        sock_disp = "[CACHE HIT]"
        wire_disp = "[CACHE HIT]"
    else:
        sock_disp = f"{sock_ms:.2f}"
        wire_disp = f"{wire_ms:.2f}"
        
    row = f"{timestamp:<24} {event.pid:<8} {comm:<16} {app_ms:<15.2f} {sock_disp:<15} {wire_disp:<15} {domain}"
    print(row)
    with open(LOG_FILE, "a") as f:
        f.write(row + "\n")

b["events"].open_perf_buffer(print_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    pass