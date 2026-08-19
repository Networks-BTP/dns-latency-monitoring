#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "dns_tracer.skel.h"

#define MAX_DNS_NAME_LEN 256

/* Must match xdp.h exactly. */
struct DNSQueryEvent {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t query_id;
    uint16_t query_type;
    uint16_t query_class;
    uint8_t  is_response;
    uint8_t  rcode;
    uint16_t answer_count;
    uint8_t  truncated;
    uint8_t  authoritative;
    uint8_t  raw_payload[512];   // Raw DNS payload, parsed on egress
};

/* Must match tc.h exactly. */
struct latency_event {
    uint64_t timestamp;
    uint64_t latency_ns;
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t query_id;
    uint16_t query_type;
    uint8_t  rcode;
    uint8_t  is_timeout;
    uint16_t answer_count;
    uint8_t  raw_payload[512];   // Raw DNS payload, parsed on ingress
};

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format,
                           va_list args)
{
    if (level == LIBBPF_WARN || level == LIBBPF_INFO) {
        vfprintf(stderr, format, args);
    }
    return 0;
}

static const char *dns_type_to_string(uint16_t type)
{
    switch (type) {
    case 1:  return "A";
    case 2:  return "NS";
    case 5:  return "CNAME";
    case 6:  return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    default: return "UNKNOWN";
    }
}

static const char *rcode_to_string(uint8_t rcode)
{
    switch (rcode) {
    case 0: return "NOERROR";
    case 1: return "FORMERR";
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 5: return "REFUSED";
    default: return "OTHER";
    }
}


/**
 * Parses a DNS name from a raw DNS payload.
 *
 * @param packet       Pointer to the start of the raw DNS header.
 * @param packet_len   Total length of the captured DNS payload.
 * @param offset       Pointer to the current byte offset (updated as bytes are consumed).
 * @param out_name     Buffer to store the null-terminated dotted domain string.
 * @param max_out      Maximum size of the out_name buffer.
 * @return             0 on success, -1 on a malformed packet or buffer overflow.
 */
int parse_dns_name(const uint8_t *packet, size_t packet_len, size_t *offset, char *out_name, size_t max_out) {
    size_t current_offset = *offset;
    size_t out_pos = 0;
    int jumped = 0;
    size_t jump_offset = 0;
    int jumps_taken = 0;

    if (max_out > 0) {
        out_name[0] = '\0';
    }

    while (current_offset < packet_len) {
        uint8_t len = packet[current_offset];

        // A length of 0 indicates the end of the domain name
        if (len == 0) {
            if (!jumped) {
                *offset = current_offset + 1;
            } else {
                *offset = jump_offset;
            }
            
            // Remove the trailing dot if we added one
            if (out_pos > 0) {
                out_name[out_pos - 1] = '\0';
            }
            return 0; // Success
        }

        // Check for a DNS compression pointer (top two bits set to 11, i.e., 0xC0)
        if ((len & 0xC0) == 0xC0) {
            if (current_offset + 1 >= packet_len) {
                return -1; // Malformed packet: pointer truncated
            }
            
            // If this is the first jump, record where we need to return to update the offset
            if (!jumped) {
                jump_offset = current_offset + 2;
                jumped = 1;
            }

            // Calculate the pointer offset (mask out the top 2 bits, combine with next byte)
            uint16_t pointer = ((len & 0x3F) << 8) | packet[current_offset + 1];
            current_offset = pointer;
            
            // Defend against malicious/malformed packets causing infinite pointer loops
            jumps_taken++;
            if (jumps_taken > 256) {
                return -1; 
            }
            continue;
        }

        // Standard label processing
        current_offset++;
        if (current_offset + len > packet_len) {
            return -1; // Malformed packet: label exceeds packet boundary
        }

        // Copy the label text into the output buffer and append a dot
        if (out_pos + len + 1 < max_out) {
            memcpy(out_name + out_pos, packet + current_offset, len);
            out_pos += len;
            out_name[out_pos++] = '.';
            out_name[out_pos] = '\0';
        } else {
            return -1; // Output buffer is too small
        }

        current_offset += len;
    }

    return -1; // Malformed packet: hit the end without finding a null terminator
}

static int handle_dns_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct DNSQueryEvent)) return 0;

    const struct DNSQueryEvent *event = data;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &event->src_ip, src, sizeof(src))) snprintf(src, sizeof(src), "?");
    if (!inet_ntop(AF_INET, &event->dst_ip, dst, sizeof(dst))) snprintf(dst, sizeof(dst), "?");

    // Parse domain name from raw payload (offset 12 skips 12-byte DNS header)
    char domain_name[MAX_DNS_NAME_LEN] = "<unknown>";
    size_t offset = 12;
    parse_dns_name(event->raw_payload, sizeof(event->raw_payload), &offset, domain_name, sizeof(domain_name));

    uint16_t qtype = event->query_type;
    if (qtype == 0 && offset + 2 <= sizeof(event->raw_payload)) {
        qtype = (event->raw_payload[offset] << 8) | event->raw_payload[offset + 1];
    }

    printf(
        "[XDP] %-8s %s:%u -> %s:%u "
        "id=%u type=%s name=%s rcode=%u(%s) answers=%u%s%s\n",
        event->is_response ? "RESPONSE" : "QUERY",
        src, event->src_port, dst, event->dst_port,
        event->query_id,
        dns_type_to_string(qtype),
        domain_name,
        event->rcode,
        rcode_to_string(event->rcode),
        event->answer_count,
        event->truncated ? " [TRUNCATED]" : "",
        event->authoritative ? " [AA]" : ""
    );

    fflush(stdout);
    return 0;
}

static int handle_latency_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct latency_event)) return 0;

    const struct latency_event *event = data;
    char client[INET_ADDRSTRLEN], server[INET_ADDRSTRLEN];

    if (!inet_ntop(AF_INET, &event->client_ip, client, sizeof(client))) snprintf(client, sizeof(client), "?");
    if (!inet_ntop(AF_INET, &event->server_ip, server, sizeof(server))) snprintf(server, sizeof(server), "?");

    // Parse domain name from raw payload
    char domain_name[MAX_DNS_NAME_LEN] = "<unknown>";
    size_t offset = 12;
    parse_dns_name(event->raw_payload, sizeof(event->raw_payload), &offset, domain_name, sizeof(domain_name));

    printf(
        "[TC ] %s -> %s "
        "id=%u type=%s name=%s latency=%.3f ms "
        "rcode=%u(%s) answers=%u\n",
        client, server,
        event->query_id,
        dns_type_to_string(event->query_type),
        domain_name,
        (double)event->latency_ns / 1000000.0,
        event->rcode,
        rcode_to_string(event->rcode),
        event->answer_count
    );

    fflush(stdout);
    return 0;
}

/*
 * Attach a SCHED_CLS BPF program to a legacy TC ingress/egress hook.
 *
 * This uses the bpf_tc_* API available in libbpf 0.5.0 rather than TCX.
 */
static int attach_tc_program(struct bpf_program *prog,
                             int ifindex,
                             enum bpf_tc_attach_point attach_point,
                             struct bpf_tc_hook *hook,
                             struct bpf_tc_opts *opts)
{
    int err;

    memset(hook, 0, sizeof(*hook));
    memset(opts, 0, sizeof(*opts));

    hook->sz = sizeof(*hook);
    hook->ifindex = ifindex;
    hook->attach_point = attach_point;

    err = bpf_tc_hook_create(hook);

    if (err && err != -EEXIST) {
        fprintf(stderr,
                "bpf_tc_hook_create(%s) failed: %d (%s)\n",
                attach_point == BPF_TC_INGRESS ? "ingress" : "egress",
                err,
                strerror(-err));
        return err;
    }

    opts->sz = sizeof(*opts);
    opts->prog_fd = bpf_program__fd(prog);

    if (attach_point == BPF_TC_INGRESS) {
        opts->handle = 1;
        opts->priority = 1;
    } else {
        opts->handle = 2;
        opts->priority = 1;
    }

    err = bpf_tc_attach(hook, opts);

    if (err) {
        fprintf(stderr,
                "bpf_tc_attach(%s) failed: %d (%s)\n",
                attach_point == BPF_TC_INGRESS ? "ingress" : "egress",
                err,
                strerror(-err));
        return err;
    }

    printf("  TC %s attached: handle=%u priority=%u\n",
           attach_point == BPF_TC_INGRESS ? "ingress" : "egress",
           opts->handle,
           opts->priority);

    return 0;
}

static int detach_tc_program(struct bpf_tc_hook *hook,
                             struct bpf_tc_opts *opts)
{
    struct bpf_tc_opts detach_opts = {};

    detach_opts.sz = sizeof(detach_opts);

    /*
     * bpf_tc_detach() requires ONLY:
     *   - handle
     *   - priority
     *
     * prog_fd, prog_id and flags must be zero.
     */
    detach_opts.handle = opts->handle;
    detach_opts.priority = opts->priority;

    int err = bpf_tc_detach(hook, &detach_opts);

    if (err) {
        /*
         * The filter may already have been removed.
         * Treat that as harmless during cleanup.
         */
        if (err == -ENOENT)
            return 0;

        fprintf(stderr,
                "Warning: bpf_tc_detach failed: %d (%s)\n",
                err,
                strerror(-err));
    }

    return err;
}

int main(int argc, char **argv)
{
    const char *ifname;
    unsigned int ifindex;

    struct dns_tracer_bpf *obj = NULL;
    struct bpf_link *xdp_link = NULL;
    struct ring_buffer *rb = NULL;

    struct bpf_tc_hook tc_ingress_hook;
    struct bpf_tc_opts tc_ingress_opts;

    struct bpf_tc_hook tc_egress_hook;
    struct bpf_tc_opts tc_egress_opts;

    bool tc_ingress_attached = false;
    bool tc_egress_attached = false;

    int err = 0;

    memset(&tc_ingress_hook, 0, sizeof(tc_ingress_hook));
    memset(&tc_ingress_opts, 0, sizeof(tc_ingress_opts));
    memset(&tc_egress_hook, 0, sizeof(tc_egress_hook));
    memset(&tc_egress_opts, 0, sizeof(tc_egress_opts));

    if (argc != 2) {
        fprintf(stderr, "Usage: sudo %s <interface>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s eno1\n", argv[0]);
        return 1;
    }

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        fprintf(stderr,
                "Interface '%s' not found: %s\n",
                ifname,
                strerror(errno));
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    printf("============================================\n");
    printf(" DNS Tracer\n");
    printf("============================================\n");
    printf("Interface : %s\n", ifname);
    printf("Ifindex   : %u\n\n", ifindex);

    obj = dns_tracer_bpf__open();
    if (!obj) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /*
    * libbpf 0.5.0 does not recognize the newer
    * SEC("tc/ingress") / SEC("tc/egress") sections.
    *
    * Both TC programs are therefore placed in the
    * legacy "classifier" section and explicitly marked
    * as BPF_PROG_TYPE_SCHED_CLS.
    */
    bpf_program__set_type(
        obj->progs.tc_dns_egress,
        BPF_PROG_TYPE_SCHED_CLS
    );

    bpf_program__set_type(
        obj->progs.tc_dns_ingress,
        BPF_PROG_TYPE_SCHED_CLS
    );

    err = dns_tracer_bpf__load(obj);
    if (err) {
        fprintf(stderr,
                "Failed to load BPF object: %d\n",
                err);
        goto cleanup;
    }

    printf("BPF object loaded.\n");

    /*
     * XDP attachment.
     *
     * Use the generic XDP mode on this older 5.15 CloudLab setup.
     * If native driver mode is desired later, this can be changed.
     */
    printf("Attaching XDP...\n");

    xdp_link = bpf_program__attach_xdp(
        obj->progs.xdp_dns_parser,
        ifindex
    );

    if (!xdp_link) {
        err = -errno;
        fprintf(stderr,
                "Failed to attach XDP: %d (%s)\n",
                err,
                strerror(-err));
        goto cleanup;
    }

    printf("  XDP attached.\n");

    /*
     * Legacy TC ingress.
     */
    printf("Attaching TC ingress...\n");

    err = attach_tc_program(
        obj->progs.tc_dns_ingress,
        (int)ifindex,
        BPF_TC_INGRESS,
        &tc_ingress_hook,
        &tc_ingress_opts
    );

    if (err) {
        fprintf(stderr, "Failed to attach TC ingress.\n");
        goto cleanup;
    }

    tc_ingress_attached = true;
    printf("  TC ingress attached.\n");

    /*
     * Legacy TC egress.
     */
    printf("Attaching TC egress...\n");

    err = attach_tc_program(
        obj->progs.tc_dns_egress,
        (int)ifindex,
        BPF_TC_EGRESS,
        &tc_egress_hook,
        &tc_egress_opts
    );

    if (err) {
        fprintf(stderr, "Failed to attach TC egress.\n");
        goto cleanup;
    }

    tc_egress_attached = true;
    printf("  TC egress attached.\n");

    /*
     * Create a single ring-buffer manager and register both maps.
     */
    printf("Creating ring-buffer manager...\n");

    rb = ring_buffer__new(
        bpf_map__fd(obj->maps.dns_events),
        handle_dns_event,
        NULL,
        NULL
    );

    if (!rb) {
        err = -errno;
        fprintf(stderr,
                "Failed to create XDP ring buffer: %d (%s)\n",
                err,
                strerror(-err));
        goto cleanup;
    }

    err = ring_buffer__add(
        rb,
        bpf_map__fd(obj->maps.latency_events),
        handle_latency_event,
        NULL
    );

    if (err) {
        fprintf(stderr,
                "Failed to add TC latency ring buffer: %d\n",
                err);
        goto cleanup;
    }

    printf("  XDP ring buffer added.\n");
    printf("  TC  ring buffer added.\n\n");

    printf("============================================\n");
    printf(" Tracer running\n");
    printf("============================================\n");
    printf("Listening for DNS events on %s...\n", ifname);
    printf("Press Ctrl+C to stop.\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR)
            break;

        if (err < 0) {
            fprintf(stderr,
                    "ring_buffer__poll failed: %d (%s)\n",
                    err,
                    strerror(-err));
            goto cleanup;
        }
    }

    err = 0;

cleanup:
    if (rb)
        ring_buffer__free(rb);

    /*
     * TC attachments are not BPF links with this older API, so
     * explicitly detach them.
     */
    if (tc_egress_attached)
        detach_tc_program(&tc_egress_hook, &tc_egress_opts);

    if (tc_ingress_attached)
        detach_tc_program(&tc_ingress_hook, &tc_ingress_opts);

    /*
     * Destroying the XDP BPF link detaches XDP.
     */
    if (xdp_link)
        bpf_link__destroy(xdp_link);

    /*
     * Destroy the TC qdisc hooks only after detaching our programs.
     * If another user/program is using the hook, failure here is
     * harmless and only results in a warning.
     */
    if (tc_egress_attached) {
        int tc_err = bpf_tc_hook_destroy(&tc_egress_hook);
        if (tc_err && tc_err != -ENOENT) {
            fprintf(stderr,
                    "Warning: failed to destroy TC egress hook: %d\n",
                    tc_err);
        }
    }

    if (tc_ingress_attached) {
        int tc_err = bpf_tc_hook_destroy(&tc_ingress_hook);
        if (tc_err && tc_err != -ENOENT) {
            fprintf(stderr,
                    "Warning: failed to destroy TC ingress hook: %d\n",
                    tc_err);
        }
    }

    if (obj)
        dns_tracer_bpf__destroy(obj);

    if (err)
        fprintf(stderr, "\nTracer exited with error %d.\n", err);
    else
        printf("\nTracer stopped.\n");

    return err ? 1 : 0;
}
