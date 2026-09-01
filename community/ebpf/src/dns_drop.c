#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define MAX_DOMAINS 50000

// Hash map for blacklisted domains (hashed QNAME)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DOMAINS);
    __type(key, __u32); // 32-bit hash of the domain
    __type(value, __u8); // 1 = drop
} blocklist SEC(".maps");

// Simple DJB2 hash for DNS QNAMEs (simplified for demonstration)
static __always_inline __u32 hash_djb2(const unsigned char *str, int len) {
    __u32 hash = 5381;
    for (int i = 0; i < len && i < 255; i++) {
        hash = ((hash << 5) + hash) + str[i]; 
    }
    return hash;
}

SEC("xdp")
int xdp_dns_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    if (udp->dest != bpf_htons(53)) return XDP_PASS;

    // DNS Header parsing
    unsigned char *dns_payload = (unsigned char *)(udp + 1);
    if ((void *)(dns_payload + 12) > data_end) return XDP_PASS; // DNS Header is 12 bytes

    // Parse first QNAME (simplified: skipping full label parsing for performance, hashing first chunk)
    unsigned char *qname = dns_payload + 12;
    if ((void *)(qname + 1) > data_end) return XDP_PASS;
    
    int qname_len = qname[0];
    if ((void *)(qname + 1 + qname_len) > data_end || qname_len == 0) return XDP_PASS;

    __u32 hash = hash_djb2(qname + 1, qname_len);

    __u8 *action = bpf_map_lookup_elem(&blocklist, &hash);
    if (action && *action == 1) {
        bpf_printk("XDP_DROP: DNS Query Blocked (Hash: %u)\n", hash);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
