#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ROUTER_ID, TUNNEL_NET and TUNNEL_MASK are host-order IPv4 values passed with -D */

#define IPPROTO_OSPF 89
#define OSPF_HEADER_LEN 24
#define OSPF_LS_UPDATE 4
#define LSA_HEADER_LEN 20
#define LSA_ROUTER_BODY_LEN 4
#define ROUTER_LINK_LEN 12
#define LSA_TYPE_ROUTER 1
#define LINK_TYPE_P2P 1
#define LINK_TYPE_STUB 3
#define MAX_LSAS 4
#define MAX_LINKS 4
#define IP_MF_OR_OFFSET 0x3fff

enum drop_reason {
    DROP_MALFORMED,
    DROP_FRAGMENT,
    DROP_LSA_COUNT,
    DROP_LSA_TYPE,
    DROP_LSA_ORIGIN,
    DROP_LSA_FLAGS,
    DROP_LSA_LENGTH,
    DROP_LINK_TYPE,
    DROP_FOREIGN_STUB,
    DROP_P2P_COUNT,
    DROP_REASON_MAX,
};

/* iproute2's tc loader reads only this legacy map layout, not BTF-defined maps. */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

struct bpf_elf_map SEC("maps") drop_counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(__u32),
    .size_value = sizeof(__u64),
    .max_elem = DROP_REASON_MAX,
};

static __always_inline int drop(enum drop_reason reason)
{
    __u32 key = reason;
    __u64 *counter = bpf_map_lookup_elem(&drop_counters, &key);

    if (counter)
        __sync_fetch_and_add(counter, 1);
    return TC_ACT_SHOT;
}

/* Offsets are relative to the IPv4 header: gre1 egress has no L2 header. */
static __always_inline int load(struct __sk_buff *skb, __u32 offset, void *to, __u32 len)
{
    return bpf_skb_load_bytes_relative(skb, offset, to, len, BPF_HDR_START_NET);
}

/* Returns 0 when the LSA is the watcher's own minimal Router LSA, else a drop reason + 1. */
static __always_inline int check_router_lsa(struct __sk_buff *skb, __u32 offset, __u32 end, __u32 *lsa_len)
{
    struct {
        __u16 age;
        __u8 options;
        __u8 type;
        __u32 id;
        __u32 adv_router;
        __u32 seq;
        __u16 checksum;
        __u16 length;
        __u8 flags;
        __u8 zero;
        __u16 num_links;
    } __attribute__((packed)) lsa;
    __u32 length;
    __u32 num_links;
    __u32 p2p_links = 0;

    if (load(skb, offset, &lsa, sizeof(lsa)))
        return DROP_MALFORMED + 1;
    if (lsa.type != LSA_TYPE_ROUTER)
        return DROP_LSA_TYPE + 1;
    if (bpf_ntohl(lsa.id) != ROUTER_ID || bpf_ntohl(lsa.adv_router) != ROUTER_ID)
        return DROP_LSA_ORIGIN + 1;
    if (lsa.flags)
        return DROP_LSA_FLAGS + 1;

    length = bpf_ntohs(lsa.length);
    num_links = bpf_ntohs(lsa.num_links);
    if (num_links > MAX_LINKS)
        return DROP_LSA_LENGTH + 1;
    if (length != LSA_HEADER_LEN + LSA_ROUTER_BODY_LEN + num_links * ROUTER_LINK_LEN)
        return DROP_LSA_LENGTH + 1;
    if (offset + length > end)
        return DROP_MALFORMED + 1;

#pragma unroll
    for (int index = 0; index < MAX_LINKS; index++) {
        struct {
            __u32 link_id;
            __u32 link_data;
            __u8 type;
            __u8 tos_count;
            __u16 metric;
        } __attribute__((packed)) link;

        if (index >= num_links)
            break;
        if (load(skb, offset + LSA_HEADER_LEN + LSA_ROUTER_BODY_LEN + index * ROUTER_LINK_LEN, &link, sizeof(link)))
            return DROP_MALFORMED + 1;
        if (link.tos_count)
            return DROP_LSA_LENGTH + 1;
        if (link.type == LINK_TYPE_P2P) {
            p2p_links++;
            continue;
        }
        if (link.type != LINK_TYPE_STUB)
            return DROP_LINK_TYPE + 1;
        if (bpf_ntohl(link.link_id) != TUNNEL_NET || bpf_ntohl(link.link_data) != TUNNEL_MASK)
            return DROP_FOREIGN_STUB + 1;
    }
    if (p2p_links > 1)
        return DROP_P2P_COUNT + 1;
    *lsa_len = length;
    return 0;
}

SEC("tc")
int announcement_filter(struct __sk_buff *skb)
{
    struct iphdr ip;
    struct {
        __u8 version;
        __u8 type;
        __u16 length;
    } __attribute__((packed)) ospf;
    __u32 ip_header_len;
    __u32 ospf_end;
    __u32 num_lsas;
    __u32 offset;

    if (load(skb, 0, &ip, sizeof(ip)))
        return TC_ACT_OK;
    if (ip.protocol != IPPROTO_OSPF)
        return TC_ACT_OK;

    ip_header_len = ip.ihl * 4;
    if (ip.version != 4 || ip_header_len < sizeof(ip))
        return drop(DROP_MALFORMED);
    if (bpf_ntohs(ip.frag_off) & IP_MF_OR_OFFSET)
        return drop(DROP_FRAGMENT);
    if (load(skb, ip_header_len, &ospf, sizeof(ospf)))
        return drop(DROP_MALFORMED);
    if (ospf.type != OSPF_LS_UPDATE)
        return TC_ACT_OK;

    /* the MD5 digest trailer sits after the OSPF length and is not LSA data */
    ospf_end = ip_header_len + bpf_ntohs(ospf.length);
    if (ospf_end > bpf_ntohs(ip.tot_len))
        return drop(DROP_MALFORMED);
    offset = ip_header_len + OSPF_HEADER_LEN;
    if (offset + 4 > ospf_end)
        return drop(DROP_MALFORMED);
    if (load(skb, offset, &num_lsas, sizeof(num_lsas)))
        return drop(DROP_MALFORMED);
    num_lsas = bpf_ntohl(num_lsas);
    if (num_lsas < 1 || num_lsas > MAX_LSAS)
        return drop(DROP_LSA_COUNT);
    offset += 4;

    for (int index = 0; index < MAX_LSAS; index++) {
        __u32 lsa_len = 0;
        int verdict;

        if (index >= num_lsas)
            break;
        verdict = check_router_lsa(skb, offset, ospf_end, &lsa_len);
        if (verdict)
            return drop(verdict - 1);
        offset += lsa_len;
    }
    if (offset != ospf_end)
        return drop(DROP_MALFORMED);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
