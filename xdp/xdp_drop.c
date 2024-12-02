#include <linux/bpf.h> // define XDP program return code: XDP_PASS,..
#include <linux/ip.h> // iphdr
#include <linux/if_ether.h> // ethhdr, ETH_P_IP
#include <bpf/bpf_helpers.h> // SEC() macro.
#include <bpf/bpf_endian.h> // bpf_htons, convert a 32-bit integer value from network byte order to host byte order.
#include <stdint.h> // uint8_t
#include <stdbool.h>

// enable debug print
// #define DEBUG
// enable packet header dump
// #define DEBUG_PRINT_HEADER_SIZE 64

#define IP_PROTO_TYPE 0x0800 /*IP Proto*/
#define IPPROTO_GRE		47 /* Cisco GRE tunnels (rfc 1701,1702)	*/
#define IPPROTO_OSPF_IGP	89
#define OSPF_HEADER_SIZE         24U
#define OSPF_AUTH_SIMPLE_SIZE     8U
#define OSPF_DB_DESC_MIN_SIZE     8U
#define OSPF_LS_UPDATE     4 /* LS Update 4*/
#define OSPF_MAX_ALLOWED_LSA_NUM     1 /* only 1 LSA is allowed */
#define OSPF_ROUTER_LSA               1
#define OSPF_DB_DESCRIPTION            2
#define OSPF_LSA1_SUBTYPE_P2P_1        1
#define OSPF_LSA1_SUBTYPE_BROADCAST_2  2
#define MAX_LINK_ENTRIES 10
#pragma pack(1)
struct gre_header {
    __be16 flags_and_version;
    __be16 proto;
};
#pragma pack(1)
struct in_addr {
    uint8_t octet1;
    uint8_t octet2;
    uint8_t octet3;
    uint8_t octet4;
};

/* OSPF packet header structure. */
#pragma pack(1)
struct ospf_header {
	uint8_t version;	  /* OSPF Version. */
	uint8_t type;		  /* Packet Type. */
	uint16_t length;	  /* Packet Length. */
	__be32 router_id; /* Router ID. */
	struct in_addr area_id;   /* Area ID. */
	uint16_t checksum;	/* Check Sum. */
	uint16_t auth_type;       /* Authentication Type. */
	/* Authentication Data. */
	union {
		/* Simple Authentication. */
		uint8_t auth_data[OSPF_AUTH_SIMPLE_SIZE];
		/* Cryptographic Authentication. */
		struct {
			uint16_t zero;	 /* Should be 0. */
			uint8_t key_id;	/* Key ID. */
			uint8_t auth_data_len; /* Auth Data Length. */
			uint32_t crypt_seqnum; /* Cryptographic Sequence
						   Number. */
		} crypt;
	} u;
};

#pragma pack(1)
struct ospf_ls_update {
	uint32_t num_lsas;
};

/* OSPF LSA header. */
#pragma pack(1)
struct lsa_header {
	uint16_t ls_age;
#define DO_NOT_AGE 0x8000
	uint8_t options;
	uint8_t type;
	struct in_addr id;
	struct in_addr adv_router;
	uint32_t ls_seqnum;
	uint16_t checksum;
	uint16_t length;
};

#pragma pack(1)
struct lsa_tail {
	uint8_t flags;
    uint8_t zero;
	uint16_t num_links;
};

#pragma pack(1)
struct router_link {
    __be32 link_id; // in_addr
    __be32 link_data;
    uint8_t type;
    uint8_t tos;
    uint16_t metric;
};
#pragma pack(1)
/* OSPF Database Description body format. */
struct ospf_db_desc {
	uint16_t mtu;
	uint8_t options;
	uint8_t flags;
	uint32_t dd_seqnum;
};

SEC("xdp_drop")
int xdp_isis_tlv_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }
    // IP Header
    data += sizeof(struct ethhdr);
    #ifdef DEBUG
		bpf_printk("New packet\n");
	#endif

	// debug print packet header
    
	#if (defined DEBUG_PRINT_HEADER_SIZE) && (DEBUG_PRINT_HEADER_SIZE > 0)
		// check for out of boarder access is necessary, kernel will run static analysis on our program
		if ((data + DEBUG_PRINT_HEADER_SIZE) > data_end) {
			bpf_printk("Packet size too small, dump failed\n");
			return XDP_PASS;
		}
		__u8 *data_raw = (__u8 *)data;
		bpf_printk("Packet header dump:\n");
		#pragma unroll
		for (int i = 0; i < DEBUG_PRINT_HEADER_SIZE; ++i) {
			bpf_printk("#%d: %x\n", i, data_raw[i]);
		}
	#endif

    if ( eth->h_proto == bpf_htons(ETH_P_IP)) {

        if (data + sizeof(struct iphdr) > data_end) goto pass;

        struct iphdr *ip = (struct iphdr *)(data);
        if ((ip->protocol) != IPPROTO_GRE) goto pass;
        // GRE Header
        data += sizeof(struct iphdr);

        if (data + sizeof(struct gre_header) > data_end) goto pass;
        struct gre_header *gre = (struct gre_header *)(data);

        if ((gre->proto) != bpf_htons(IP_PROTO_TYPE)) goto pass;
        // IP
        data += sizeof(struct gre_header);
        if (data + sizeof(struct iphdr) > data_end) goto pass;

        struct iphdr *inner_ip = (struct iphdr *)(data);
        if ((inner_ip->protocol) != IPPROTO_OSPF_IGP) goto pass;
        // OSPF
        data += sizeof(struct iphdr);
        if (data + sizeof(struct ospf_header) > data_end) goto pass;
        struct ospf_header *o_header = (struct ospf_header *)(data);
        #ifdef DEBUG
            bpf_printk("OSPF header, message type: %d, router_id: %x\n", o_header->type, o_header->router_id);
        #endif

        if ((o_header->type != OSPF_LS_UPDATE) && (o_header->type != OSPF_DB_DESCRIPTION)) goto pass;
        if (o_header->type == OSPF_DB_DESCRIPTION) {
            // DB Description start
            data += sizeof(struct ospf_header);
            #ifdef DEBUG
                bpf_printk("DB description, %i\n", bpf_htons(o_header->length));
            #endif
            if (data + sizeof(struct ospf_db_desc) > data_end) {
                #ifdef DEBUG
                    bpf_printk("DB description doesn't have LSA");
                #endif
                goto pass;
            }
            struct ospf_db_desc * ospf_db_desc = (struct ospf_db_desc *)(data);
            int size = bpf_htons(o_header->length) - OSPF_HEADER_SIZE - OSPF_DB_DESC_MIN_SIZE;
            #ifdef DEBUG
                bpf_printk("DB description, mtu: %d, seq: %x\n", bpf_htons(ospf_db_desc->mtu), bpf_htonl(ospf_db_desc->dd_seqnum));
                bpf_printk("Left size: %i\n", size);
            #endif

            if (size == 0) goto pass;
            // DB Description end
            data += sizeof(struct ospf_db_desc);

            if (data + sizeof(struct lsa_header) > data_end) goto pass;
            struct lsa_header *lsah = (struct lsa_header *)(data);
            #ifdef DEBUG
                bpf_printk("LSU, length: %i, type: %i\n", bpf_htons(lsah->length), lsah->type);
            #endif
            
            if (lsah->type != OSPF_ROUTER_LSA) {
                // Watcher shouldn't generate any other LSA like Network, Summary or External ntohl
                bpf_printk("DDB DROP, it includes non LSA1 : %x\n", lsah->type);
                return XDP_DROP;
            };

            // advertise more than one LSA in DDB
            if (size - sizeof(struct lsa_header)) {
                bpf_printk("DDB DROP, it includes more than one LSA, bytes left: %d\n", size - sizeof(struct lsa_header));
                return XDP_DROP;
            }
        }
        else if (o_header->type == OSPF_LS_UPDATE) {
            // LS Update
            data += sizeof(struct ospf_header);
            if (data + sizeof(struct ospf_ls_update) > data_end) goto pass;
            // ospf_ls_upd https://github.com/FRRouting/frr/blob/172a2aa533a6fee4582951800105bff4dd6b3592/ospfd/ospf_packet.c#L1682
            // ospf_ls_upd_list_lsa

            struct ospf_ls_update *lsupd = (struct ospf_ls_update *)(data);
            #ifdef DEBUG
                bpf_printk("LSU, num_lsas: %x\n", bpf_htonl(lsupd->num_lsas));
            #endif
            if (bpf_htonl(lsupd->num_lsas) != OSPF_MAX_ALLOWED_LSA_NUM) {
                // Watcher shouldn't generate more than 1 LSA
                bpf_printk("LSA DROP, it has more than 1 LSA, num_lsas: %i\n", bpf_htonl(lsupd->num_lsas));
                return XDP_DROP;
            };
            // LSA Type
            data += sizeof(struct ospf_ls_update);
            if (data + sizeof(struct lsa_header) > data_end) goto pass;
            struct lsa_header *lsah = (struct lsa_header *)(data);
            
            if (lsah->type != OSPF_ROUTER_LSA) {
                // Watcher shouldn't generate any other LSA like Network, Summary or External ntohl
                bpf_printk("LSA DROP, it includes non LSA1 : %x\n", lsah->type);
                return XDP_DROP;
            };
            #ifdef DEBUG
                bpf_printk("LSA, OSPF_ROUTER_LSA: %x\n", lsah->type);
            #endif

            // LSA Header tail
            data += sizeof(struct lsa_header);
  
            if (data + sizeof(struct lsa_tail) > data_end) goto pass;
            struct lsa_tail *lsat = (struct lsa_tail *)(data);
            #ifdef DEBUG
                bpf_printk("LSA, num_links: %i\n", bpf_htons(lsat->num_links));
            #endif

            if (bpf_htons(lsat->num_links) > 2) {
                // Watcher shouldn't include mode than two links
                bpf_printk("LSA DROP, it includes more than two links : %x\n", bpf_htons(lsat->num_links));
                return XDP_DROP;
            };
            // int i, len, sum;
            // struct router_link *rlnk;
            // len = lsah->length - OSPF_LSA_HEADER_SIZE - 4;
            // rlnk = &lsat->num_links[0];
            // sum = 0;
            // for (i = 0; sum < len && rlnk; sum += 12, rlnk = &lsah->link[++i]) {
            //     bpf_printk("    Link ID %pI4", &rlnk->link_id);
            //     bpf_printk("    Link Data %pI4", &rlnk->link_data);
            //     bpf_printk("    Type %d", (uint8_t)rlnk->type);
            //     bpf_printk("    TOS %d", (uint8_t)rlnk->tos);
            //     bpf_printk("    metric %d", ntohs(rlnk->metric));
            // } 
            
            // LSA Links
            data += sizeof(struct lsa_tail);
            bool p2p_lsp_checked = false;
            for (int link_num = 0; link_num < MAX_LINK_ENTRIES; link_num++) {
                if (data + sizeof(struct router_link) > data_end) goto link_final_check;
                struct router_link *router_link = (struct router_link *)(data);
                #ifdef DEBUG
                    bpf_printk("LSA router_link: type %i, link_id %x, link_data %x\n", router_link->type, bpf_htonl(router_link->link_id), bpf_htonl(router_link->link_data));
                #endif
                if (router_link->type == OSPF_LSA1_SUBTYPE_P2P_1) {
                    p2p_lsp_checked = true;
                }
                else if (router_link->type == OSPF_LSA1_SUBTYPE_BROADCAST_2) {
                    // Watcher should generate only P2P + 1 Stub LSA
                    bpf_printk("LSA DROP, it has network type - broadcast, has to be p2p: %x\n", router_link->type);
                    return XDP_DROP;
                };
                data += sizeof(struct router_link);
            }
            link_final_check:
                if (!p2p_lsp_checked) {
                    bpf_printk("LSA DROP, it doesn't include P2P link type\n");
                    return XDP_DROP;
                }
                goto pass;
        }
    }


    return XDP_PASS;
pass:
	return XDP_PASS;
}

char _license[4] SEC("license") = "GPL";