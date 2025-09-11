/* SPDX-License-Identifier: Apache-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} xsks_map SEC(".maps");

SEC("xdp")
int af_xdp_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* Bounds check for Ethernet header */
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    /* Check if this is our target EtherType */
    if (bpf_ntohs(eth->h_proto) == TARGET_ETHERTYPE) {
        /* Redirect to AF_XDP socket */
        return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
    }

    /* Let other packets pass through normally */
    return XDP_PASS;
}

char _license[] SEC("license") = "Apache-2.0";
