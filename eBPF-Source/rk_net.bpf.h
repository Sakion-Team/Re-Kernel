// SPDX-License-Identifier: GPL-2.0
#ifndef RK_NET_BPF_H
#define RK_NET_BPF_H

#include "rk_common.bpf.h"
#include <bpf/bpf_endian.h>

#ifdef RK_DEBUG_TRACE
#define RK_TRACE(...) bpf_printk(__VA_ARGS__)
#else
#define RK_TRACE(...) do {} while (0)
#endif

#define RK_IPPROTO_TCP       6
#define RK_NEXTHDR_HOP       0
#define RK_NEXTHDR_ROUTING   43
#define RK_NEXTHDR_FRAGMENT  44
#define RK_NEXTHDR_AUTH      51
#define RK_NEXTHDR_DEST      60
#define RK_NEXTHDR_MOBILITY  135
#define RK_V6_EXT_MAX        8

static __always_inline __u8 rd_u8(unsigned char *base, __u32 off)
{
	__u8 v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), base + off);
	return v;
}

static __always_inline __u16 rd_be16(unsigned char *base, __u32 off)
{
	__u16 v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), base + off);
	return bpf_ntohs(v);
}

struct rk_l4 {
	__u8  proto;
	__u32 hdr_len;    /* IP header length == transport-header offset */
	__u32 l4_total;   /* transport header + payload */
};

static __always_inline int rk_parse_ip(unsigned char *iph, struct rk_l4 *l4)
{
	__u8 vb = rd_u8(iph, 0);

	if ((vb >> 4) == 4) {
		l4->proto    = RK_PROTO_IPV4;
		l4->hdr_len  = (vb & 0x0f) * 4;
		l4->l4_total = rd_be16(iph, 2) - l4->hdr_len;
		return 0;
	}
	if ((vb >> 4) != 6)
		return -1;

	__u16 plen = rd_be16(iph, 4);
	__u8 nexthdr = rd_u8(iph, 6);
	__u32 off = 40;

#pragma unroll
	for (int i = 0; i < RK_V6_EXT_MAX; i++) {
		if (nexthdr == RK_IPPROTO_TCP) {
			l4->proto    = RK_PROTO_IPV6;
			l4->hdr_len  = off;
			l4->l4_total = plen - (off - 40);
			return 0;
		}
		if (nexthdr == RK_NEXTHDR_FRAGMENT) {
			nexthdr = rd_u8(iph, off);
			off += 8;
		} else if (nexthdr == RK_NEXTHDR_AUTH) {
			__u8 hlen = rd_u8(iph, off + 1);
			nexthdr = rd_u8(iph, off);
			off += (hlen + 2) * 4;
		} else if (nexthdr == RK_NEXTHDR_HOP || nexthdr == RK_NEXTHDR_ROUTING ||
			   nexthdr == RK_NEXTHDR_DEST || nexthdr == RK_NEXTHDR_MOBILITY) {
			__u8 hlen = rd_u8(iph, off + 1);
			nexthdr = rd_u8(iph, off);
			off += (hlen + 1) * 8;
		} else {
			return -1;
		}
	}
	return -1;
}

SEC("kprobe/sk_filter_trim_cap")
int BPF_KPROBE(rk_sk_filter, struct sock *sk, struct sk_buff *skb)
{
	unsigned char *iph, *tcph;
	struct rk_l4 l4;
	struct rk_event *e;
	__u32 uid, doff;
	__u8 flags;
	int data_len;
	bool syn, fin, rst;

	if (!sk || !skb)
		return 0;
	if (BPF_CORE_READ(sk, sk_protocol) != RK_IPPROTO_TCP)
		return 0;

	uid = BPF_CORE_READ(sk, sk_uid.val);
	RK_TRACE("rk_net: hit uid=%u", uid);
	if (uid < MIN_USERAPP_UID)
		return 0;
	if (!bpf_map_lookup_elem(&net_uid_map, &uid))
		return 0;

	iph = (unsigned char *)BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header);
	if (rk_parse_ip(iph, &l4) < 0)
		return 0;

	tcph = iph + l4.hdr_len;
	doff = (rd_u8(tcph, 12) >> 4) * 4;
	flags = rd_u8(tcph, 13);
	fin = flags & 0x01;
	syn = flags & 0x02;
	rst = flags & 0x04;

	data_len = (int)l4.l4_total - (int)doff;
	RK_TRACE("rk_net: uid=%u proto=%u dlen=%d doff=%u", uid, l4.proto, data_len, doff);
	if (data_len <= 0 && !syn && !fin && !rst)
		return 0;

	e = evt_reserve();
	if (!e) {
		RK_TRACE("rk_net: uid=%u RESERVE_FAIL", uid);
		return 0;
	}
	e->type               = RK_NETWORK;
	e->network.proto      = l4.proto;
	e->network.target_uid = uid;
	e->network.data_len   = data_len;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#endif
