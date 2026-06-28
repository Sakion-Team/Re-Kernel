/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_netfilter.c
 * Description: Re:Kernel inbound-network monitor. Netfilter LOCAL_IN hooks fire
 *              for every inbound packet but only emit an event for uids the
 *              userspace daemon opted in via MONITOR_NET (RCU hashmap below).
 */
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/rtnetlink.h>
#include "rekernel_internal.h"

/* hashmap for net monitor uids */
#define REKERNEL_NET_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_net_uid_map, REKERNEL_NET_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

static DEFINE_MUTEX(rekernel_net_uid_mutex);

static bool net_uid_monitored(uid_t uid)
{
	struct uid_info *entry;

	hash_for_each_possible_rcu(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid)
			return true;
	}
	return false;
}

/* add a uid to the monitor map (no-op if already present). Caller must NOT hold the mutex. */
void net_uid_add(uid_t uid)
{
	mutex_lock(&rekernel_net_uid_mutex);
	if (!net_uid_monitored(uid)) {
		struct uid_info *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
		if (entry) {
			entry->uid = uid;
			hash_add_rcu(rekernel_net_uid_map, &entry->hnode, uid);
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

/* remove a uid from the monitor map. Caller must NOT hold the mutex. */
void net_uid_del(uid_t uid)
{
	struct uid_info *entry;

	mutex_lock(&rekernel_net_uid_mutex);
	hash_for_each_possible(rekernel_net_uid_map, entry, hnode, uid) {
		if (entry->uid == uid) {
			hash_del_rcu(&entry->hnode);
			kfree_rcu(entry, rcu);
			break;
		}
	}
	mutex_unlock(&rekernel_net_uid_mutex);
}

static inline uid_t line_sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	else
		return 0;
}

static unsigned int rekernel_pkg_ipv4_ipv6_in(void *priv, struct sk_buff *socket_buffer,
   const struct nf_hook_state *state)
{
  struct sock *sk;
  unsigned int thoff = 0;
  unsigned short frag_off = 0;
  uid_t uid;
  uint hook;
  struct net_device *dev = NULL;
  struct tcphdr *th;
  int data_len = 0;
  bool monitored;

  if (!socket_buffer || !socket_buffer->len || !state)
   return NF_ACCEPT;

  hook = state->hook;
  if (NF_INET_LOCAL_IN == hook)
   dev = state->in;

  if (NULL == dev)
   return NF_ACCEPT;

  sk = skb_to_full_sk(socket_buffer);
  if (sk == NULL || !sk_fullsock(sk))
   return NF_ACCEPT;

  uid = line_sock2uid(sk);
  if (uid < MIN_USERAPP_UID) return NF_ACCEPT;

  rcu_read_lock();
  monitored = net_uid_monitored(uid);
  rcu_read_unlock();
  if (!monitored) return NF_ACCEPT;

  if (ip_hdr(socket_buffer)->version == 4) {
   struct iphdr *iph4;
   unsigned int ip_hdr_len;

   if (!pskb_may_pull(socket_buffer, sizeof(struct iphdr))) {
    return NF_ACCEPT;
   }

   iph4 = ip_hdr(socket_buffer);
   if (iph4->protocol != IPPROTO_TCP) {
    return NF_ACCEPT;
   }

   ip_hdr_len = iph4->ihl << 2;
   if (!pskb_may_pull(socket_buffer, ip_hdr_len + sizeof(struct tcphdr))) {
    return NF_ACCEPT;
   }

   iph4 = ip_hdr(socket_buffer);
   th = (struct tcphdr *)((unsigned char *)iph4 + ip_hdr_len);
   data_len = ntohs(iph4->tot_len) - ip_hdr_len - (th->doff << 2);

#if IS_ENABLED(CONFIG_IPV6)
  } else if (ip_hdr(socket_buffer)->version == 6) {
   struct ipv6hdr *iph6;

   if (!pskb_may_pull(socket_buffer, sizeof(struct ipv6hdr))) {
    return NF_ACCEPT;
   }

   if (ipv6_find_hdr(socket_buffer, &thoff, -1, &frag_off, NULL) != IPPROTO_TCP) {
    return NF_ACCEPT;
   }

   if (!pskb_may_pull(socket_buffer, thoff + sizeof(struct tcphdr))) {
    return NF_ACCEPT;
   }

   iph6 = ipv6_hdr(socket_buffer);
   th = (struct tcphdr *)(skb_network_header(socket_buffer) + thoff);
   data_len = ntohs(iph6->payload_len) - (thoff - sizeof(struct ipv6hdr)) - (th->doff << 2);
#endif
  } else {
   return NF_ACCEPT;
  }

  if (data_len <= 0 && !th->syn && !th->fin && !th->rst)
   return NF_ACCEPT;

#ifdef DEBUG
  pr_info("[Re-Kernel LKM] Receive net data! target=%d\n", uid);
#endif
  if (rekernel_netlink_ready()) {
   char binder_kmsg[PACKET_SIZE];
   int len;
   if (ip_hdr(socket_buffer)->version == 4) {
    len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv4,data_len=%d;", uid, data_len);
#if IS_ENABLED(CONFIG_IPV6)
   } else if (ip_hdr(socket_buffer)->version == 6) {
    len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv6,data_len=%d;", uid, data_len);
#endif
   } else {
    return NF_ACCEPT;
   }
   sendMessage(binder_kmsg, len);
  }

  return NF_ACCEPT;
}

/* Only monitor input network packages */
static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook     = rekernel_pkg_ipv4_ipv6_in,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = rekernel_pkg_ipv4_ipv6_in,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	}
#endif
};

void unregister_netfilter(void)
{
	struct net *net;
	struct uid_info *entry;
	struct hlist_node *tmp;
	int bkt;

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
	}
	rtnl_unlock();

	synchronize_rcu();
	hash_for_each_safe(rekernel_net_uid_map, bkt, tmp, entry, hnode) {
		hash_del(&entry->hnode);
		kfree(entry);
	}
}

int register_netfilter(void)
{
	int rc = LINE_SUCCESS;
	struct net *net = NULL;

	hash_init(rekernel_net_uid_map);

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
		if (rc != LINE_SUCCESS) {
			pr_err("register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	rtnl_unlock();

	if (rc != LINE_SUCCESS) {
		unregister_netfilter();
		return LINE_ERROR;
	}

	return LINE_SUCCESS;
}
