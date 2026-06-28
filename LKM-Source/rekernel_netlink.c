/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_netlink.c
 * Description: Re:Kernel netlink transport. Generic Netlink by default; raw
 *              netlink (fixed units, USER_PORT, /proc discovery) when
 *              LEGACY_NETLINK is defined. Builds/multicasts event strings to
 *              userspace and receives MONITOR_NET commands.
 */
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/genetlink.h>
#include "rekernel_internal.h"

extern struct net init_net;

#ifdef LEGACY_NETLINK
#define NETLINK_REKERNEL_MAX			26
#define NETLINK_REKERNEL_MIN			22
static struct sock *netlink_socket = NULL;
static int netlink_unit = NETLINK_REKERNEL_MIN;
/* /proc/rekernel only exists for legacy netlink-unit discovery; genl resolves by family name. */
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;

/* Raw-netlink transport is ready once the kernel socket exists. */
bool rekernel_netlink_ready(void)
{
	return netlink_socket != NULL;
}
#else
/* Generic-netlink transport. The family is defined below and registered at init. */
static bool rekernel_genl_registered = false;

bool rekernel_netlink_ready(void)
{
	return rekernel_genl_registered;
}

/* user -> kernel: add a uid to the network monitor hashmap. */
static int rekernel_genl_add_monitor_net(struct sk_buff *skb, struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_A_UID]);
#ifdef DEBUG
	pr_info("Re-Kernel monitorNet uid=%d\n", muid);
#endif
	net_uid_add(muid);
	return 0;
}

/* user -> kernel: remove a uid from the network monitor hashmap. */
static int rekernel_genl_del_monitor_net(struct sk_buff *skb, struct genl_info *info)
{
	uid_t muid;

	if (!info->attrs[REKERNEL_A_UID])
		return -EINVAL;

	muid = (uid_t)nla_get_u32(info->attrs[REKERNEL_A_UID]);
#ifdef DEBUG
	pr_info("Re-Kernel delMonitorNet uid=%d\n", muid);
#endif
	net_uid_del(muid);
	return 0;
}

static const struct nla_policy rekernel_genl_policy[REKERNEL_A_MAX + 1] = {
	[REKERNEL_A_MSG] = { .type = NLA_NUL_STRING, .len = PACKET_SIZE - 1 },
	[REKERNEL_A_UID] = { .type = NLA_U32 },
};

static const struct genl_ops rekernel_genl_ops[] = {
	{
		.cmd  = REKERNEL_C_ADD_MONITOR_NET,
		.doit = rekernel_genl_add_monitor_net,
	},
	{
		.cmd  = REKERNEL_C_DEL_MONITOR_NET,
		.doit = rekernel_genl_del_monitor_net,
	},
};

static const struct genl_multicast_group rekernel_genl_mcgrps[] = {
	{ .name = REKERNEL_GENL_MCGRP_NAME },
};

static struct genl_family rekernel_genl_family = {
	.name     = REKERNEL_GENL_FAMILY_NAME,
	.version  = REKERNEL_GENL_VERSION,
	.maxattr  = REKERNEL_A_MAX,
	.policy   = rekernel_genl_policy,
	.module   = THIS_MODULE,
	.ops      = rekernel_genl_ops,
	.n_ops    = ARRAY_SIZE(rekernel_genl_ops),
	.mcgrps   = rekernel_genl_mcgrps,
	.n_mcgrps = ARRAY_SIZE(rekernel_genl_mcgrps),
};
#endif /* LEGACY_NETLINK */

int sendMessage(char *packet_buffer, uint16_t len)
{
#ifdef LEGACY_NETLINK
    struct sk_buff *socket_buffer;
    struct nlmsghdr *netlink_hdr;

    socket_buffer = nlmsg_new(len, GFP_ATOMIC);
    if (!socket_buffer) {
        pr_err("netlink alloc failure!\n");
        return LINE_ERROR;
    }

    netlink_hdr = nlmsg_put(socket_buffer, 0, 0, netlink_unit, len, 0);
    if (netlink_hdr == NULL) {
        pr_err("nlmsg_put failaure!\n");
        nlmsg_free(socket_buffer);
        return LINE_ERROR;
    }

    memcpy(nlmsg_data(netlink_hdr), packet_buffer, len);
    return netlink_unicast(netlink_socket, socket_buffer, USER_PORT, MSG_DONTWAIT);
#else
    struct sk_buff *socket_buffer;
    void *msg_head;
    int rc;

    socket_buffer = genlmsg_new(nla_total_size(len), GFP_ATOMIC);
    if (!socket_buffer) {
        pr_err("genlmsg alloc failure!\n");
        return LINE_ERROR;
    }

    msg_head = genlmsg_put(socket_buffer, 0, 0, &rekernel_genl_family, 0, REKERNEL_C_EVENT);
    if (msg_head == NULL) {
        pr_err("genlmsg_put failure!\n");
        nlmsg_free(socket_buffer);
        return LINE_ERROR;
    }

    if (nla_put(socket_buffer, REKERNEL_A_MSG, len, packet_buffer)) {
        genlmsg_cancel(socket_buffer, msg_head);
        nlmsg_free(socket_buffer);
        return LINE_ERROR;
    }

    genlmsg_end(socket_buffer, msg_head);

    /* genlmsg_multicast consumes socket_buffer; -ESRCH only means "no listeners". */
    rc = genlmsg_multicast(&rekernel_genl_family, socket_buffer, 0, 0, GFP_ATOMIC);
    if (rc && rc != -ESRCH) {
        pr_err("genlmsg_multicast failed, rc=%d\n", rc);
        return LINE_ERROR;
    }

    return LINE_SUCCESS;
#endif
}

#ifdef LEGACY_NETLINK
static void netlink_rcv_msg(struct sk_buff *socket_buffer)
{
	struct nlmsghdr *nlhdr;
	struct rekernel_cmd *cmd;

	if (socket_buffer->len < nlmsg_total_size(sizeof(struct rekernel_cmd)))
		return;

	nlhdr = nlmsg_hdr(socket_buffer);
	cmd = NLMSG_DATA(nlhdr);

#ifdef DEBUG
	pr_info("Re-Kernel_netlink recv cmd type=%d\n", cmd->type);
#endif

	switch (cmd->type) {
	case REKERNEL_CMD_REMOVE_PROC:
		if (rekernel_unit_entry) {
			proc_remove(rekernel_unit_entry);
			rekernel_unit_entry = NULL;
		}
		if (rekernel_dir) {
			proc_remove(rekernel_dir);
			rekernel_dir = NULL;
		}
		break;
	case REKERNEL_CMD_ADD_MONITOR_NET:
	case REKERNEL_CMD_DEL_MONITOR_NET:
	{
		struct rekernel_monitor_net_args *args;
		uid_t muid;

		if (nlmsg_len(nlhdr) < sizeof(struct rekernel_cmd) + sizeof(struct rekernel_monitor_net_args)) {
#ifdef DEBUG
			pr_warn("Re-Kernel monitorNet error: payload too small\n");
#endif
			break;
		}
		args = (struct rekernel_monitor_net_args *)((char *)cmd + sizeof(struct rekernel_cmd));
		muid = (uid_t)args->uid;
#ifdef DEBUG
		pr_info("Re-Kernel %sMonitorNet uid=%d\n",
			cmd->type == REKERNEL_CMD_DEL_MONITOR_NET ? "del" : "", muid);
#endif
		if (cmd->type == REKERNEL_CMD_DEL_MONITOR_NET)
			net_uid_del(muid);
		else
			net_uid_add(muid);
		break;
	}
	default:
#ifdef DEBUG
		pr_warn("Re-Kernel unknown cmd type=%d\n", cmd->type);
#endif
		break;
	}
}

static struct netlink_kernel_cfg cfg = {
	.input = netlink_rcv_msg, // set recv callback
};

/* /proc/rekernel/<unit> exposes the chosen netlink unit for legacy daemon discovery. */
static int rekernel_unit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", netlink_unit);
	return 0;
}

static int rekernel_unit_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_unit_show, NULL);
}

static const struct proc_ops rekernel_unit_fops = {
	.proc_open   = rekernel_unit_open,
	.proc_read   = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release   = single_release,
};
#endif /* LEGACY_NETLINK */

int rekernel_netlink_start(void)
{
#ifdef LEGACY_NETLINK
	pr_info("Re:Kernel v9.5 | DEVELOPER: Sakion Team | USER PORT: %d\n", USER_PORT);
	pr_info("Trying to create Re:Kernel Server......\n");

	for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
		netlink_socket = (struct sock *)netlink_kernel_create(&init_net, netlink_unit, &cfg);
		if (netlink_socket != NULL)
			break;
	}

	if (netlink_socket == NULL) {
		pr_err("Failed to create Re:Kernel server!\n");
		return LINE_ERROR;
	}

	pr_info("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

	/* /proc/rekernel/<unit> is only needed for legacy netlink-unit discovery. */
	rekernel_dir = proc_mkdir("rekernel", NULL);
	if (!rekernel_dir)
		pr_err("create /proc/rekernel failed!\n");
	else {
		char buff[32];
		sprintf(buff, "%d", netlink_unit);
		rekernel_unit_entry = proc_create(buff,
			0644, rekernel_dir, &rekernel_unit_fops);
		if (!rekernel_unit_entry)
			pr_err("create rekernel unit failed!\n");
	}
#else
	pr_info("Re:Kernel v9.5 | DEVELOPER: Sakion Team | GENL FAMILY: %s\n", REKERNEL_GENL_FAMILY_NAME);
	pr_info("Trying to register Re:Kernel Generic Netlink family......\n");

	if (genl_register_family(&rekernel_genl_family) != 0) {
		pr_err("Failed to register Re:Kernel genl family!\n");
		return LINE_ERROR;
	}
	rekernel_genl_registered = true;

	pr_info("Registered Re:Kernel genl family! ID: %d\n", rekernel_genl_family.id);
#endif

	return LINE_SUCCESS;
}

void rekernel_netlink_stop(void)
{
#ifdef LEGACY_NETLINK
	netlink_kernel_release(netlink_socket);
#else
	if (rekernel_genl_registered) {
		genl_unregister_family(&rekernel_genl_family);
		rekernel_genl_registered = false;
	}
#endif
}
