#include <linux/init.h>
#include <linux/types.h>

#include <net/sock.h>
#include <net/ip.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#endif /* IS_ENABLED(CONFIG_IPV6) */
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <linux/netfilter_ipv6.h>
#endif /* IS_ENABLED(CONFIG_IPV6) */

#include <linux/proc_fs.h>
#include <uapi/linux/android/binder.h>
#include "rekernel.h"

#define MIN_USERAPP_UID				10000
#define MAX_SYSTEM_UID				2000
#define SYSTEM_APP_UID				1000
#define INTERFACETOKEN_BUFF_SIZE	140
#define PARCEL_OFFSET				16
#define LINE_ERROR					1
#define LINE_SUCCESS				0

#define NETLINK_REKERNEL_MAX		26
#define NETLINK_REKERNEL_MIN		22
#define USER_PORT					100
#define PACKET_SIZE					256

static const char* binder_type[] = {
	"reply",
	"transaction",
	"free_buffer_full",
};
static const char* rpc_type[] = {
	"SYNC_BINDER_REPLY",
	"SYNC_BINDER",
	"FREE_BUFFER_FULL",
};
static struct sock* netlink_socket;
extern struct net init_net;
static unsigned long netlink_unit = 0;
#ifdef CONFIG_PROC_FS
static struct proc_dir_entry* rekernel_dir, * rekernel_unit_entry;
#endif /* CONFIG_PROC_FS */

static int sendMessage(char* packet_buffer, uint16_t len) {
	struct sk_buff* socket_buffer;
	struct nlmsghdr* netlink_hdr;

	socket_buffer = nlmsg_new(len, GFP_ATOMIC);
	if (!socket_buffer) {
		pr_err("netlink alloc failure.\n");
		return -LINE_ERROR;
	}

	netlink_hdr = nlmsg_put(socket_buffer, 0, 0, netlink_unit, len, 0);
	if (!netlink_hdr) {
		pr_err("nlmsg_put failaure.\n");
		nlmsg_free(socket_buffer);
		return -LINE_ERROR;
	}

	memcpy(nlmsg_data(netlink_hdr), packet_buffer, len);
	return netlink_unicast(netlink_socket, socket_buffer, USER_PORT, MSG_DONTWAIT);
}
static void netlink_rcv_msg(struct sk_buff* socket_buffer) {
	struct nlmsghdr* nlhdr = NULL;
	char* umsg = NULL;

	if (socket_buffer->len >= nlmsg_total_size(0)) {
		nlhdr = nlmsg_hdr(socket_buffer);
		umsg = nlmsg_data(nlhdr);
		if (umsg) {
#ifdef CONFIG_PROC_FS
			if (!memcmp(umsg, "#proc_remove", nlmsg_len(nlhdr))) {
				if (rekernel_dir) {
					proc_remove(rekernel_dir);
				}
			}
#endif /* CONFIG_PROC_FS */
		}
	}
}
#ifdef CONFIG_REKERNEL_NETWORK
static unsigned int rekernel_pkg_ipv4_ipv6_in(void* priv, struct sk_buff* socket_buffer,
	const struct nf_hook_state* state) {
	struct sock* sk;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	uid_t uid;
	uint hook;
	struct net_device* dev = NULL;

	if (!socket_buffer || !socket_buffer->len || !state)
		return NF_ACCEPT;

	hook = state->hook;
	if (NF_INET_LOCAL_IN == hook)
		dev = state->in;

	if (NULL == dev)
		return NF_ACCEPT;

	if (ip_hdr(socket_buffer)->version == 4) {
		if (ip_hdr(socket_buffer)->protocol != IPPROTO_TCP)
			return NF_ACCEPT;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_hdr(socket_buffer)->version == 6) {
		if (ipv6_find_hdr(socket_buffer, &thoff, -1, &frag_off, NULL) != IPPROTO_TCP)
			return NF_ACCEPT;
#endif
	} else {
		return NF_ACCEPT;
	}

	sk = skb_to_full_sk(socket_buffer);
	if (sk == NULL || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = sock_i_uid(sk).val;
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

	rekernel_report(NETWORK, 0, ip_hdr(socket_buffer)->version, NULL, uid, NULL, true, NULL);
	return NF_ACCEPT;
}
/* Only monitor input network packages */
static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook = rekernel_pkg_ipv4_ipv6_in,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = rekernel_pkg_ipv4_ipv6_in,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	}
#endif
};

int register_netfilter(void) {
	int rc;
	struct net* net = NULL;
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
		if (rc) {
			pr_err("register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	if (rc) {
		for_each_net(net) {
			nf_unregister_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
		}
		return -1;
	}

	return LINE_SUCCESS;
}
#endif /* CONFIG_REKERNEL_NETWORK */
struct netlink_kernel_cfg cfg = {
	.input = netlink_rcv_msg, // set recv callback
};
#ifdef CONFIG_PROC_FS
static int rekernel_unit_show(struct seq_file* m, void* v) {
	seq_printf(m, "%d\n", netlink_unit);
	return LINE_SUCCESS;
}
static int rekernel_unit_open(struct inode* inode, struct file* file) {
	return single_open(file, rekernel_unit_show, NULL);
}
static const struct file_operations rekernel_unit_fops = {
	.open = rekernel_unit_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release
};
#endif /* CONFIG_PROC_FS */
// init
static int start_rekernel(void) {
	if (netlink_unit)
		return 0;

	pr_info("Thank you for choosing Re:Kernel!\n");
#ifdef CONFIG_REKERNEL_NETWORK
	pr_info("NetFilter is enabled!\n");
#endif
	pr_info("Re:Kernel v8.5 | DEVELOPER: Sakion Team | Timeline | USER PORT: %d\n", USER_PORT);
	pr_info("Trying to create Re:Kernel Server......\n");

	for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
		netlink_socket = netlink_kernel_create(&init_net, netlink_unit, &cfg);
		if (netlink_socket != NULL)
			break;
	}
	if (netlink_socket == NULL) {
		netlink_unit = 0;
		pr_err("Failed to create Re:Kernel server!\n");
		return -LINE_ERROR;
	}
	pr_info("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);

#ifdef CONFIG_PROC_FS
	rekernel_dir = proc_mkdir("rekernel", NULL);
	if (!rekernel_dir) {
		pr_err("create /proc/rekernel failed!\n");
	} else {
		char buff[32];
		sprintf(buff, "%d", netlink_unit);
		rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir, &rekernel_unit_fops);
		if (!rekernel_unit_entry) {
			pr_err("create rekernel unit failed!\n");
		}
	}
#endif /* CONFIG_PROC_FS */
#ifdef CONFIG_REKERNEL_NETWORK
	if (register_netfilter()) {
		pr_err("%s: Failed to hook netfilter!\n", __func__);
		return -LINE_ERROR;
	}
#endif /* CONFIG_REKERNEL_NETWORK */
	return LINE_SUCCESS;
}

void rekernel_report(int reporttype, int type, pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst, bool oneway, struct binder_transaction_data* tr) {
	char binder_kmsg[PACKET_SIZE];
	char buf_data[INTERFACETOKEN_BUFF_SIZE];
	size_t buf_data_size;
	char buf[INTERFACETOKEN_BUFF_SIZE] = { 0 };
	char* p;
	int i = 0;
	int j = 0;

	if (start_rekernel())
		return;

#ifdef CONFIG_REKERNEL_NETWORK
	if (reporttype == NETWORK) {
		char binder_kmsg[PACKET_SIZE];
		snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv%d;", dst_pid, src_pid);
		sendMessage(binder_kmsg, strlen(binder_kmsg));
		return;
	}
#endif /* CONFIG_REKERNEL_NETWORK */

	if (!frozen_task_group(dst))
		return;

	if (task_uid(src).val == task_uid(dst).val)
		return;

	switch (reporttype) {
	case BINDER:
		if (oneway && type == TRANSACTION) {
			if (tr->code < 29 || tr->code > 32)
				return;
			buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ? INTERFACETOKEN_BUFF_SIZE : tr->data_size;
			if (copy_from_user(buf_data, (char*)tr->data.ptr.buffer, buf_data_size))
				return;
			j = PARCEL_OFFSET + 1;
			p = (char*)(buf_data)+PARCEL_OFFSET;
			while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p != '\0') {
				buf[i++] = *p;
				j += 2;
				p += 2;
			}
			if (i == INTERFACETOKEN_BUFF_SIZE) {
				buf[i - 1] = '\0';
			}
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=%s,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", binder_type[type], oneway, src_pid, task_uid(src).val, dst_pid, task_uid(dst).val, buf, tr->code);
		} else {
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=%s,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", binder_type[type], oneway, src_pid, task_uid(src).val, dst_pid, task_uid(dst).val, rpc_type[type], -1);
		}
		break;
	case SIGNAL:
		snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", type, src_pid, task_uid(src).val, dst_pid, task_uid(dst).val);
		break;
	default:
		return;
	}
	sendMessage(binder_kmsg, strlen(binder_kmsg));
}

void binder_reply_handler(pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst, bool oneway, struct binder_transaction_data* tr) {
	if (unlikely(!dst))
		return;
	if (task_uid(dst).val > MAX_SYSTEM_UID || src_pid == dst_pid)
		return;

	// oneway=0
	rekernel_report(BINDER, REPLY, src_pid, src, dst_pid, dst, oneway, tr);
}

void binder_trans_handler(pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst, bool oneway, struct binder_transaction_data* tr) {
	if (unlikely(!dst))
		return;
	if ((task_uid(dst).val <= MIN_USERAPP_UID) || src_pid == dst_pid)
		return;

	rekernel_report(BINDER, TRANSACTION, src_pid, src, dst_pid, dst, oneway, tr);
}

void binder_overflow_handler(pid_t src_pid, struct task_struct* src, pid_t dst_pid, struct task_struct* dst, bool oneway, struct binder_transaction_data* tr) {
	if (unlikely(!dst))
		return;

	// oneway=1
	rekernel_report(BINDER, OVERFLOW, src_pid, src, dst_pid, dst, oneway, tr);
}
