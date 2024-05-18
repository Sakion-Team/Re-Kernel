/*
 * Copyright (c) Sakion Team., Ltd. 2015. All rights reserved.
 *
 * File name: rekernel.c
 * Description: rekernel module
 * Author: nep_timeline@outlook.com
 * Last Modification:  2024/5/18
 */
#include "linux/printk.h"
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/freezer.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/proc_fs.h>
#include "rekernel.h"
#include <trace/hooks/binder.h>
#include <trace/hooks/signal.h>
#include <../../android/binder_internal.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>

#include <linux/jiffies.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/slab.h>

#define NETLINK_REKERNEL_MAX     		26
#define NETLINK_REKERNEL_MIN     		22
#define USER_PORT        				    100
#define PACKET_SIZE 					      128
int netlink_count = 0;
char netlink_kmsg[PACKET_SIZE];
struct sock *netlink_socket = NULL;
extern struct net init_net;
int netlink_unit = NETLINK_REKERNEL_MIN;

#define REKERNEL_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_uid_map, REKERNEL_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
};

#define REKERNEL_P_UID_HASH_BITS 5
static DEFINE_HASHTABLE(rekernel_p_uid_map, REKERNEL_P_UID_HASH_BITS);
struct p_uid_info {
	uid_t uid;
	unsigned long last_arrival_time;
	struct hlist_node hnode;
};

spinlock_t rekernel_map_lock;

static inline bool rekernel_is_frozen_state_compatible(struct task_struct *task)
{
#ifdef KERNEL_6_1
	return READ_ONCE(task->__state) & TASK_FROZEN;
#else
	return frozen(task);
#endif
}

static inline bool rekernel_is_jobctl_frozen_compatible(struct task_struct *task)
{
#ifdef KERNEL_5_10
	return cgroup_task_freeze(task);
#else
	return ((task->jobctl & JOBCTL_TRAP_FREEZE) != 0);
#endif
}

static inline bool line_is_frozen(struct task_struct *task)
{
	return (cgroup_task_frozen(task) || rekernel_is_jobctl_frozen_compatible(task) || rekernel_is_frozen_state_compatible(task->group_leader) || freezing(task->group_leader));
}

static int sendMessage(char *packet_buffer, uint16_t len)
{
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
}

#if defined(KERNEL_5_15) || defined(KERNEL_6_1)
void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async)
#elif defined(KERNEL_5_10)
void line_binder_alloc_new_buf_locked(void *data, size_t size, struct binder_alloc *alloc, int is_async)
#endif
{
	struct task_struct *p = NULL;
#if defined(KERNEL_5_15) || defined(KERNEL_6_1)
	struct binder_alloc *alloc = NULL;

	alloc = container_of(free_async_space, struct binder_alloc, free_async_space);
	if (alloc == NULL) {
		return;
	}
#endif
	if (is_async
		&& (alloc->free_async_space < 3 * (size + sizeof(struct binder_buffer))
		|| (alloc->free_async_space < WARN_AHEAD_SPACE))) {
		rcu_read_lock();
		p = find_task_by_vpid(alloc->pid);
		rcu_read_unlock();
		if (p != NULL && line_is_frozen(p)) {
#ifdef DEBUG
			pr_info("[Re-Kernel LKM] Binder Free buffer full! from=%d | target=%d\n", task_uid(current).val, task_uid(p).val);
#endif
			if (netlink_socket != NULL) {
				char binder_kmsg[PACKET_SIZE];
				snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d;", current->pid, task_uid(current).val, p->pid, task_uid(p).val);
				send_usrmsg(binder_kmsg, strlen(binder_kmsg));
			}
		}
	}
}

struct hlist_head *binder_procs = NULL;
struct mutex *binder_procs_lock = NULL;

void line_binder_preset(void *data, struct hlist_head *hhead,
			   struct mutex *lock)
{
	if (binder_procs == NULL)
		binder_procs = hhead;

	if (binder_procs_lock == NULL)
		binder_procs_lock = lock;
}

void line_binder_reply(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	if (target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val <= MAX_SYSTEM_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Sync Binder Reply! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
		if (netlink_socket != NULL) {
			char binder_kmsg[PACKET_SIZE];
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
			send_usrmsg(binder_kmsg, strlen(binder_kmsg));
		}
	}
}

#ifdef KERNEL_6_1
static long line_copy_from_user_nofault(void *dst, const void __user *src, size_t size)
{
	long ret = -EFAULT;
	if (access_ok(src, size)) {
		pagefault_disable();
		ret = __copy_from_user_inatomic(dst, src, size);
		pagefault_enable();
	}
	if (ret)
		return -EFAULT;
	return 0;
}
#endif

static long line_copy_from_user_compatible(void *dst, const void __user *src, size_t size)
{
#ifdef KERNEL_6_1
	return line_copy_from_user_nofault(dst, src, size);
#else
	return copy_from_user(dst, src, size);
#endif
}

void line_binder_transaction(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	if (target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
		if (netlink_socket != NULL) {
			char binder_kmsg[PACKET_SIZE];
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", tr->flags & TF_ONE_WAY, proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
			send_usrmsg(binder_kmsg, strlen(binder_kmsg));
		}
	}
}

void line_signal(void *data, int sig, struct task_struct *killer, struct task_struct *dst)
{
	if (!dst || !killer)
		return;

	if (line_is_frozen(dst) &&
			(sig == SIGKILL
			|| sig == SIGTERM
			|| sig == SIGABRT
			|| sig == SIGQUIT)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Process Signal! signal=%d\n", sig);
#endif
		if (netlink_socket != NULL) {
			char binder_kmsg[PACKET_SIZE];
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", sig, task_tgid_nr(killer), task_uid(killer).val, task_tgid_nr(dst), task_uid(dst).val);
			send_usrmsg(binder_kmsg, strlen(binder_kmsg));
		}
	}
}

int register_binder(void)
{
	int rc = LINE_SUCCESS;
	rc = register_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_alloc_new_buf_locked failed, rc=%d\n", rc);
		return rc;
	}
	rc = register_trace_android_vh_binder_preset(line_binder_preset, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_preset failed, rc=%d\n", rc);
		return rc;
	}
	rc = register_trace_android_vh_binder_reply(line_binder_reply, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_reply failed, rc=%d\n", rc);
		return rc;
	}
	rc = register_trace_android_vh_binder_trans(line_binder_transaction, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_trans failed, rc=%d\n", rc);
		return rc;
	}

	return LINE_SUCCESS;
}

void unregister_binder(void)
{
	unregister_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	unregister_trace_android_vh_binder_preset(line_binder_preset, NULL);
	unregister_trace_android_vh_binder_reply(line_binder_reply, NULL);
	unregister_trace_android_vh_binder_trans(line_binder_transaction, NULL);
}

int register_signal(void)
{
	int rc = LINE_SUCCESS;

	rc = register_trace_android_vh_do_send_sig_info(line_signal, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_do_send_sig_info failed, rc=%d\n", rc);
		return rc;
	}

	return LINE_SUCCESS;
}

static inline uid_t line_sock2uid(struct sock *sk)
{
	if(sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	else
		return 0;
}

static unsigned int rekernel_pkg_ip4_in(void *priv, struct sk_buff *socket_buffer,
		const struct nf_hook_state *state)
{
	struct sock *socket;
	uid_t uid;
	int protocol;

	protocol = ip_hdr(socket_buffer)->protocol;
	if (protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	socket = skb_to_full_sk(socket_buffer);
	if (socket == NULL || !sk_fullsock(socket))
		return NF_ACCEPT;

	uid = line_sock2uid(socket);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

#ifdef DEBUG
	pr_info("[Re-Kernel LKM] Receive net data! target=%d\n", uid);
#endif
	if (netlink_socket != NULL) {
		char binder_kmsg[PACKET_SIZE];
		snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d;", uid);
		send_usrmsg(binder_kmsg, strlen(binder_kmsg));
	}

	return NF_ACCEPT;
}

static unsigned int rekernel_pkg_ip6_in(void *priv, struct sk_buff *socket_buffer,
		const struct nf_hook_state *state)
{
	struct sock *sk;
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	int protohdr;
	uid_t uid;

	protohdr = ipv6_find_hdr(socket_buffer, &thoff, -1, &frag_off, NULL);
	if (protohdr != IPPROTO_TCP)
		return NF_ACCEPT;

	sk = skb_to_full_sk(socket_buffer);
	if (sk == NULL || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = line_sock2uid(sk);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

#ifdef DEBUG
	pr_info("[Re-Kernel LKM] Receive net data! target=%d\n", uid);
#endif
	if (netlink_socket != NULL) {
		char binder_kmsg[PACKET_SIZE];
		snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d;", uid);
		send_usrmsg(binder_kmsg, strlen(binder_kmsg));
	}
	
	return NF_ACCEPT;
}

static inline unsigned int rekernel_pkg_ip_out(void *priv, struct sk_buff *socket_buffer,
		const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}

static struct nf_hook_ops rekernel_nf_ops[] = {
	{
		.hook     = rekernel_pkg_ip4_in,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = rekernel_pkg_ip6_in,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	},
#endif
	{
		.hook     = rekernel_pkg_ip_out,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = rekernel_pkg_ip_out,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	},
#endif
};

void unregister_signal(void)
{
	struct net *net;

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
	}
	rtnl_unlock();
}

int register_netfilter(void)
{
	int rc = LINE_SUCCESS;

	struct net *net = NULL;

	spin_lock_init(&rekernel_map_lock);
	hash_init(rekernel_uid_map);
	hash_init(rekernel_p_uid_map);

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_nf_ops, ARRAY_SIZE(rekernel_nf_ops));
		if (rc != 0) {
			pr_err("register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	rtnl_unlock();

	return LINE_SUCCESS;
}

void unregister_netfilter(void)
{
	unregister_trace_android_vh_do_send_sig_info(line_signal, NULL);
}

// Test code, Useless
static void netlink_rcv_msg(struct sk_buff *socket_buffer)
{
	struct nlmsghdr *nlhdr = NULL;
    char *umsg = NULL;
    char *kmsg;

    if (socket_buffer->len >= nlmsg_total_size(0)) {
        netlink_count++;
   		snprintf(netlink_kmsg, sizeof(netlink_kmsg), "Successfully received data packet! %d", netlink_count);
    	kmsg = netlink_kmsg;
        nlhdr = nlmsg_hdr(socket_buffer);
        umsg = NLMSG_DATA(nlhdr);
        if (umsg) {
            printk("kernel recv packet from user: %s\n", umsg);
            send_usrmsg(kmsg, strlen(kmsg));
        }
    }
}

struct netlink_kernel_cfg cfg = { 
	.input = netlink_rcv_msg, // set recv callback
};  

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

static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;    

static int __init start_rekernel(void)
{
	pr_info("Thank you for choosing Re:Kernel!\n");
#ifdef DEBUG
	pr_info("Debug mode is enabled!\n");
#endif
	pr_info("Re:Kernel v6.0 | DEVELOPER: Sakion Team | Timeline | USER PORT: %d\n", USER_PORT);
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

	pr_info("Re-Kernel start hooking!\n");

	if (register_binder() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook binder!\n", __func__);
		return LINE_ERROR;
	}

	if (register_signal() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook signal!\n", __func__);
		return LINE_ERROR;
	}
	
	if (register_netfilter() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook netfilter!\n", __func__);
		return LINE_ERROR;
	}

	pr_info("Re-Kernel hooked!\n");
	return LINE_SUCCESS;
}

static void __exit exit_rekernel(void)
{
	pr_info("Re-Kernel closing...\n");
	unregister_binder();
	unregister_signal();
	unregister_netfilter();
	netlink_kernel_release(netlink_socket);
}

module_init(start_rekernel);
module_exit(exit_rekernel);

MODULE_LICENSE("GPL");
