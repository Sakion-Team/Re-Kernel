/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel.c
 * Description: rekernel module
 * Author: nep_timeline@outlook.com
 * Last Modification:  2025/12/03
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
#include <../android/binder_internal.h>
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

#include <linux/kprobes.h>

#define NETLINK_REKERNEL_MAX     		26
#define NETLINK_REKERNEL_MIN     		22
#define USER_PORT        				100
#define PACKET_SIZE 					256

char netlink_kmsg[PACKET_SIZE];
struct sock *netlink_socket = NULL;
extern struct net init_net;
int netlink_unit = NETLINK_REKERNEL_MIN;

static unsigned long (*re_kallsyms_lookup_name)(const char* name);
static void (*re_binder_transaction_buffer_release)(struct binder_proc* proc, struct binder_thread* thread, struct binder_buffer* buffer, binder_size_t off_end_offset, bool is_failure);
static void (*re_binder_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
static struct binder_stats(*re_binder_stats);
static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;

/* hashmap for monitored uids */
#define REKERNEL_UID_HASH_BITS 6
static DEFINE_HASHTABLE(rekernel_uid_map, REKERNEL_UID_HASH_BITS);
struct uid_info {
	uid_t uid;
	struct hlist_node hnode;
};

/* hashmap for persitent uids */
#define REKERNEL_P_UID_HASH_BITS 5
static DEFINE_HASHTABLE(rekernel_p_uid_map, REKERNEL_P_UID_HASH_BITS);
struct p_uid_info {
	uid_t uid;
	unsigned long last_arrival_time; /* jiffies */
	struct hlist_node hnode;
};

spinlock_t rekernel_map_lock; /* two maps use the same spinlock */

static inline bool rekernel_is_frozen_state_compatible(struct task_struct *task)
{
#if defined(KERNEL_5_10) || defined(KERNEL_5_15)
	return frozen(task);
#else
	return READ_ONCE(task->__state) & TASK_FROZEN;
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
#else
void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async, bool *should_fail)
#endif
{
	struct task_struct *p = NULL;
#ifndef KERNEL_5_10
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
				snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(current), task_uid(current).val, task_tgid_nr(p), task_uid(p).val, "FREE_BUFFER_FULL", -1);
				sendMessage(binder_kmsg, strlen(binder_kmsg));
			}
		}
	}
}

struct hlist_head *binder_procs = NULL;
struct mutex *binder_procs_lock = NULL;

#if defined(KERNEL_5_10) || defined(KERNEL_5_15) || defined(KERNEL_6_1)
void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock)
#else
void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock, struct binder_proc *proc)
#endif
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
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, "SYNC_BINDER_REPLY", -1);
			sendMessage(binder_kmsg, strlen(binder_kmsg));
		}
	}
}

#if defined(KERNEL_6_1) || defined(KERNEL_6_6) || defined(KERNEL_6_12)
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
#if defined(KERNEL_5_10) || defined(KERNEL_5_15)
	return copy_from_user(dst, src, size);
#else
	return line_copy_from_user_nofault(dst, src, size);
#endif
}

void line_binder_transaction(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
	struct binder_thread *thread, struct binder_transaction_data *tr)
{
	char buf_data[INTERFACETOKEN_BUFF_SIZE];
	size_t buf_data_size;
	char buf[INTERFACETOKEN_BUFF_SIZE] = {0};
	int i = 0;
	int j = 0;

	if (!(tr->flags & TF_ONE_WAY) /* sync binder */
		&& target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] Sync Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
		if (netlink_socket != NULL) {
			char binder_kmsg[PACKET_SIZE];
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, "SYNC_BINDER", -1);
			sendMessage(binder_kmsg, strlen(binder_kmsg));
		}
	}

	if ((tr->flags & TF_ONE_WAY) /* async binder */
		&& target_proc
		&& (NULL != target_proc->tsk)
		&& (NULL != proc->tsk)
		&& (task_uid(target_proc->tsk).val > MIN_USERAPP_UID)
		&& (proc->pid != target_proc->pid)
		&& line_is_frozen(target_proc->tsk)) {
		buf_data_size = tr->data_size > INTERFACETOKEN_BUFF_SIZE ? INTERFACETOKEN_BUFF_SIZE : tr->data_size;
		if (!line_copy_from_user_compatible(buf_data, (char*)tr->data.ptr.buffer, buf_data_size)) {
			if (buf_data_size > PARCEL_OFFSET) {
				char *p = (char *)(buf_data) + PARCEL_OFFSET;
				j = PARCEL_OFFSET + 1;
				while (i < INTERFACETOKEN_BUFF_SIZE && j < buf_data_size && *p != '\0') {
					buf[i++] = *p;
					j += 2;
					p += 2;
				}
				if (i == INTERFACETOKEN_BUFF_SIZE) buf[i-1] = '\0';
			}
#ifdef DEBUG
			pr_info("[Re-Kernel LKM] ASync Binder Transaction! from=%d | target=%d\n", task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
#endif
			if (netlink_socket != NULL) {
				char binder_kmsg[PACKET_SIZE];
				snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, buf, tr->code);
			    sendMessage(binder_kmsg, strlen(binder_kmsg));
			}
		}
	}
}

static inline void binder_inner_proc_lock(struct binder_proc* proc)
__acquires(&proc->inner_lock)
{
	spin_lock(&proc->inner_lock);
}

static inline void binder_inner_proc_unlock(struct binder_proc* proc)
__releases(&proc->inner_lock)
{
	spin_unlock(&proc->inner_lock);
}

static inline void binder_node_lock(struct binder_node* node)
__acquires(&node->lock)
{
	spin_lock(&node->lock);
}

static inline void binder_node_unlock(struct binder_node* node)
__releases(&node->lock)
{
	spin_unlock(&node->lock);
}

static bool binder_can_update_transaction(struct binder_transaction* t1, struct binder_transaction* t2)
{
	if ((t1->flags & t2->flags & TF_ONE_WAY) != TF_ONE_WAY || !t1->to_proc || !t2->to_proc)
		return false;
	if (t1->to_proc->tsk == t2->to_proc->tsk && t1->code == t2->code &&
		t1->flags == t2->flags && t1->buffer->pid == t2->buffer->pid &&
		t1->buffer->target_node->ptr == t2->buffer->target_node->ptr &&
		t1->buffer->target_node->cookie == t2->buffer->target_node->cookie)
		return true;
	return false;
}

static struct binder_transaction* binder_find_outdated_transaction_ilocked(struct binder_transaction* t,
	struct list_head* target_list)
{
	struct binder_work* w;
	bool second = false;

	list_for_each_entry(w, target_list, entry) {
		struct binder_transaction* t_queued;

		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t_queued = container_of(w, struct binder_transaction, work);
		if (binder_can_update_transaction(t_queued, t)) {
			if (second)
				return t_queued;
			else
				second = true;
		}
	}
	return NULL;
}

static inline void __nocfi binder_release_entire_buffer(struct binder_proc* proc,
	struct binder_thread* thread, struct binder_buffer* buffer, bool is_failure)
{
	binder_size_t off_end_offset;

	off_end_offset = ALIGN(buffer->data_size, sizeof(void*));
	off_end_offset += buffer->offsets_size;

	re_binder_transaction_buffer_release(proc, thread, buffer,
		off_end_offset, is_failure);
}

static inline void binder_stats_deleted(enum binder_stat_types type)
{
	atomic_inc(&re_binder_stats->obj_deleted[type]);
}

static int __nocfi binder_proc_transaction_pre(struct kprobe* p, struct pt_regs* regs)
{
	struct binder_transaction* t = (struct binder_transaction*)regs->regs[0];
	struct binder_proc* proc = (struct binder_proc*)regs->regs[1];

	struct binder_node* node = t->buffer->target_node;
	struct binder_transaction* t_outdated = NULL;

	if (!node || !proc || proc->is_frozen || !(t->flags & TF_ONE_WAY))
		return 0;

	if (line_is_frozen(proc->tsk)) {
		binder_node_lock(node);
		if (!node->has_async_transaction) {
			binder_node_unlock(node);
			return 0;
		}
		binder_inner_proc_lock(proc);
		t_outdated = binder_find_outdated_transaction_ilocked(t, &node->async_todo);
		if (t_outdated) {
			list_del_init(&t_outdated->work.entry);
			proc->outstanding_txns--;
		}
		binder_inner_proc_unlock(proc);
		binder_node_unlock(node);

		if (t_outdated) {
			struct binder_buffer* buffer = t_outdated->buffer;
#ifdef DEBUG
			pr_info("[Re-Kernel LKM] free_outdated txn %d supersedes %d\n", t->debug_id, t_outdated->debug_id);
#endif
			t_outdated->buffer = NULL;
			buffer->transaction = NULL;
			binder_release_entire_buffer(proc, NULL, buffer, false);
			re_binder_alloc_free_buf(&proc->alloc, buffer);
			kfree(t_outdated);
			binder_stats_deleted(BINDER_STAT_TRANSACTION);
		}
	}
	return 0;
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
			sendMessage(binder_kmsg, strlen(binder_kmsg));
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

	uid = line_sock2uid(sk);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

#ifdef DEBUG
	pr_info("[Re-Kernel LKM] Receive net data! target=%d\n", uid);
#endif
	if (netlink_socket != NULL) {
		char binder_kmsg[PACKET_SIZE];
		if (ip_hdr(socket_buffer)->version == 4) {
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv4;", uid);
#if IS_ENABLED(CONFIG_IPV6)
		} else if (ip_hdr(socket_buffer)->version == 6) {
			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Network,target=%d,proto=ipv6;", uid);
#endif
		} else {
			return NF_ACCEPT;
		}
		sendMessage(binder_kmsg, strlen(binder_kmsg));
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

void unregister_signal(void)
{
	unregister_trace_android_vh_do_send_sig_info(line_signal, NULL);
}

void unregister_netfilter(void)
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

static void netlink_rcv_msg(struct sk_buff *socket_buffer)
{
	struct nlmsghdr *nlhdr = NULL;
    char *umsg = NULL;
    if (socket_buffer->len >= nlmsg_total_size(0)) {
        nlhdr = nlmsg_hdr(socket_buffer);
        umsg = NLMSG_DATA(nlhdr);
        if (umsg) {
#ifdef DEBUG
            pr_info("Re-Kernel_netlink recv_from_user: %s\n", umsg);
#endif
            if (strcmp(umsg, "#proc_remove") == 0) {
                if (rekernel_unit_entry) {
                    proc_remove(rekernel_unit_entry);
                    rekernel_unit_entry = NULL;
                }
                if (rekernel_dir) {
                    proc_remove(rekernel_dir);
                    rekernel_dir = NULL;
                }
            }
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

static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name = "kallsyms_lookup_name"
};
static struct kprobe kp_binder_proc_transaction = {
	.symbol_name = "binder_proc_transaction",
	.pre_handler = binder_proc_transaction_pre
};

int __nocfi register_kp(void) {
	int rc = LINE_SUCCESS;

	rc = register_kprobe(&kp_kallsyms_lookup_name);
	if (rc != LINE_SUCCESS) {
		pr_err("register kprobe hooks failed, rc=%d\n", rc);
		return rc;
	}
	re_kallsyms_lookup_name = (void*)kp_kallsyms_lookup_name.addr;
	unregister_kprobe(&kp_kallsyms_lookup_name);

	re_binder_transaction_buffer_release = (void*)re_kallsyms_lookup_name("binder_transaction_buffer_release");
	re_binder_alloc_free_buf = (void*)re_kallsyms_lookup_name("binder_alloc_free_buf");
	re_binder_stats = (void*)re_kallsyms_lookup_name("binder_stats");

	if (re_binder_transaction_buffer_release == NULL || re_binder_alloc_free_buf == NULL || re_binder_stats == NULL) {
		rc = -EINVAL;
		pr_err("register kprobe kallsyms_lookup_name failed, rc=%d\n", rc);
		return rc;
	}

	register_kprobe(&kp_binder_proc_transaction);
	if (rc != LINE_SUCCESS) {
		pr_err("register binder_proc_transaction hooks failed, rc=%d\n", rc);
		return rc;
	}

	return LINE_SUCCESS;
}

void unregister_kp(void) {
	unregister_kprobe(&kp_binder_proc_transaction);
}

static int __init start_rekernel(void)
{
	pr_info("Thank you for choosing Re:Kernel!\n");
#ifdef DEBUG
	pr_info("Debug mode is enabled!\n");
#endif
#ifdef NETWORK_FILTER
	pr_info("NetFilter is enabled!\n");
#endif
	pr_info("Re:Kernel v8.5 | DEVELOPER: Sakion Team | Timeline | USER PORT: %d\n", USER_PORT);
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
	
#ifdef NETWORK_FILTER
	if (register_netfilter() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook netfilter!\n", __func__);
		return LINE_ERROR;
	}
#endif

#ifdef CLEAN_UP_ASYNC_BINDER
	if (register_kp() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook kprobe!\n", __func__);
		return LINE_ERROR;
	}
#endif

	pr_info("Re-Kernel hooked!\n");
	return LINE_SUCCESS;
}

static void __exit exit_rekernel(void)
{
	pr_info("Re-Kernel closing...\n");
	unregister_binder();
	unregister_signal();
#ifdef NETWORK_FILTER
	unregister_netfilter();
#endif
	unregister_kp();
	netlink_kernel_release(netlink_socket);
}

module_init(start_rekernel);
module_exit(exit_rekernel);

MODULE_LICENSE("GPL");
