/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_binder.c
 * Description: Re:Kernel binder hooks. Android vendor hooks for binder
 *              alloc/preset/reply/transaction emit events when a frozen target
 *              is about to be woken; a live kprobe on binder_proc_transaction
 *              (CLEAN_UP_ASYNC_BINDER) frees superseded outdated async
 *              transactions. Non-exported binder symbols are resolved via a
 *              transient kprobe on kallsyms_lookup_name.
 */
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kprobes.h>
#include <trace/hooks/binder.h>
#include <../android/binder_internal.h>
#include "rekernel_internal.h"

static unsigned long (*re_kallsyms_lookup_name)(const char* name);
static void (*re_kernel_transaction_buffer_release)(struct binder_proc* proc, struct binder_thread* thread, struct binder_buffer* buffer, binder_size_t off_end_offset, bool is_failure);
static void (*re_kernel_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
static struct binder_stats(*re_kernel_stats);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
static void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async, bool *should_fail)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
static void line_binder_alloc_new_buf_locked(void *data, size_t size, size_t *free_async_space, int is_async)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
static void line_binder_alloc_new_buf_locked(void *data, size_t size, struct binder_alloc *alloc, int is_async)
#endif
{
	struct task_struct *p = NULL;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0))
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
			if (rekernel_netlink_ready()) {
				char binder_kmsg[PACKET_SIZE];
				int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(current), task_uid(current).val, task_tgid_nr(p), task_uid(p).val, "FREE_BUFFER_FULL", -1);
				sendMessage(binder_kmsg, len);
			}
		}
	}
}

static struct hlist_head *binder_procs = NULL;
static struct mutex *binder_procs_lock = NULL;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0))
static void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock, struct binder_proc *proc)
#else
static void line_binder_preset(void *data, struct hlist_head *hhead,
	struct mutex *lock)
#endif
{
	if (binder_procs == NULL)
		binder_procs = hhead;

	if (binder_procs_lock == NULL)
		binder_procs_lock = lock;
}

static void line_binder_reply(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
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
		if (rekernel_netlink_ready()) {
			char binder_kmsg[PACKET_SIZE];
			int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, "SYNC_BINDER_REPLY", -1);
			sendMessage(binder_kmsg, len);
		}
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
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
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return line_copy_from_user_nofault(dst, src, size);
#else
	return copy_from_user(dst, src, size);
#endif
}

static void line_binder_transaction(void *data, struct binder_proc *target_proc, struct binder_proc *proc,
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
		if (rekernel_netlink_ready()) {
			char binder_kmsg[PACKET_SIZE];
			int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, "SYNC_BINDER", -1);
			sendMessage(binder_kmsg, len);
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
			if (rekernel_netlink_ready()) {
				char binder_kmsg[PACKET_SIZE];
				int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;", task_tgid_nr(proc->tsk), task_uid(proc->tsk).val, task_tgid_nr(target_proc->tsk), task_uid(target_proc->tsk).val, buf, tr->code);
				sendMessage(binder_kmsg, len);
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

	re_kernel_transaction_buffer_release(proc, thread, buffer,
		off_end_offset, is_failure);
}

static inline void binder_stats_deleted(enum binder_stat_types type)
{
	atomic_inc(&re_kernel_stats->obj_deleted[type]);
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
			re_kernel_alloc_free_buf(&proc->alloc, buffer);
			kfree(t_outdated);
			binder_stats_deleted(BINDER_STAT_TRANSACTION);
		}
	}
	return 0;
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

	re_kernel_transaction_buffer_release = (void*)re_kallsyms_lookup_name("binder_transaction_buffer_release");
	re_kernel_alloc_free_buf = (void*)re_kallsyms_lookup_name("binder_alloc_free_buf");
	re_kernel_stats = (void*)re_kallsyms_lookup_name("binder_stats");

	if (re_kernel_transaction_buffer_release == NULL || re_kernel_alloc_free_buf == NULL || re_kernel_stats == NULL) {
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
