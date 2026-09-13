/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_binder.c
 * Description: Re:Kernel binder hooks. Android vendor hooks for binder
 *              alloc/preset/reply/transaction emit events when a frozen target
 *              is about to be woken. Standard Binder allocation/write-done
 *              tracepoints (CLEAN_UP_ASYNC_BINDER) arrange deferred cleanup
 *              of superseded async transactions marked TF_UPDATE_TXN.
 *              Non-exported binder symbols are resolved via a transient
 *              kprobe on kallsyms_lookup_name.
 */
#include <linux/version.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/tracepoint.h>
#include <linux/workqueue.h>
#include <trace/hooks/binder.h>
#include <../android/binder_internal.h>
#include "rekernel_internal.h"

#ifdef CLEAN_UP_ASYNC_BINDER
static unsigned long (*re_kallsyms_lookup_name)(const char* name);
static void (*re_kernel_alloc_free_buf)(struct binder_alloc* alloc, struct binder_buffer* buffer);
static void (*re_kernel_proc_dec_tmpref)(struct binder_proc* proc);
static void (*re_kernel_free_proc)(struct binder_proc* proc);
static struct binder_stats(*re_kernel_stats);
static struct workqueue_struct *binder_cleanup_wq;
static struct tracepoint *binder_alloc_buf_tp;
static struct tracepoint *binder_write_done_tp;
static DEFINE_HASHTABLE(binder_cleanup_pending, 6);
static DEFINE_SPINLOCK(binder_cleanup_lock);

struct binder_cleanup_work {
	struct work_struct work;
	struct hlist_node entry;
	struct task_struct *sender;
	struct binder_proc *proc;
	/* Identity only: the worker must rediscover this transaction in the queue. */
	struct binder_transaction *transaction;
	int transaction_id;
	binder_uintptr_t node_ptr;
	binder_uintptr_t node_cookie;
	int node_id;
	bool write_done;
};

/* Stable UAPI value; some older vendor headers do not name this flag. */
#define REKERNEL_TF_UPDATE_TXN 0x40
#endif

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

#ifdef CLEAN_UP_ASYNC_BINDER
static bool binder_can_update_transaction(struct binder_transaction* t1, struct binder_transaction* t2)
{
	if (!t1 || !t2 || !t1->buffer || !t2->buffer ||
	    !t1->buffer->target_node || !t2->buffer->target_node ||
	    !t1->to_proc || !t2->to_proc)
		return false;
	if ((t1->flags & t2->flags & (TF_ONE_WAY | REKERNEL_TF_UPDATE_TXN)) !=
	    (TF_ONE_WAY | REKERNEL_TF_UPDATE_TXN))
		return false;
	/* Only buffers without embedded Binder objects or FDs can be detached. */
	if (t1->buffer->offsets_size != 0 || t2->buffer->offsets_size != 0)
		return false;
	if (t1->to_proc->tsk == t2->to_proc->tsk && t1->code == t2->code &&
		t1->flags == t2->flags && t1->buffer->pid == t2->buffer->pid &&
		t1->buffer->target_node->ptr == t2->buffer->target_node->ptr &&
		t1->buffer->target_node->cookie == t2->buffer->target_node->cookie)
		return true;
	return false;
}

static struct binder_node *binder_cleanup_find_node_ilocked(struct binder_cleanup_work *cleanup)
{
	struct rb_node *rb = cleanup->proc->nodes.rb_node;

	while (rb) {
		struct binder_node *node = rb_entry(rb, struct binder_node, rb_node);

		if (cleanup->node_ptr < node->ptr)
			rb = rb->rb_left;
		else if (cleanup->node_ptr > node->ptr)
			rb = rb->rb_right;
		else
			return node->debug_id == cleanup->node_id &&
				node->cookie == cleanup->node_cookie ? node : NULL;
	}
	return NULL;
}

static void __nocfi binder_cleanup_put_proc(struct binder_proc *proc)
{
	if (re_kernel_proc_dec_tmpref) {
		re_kernel_proc_dec_tmpref(proc);
		return;
	}

	/* The small tmpref helper may also be inlined into its callers. */
	spin_lock(&proc->inner_lock);
	proc->tmp_ref--;
	if (proc->is_dead && RB_EMPTY_ROOT(&proc->threads) && !proc->tmp_ref) {
		spin_unlock(&proc->inner_lock);
		re_kernel_free_proc(proc);
		return;
	}
	spin_unlock(&proc->inner_lock);
}

static void __nocfi binder_cleanup_worker(struct work_struct *work)
{
	struct binder_cleanup_work *cleanup = container_of(work, struct binder_cleanup_work, work);
	struct binder_proc *proc = cleanup->proc;
	struct binder_node *node;
	struct binder_transaction *candidate = NULL, *latest;
	struct binder_work *w, *next;
	LIST_HEAD(outdated);

	if (!cleanup->write_done)
		goto out;

	for (;;) {
		spin_lock(&proc->inner_lock);
		if (proc->is_dead || proc->is_frozen || !line_is_frozen(proc->tsk))
			goto unlock_proc;
		node = binder_cleanup_find_node_ilocked(cleanup);
		if (!node)
			goto unlock_proc;
		/*
		 * The node is live only while inner_lock is held. A nonblocking
		 * trylock avoids reversing Binder's node -> inner lock dependency.
		 * On contention, drop inner_lock and look up the node again.
		 */
		if (spin_trylock(&node->lock))
			break;
		spin_unlock(&proc->inner_lock);
		cond_resched();
	}

	/* Allocation precedes validation. Only a still-queued candidate counts. */
	list_for_each_entry(w, &node->async_todo, entry) {
		struct binder_transaction *t;

		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t = container_of(w, struct binder_transaction, work);
		if (t == cleanup->transaction && t->debug_id == cleanup->transaction_id) {
			candidate = t;
			break;
		}
	}
	if (!candidate)
		goto unlock_node;

	/* Writes may batch updates, and different senders can finish out of order. */
	latest = candidate;
	list_for_each_entry(w, &node->async_todo, entry) {
		struct binder_transaction *t;

		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t = container_of(w, struct binder_transaction, work);
		if (binder_can_update_transaction(t, candidate))
			latest = t;
	}
	list_for_each_entry_safe(w, next, &node->async_todo, entry) {
		struct binder_transaction *t;

		if (w == &latest->work)
			break;
		if (w->type != BINDER_WORK_TRANSACTION)
			continue;
		t = container_of(w, struct binder_transaction, work);
		if (!binder_can_update_transaction(t, latest))
			continue;
		if (proc->outstanding_txns <= 0 || node->local_strong_refs <= 1)
			break;
		/*
		 * A zero-offset buffer only owns a target-node strong reference.
		 * The newest update keeps that reference non-final, matching the
		 * early return in binder_dec_node_nilocked(node, 1, 0).
		 */
		node->local_strong_refs--;
		t->buffer->target_node = NULL;
		t->buffer->transaction = NULL;
		list_move_tail(&w->entry, &outdated);
		proc->outstanding_txns--;
#ifdef DEBUG
		pr_info("[Re-Kernel LKM] free_outdated txn %d supersedes %d\n", latest->debug_id, t->debug_id);
#endif
	}
unlock_node:
	spin_unlock(&node->lock);
unlock_proc:
	spin_unlock(&proc->inner_lock);
	list_for_each_entry_safe(w, next, &outdated, entry) {
		struct binder_transaction *t = container_of(w, struct binder_transaction, work);

		list_del_init(&w->entry);
		re_kernel_alloc_free_buf(&proc->alloc, t->buffer);
		kfree(t);
		atomic_inc(&re_kernel_stats->obj_deleted[BINDER_STAT_TRANSACTION]);
	}
out:
	binder_cleanup_put_proc(proc);
	kfree(cleanup);
}

static void line_binder_transaction_alloc_buf(void *data, struct binder_buffer *buffer)
{
	struct binder_transaction *t = buffer->transaction;
	struct binder_node *node = buffer->target_node;
	struct binder_proc *proc;
	struct binder_cleanup_work *cleanup;

	if (!t || !node || !t->to_proc || buffer->offsets_size != 0 ||
	    (t->flags & (TF_ONE_WAY | REKERNEL_TF_UPDATE_TXN)) !=
	    (TF_ONE_WAY | REKERNEL_TF_UPDATE_TXN))
		return;
	proc = t->to_proc;
	if (!proc->tsk || !line_is_frozen(proc->tsk))
		return;
	cleanup = kmalloc(sizeof(*cleanup), GFP_ATOMIC);
	if (!cleanup)
		return;
	cleanup->proc = proc;
	cleanup->sender = current;
	cleanup->transaction = t;
	cleanup->transaction_id = t->debug_id;
	cleanup->node_ptr = node->ptr;
	cleanup->node_cookie = node->cookie;
	cleanup->node_id = node->debug_id;
	cleanup->write_done = false;
	INIT_WORK(&cleanup->work, binder_cleanup_worker);
	spin_lock(&proc->inner_lock);
	if (proc->is_dead || proc->is_frozen) {
		spin_unlock(&proc->inner_lock);
		kfree(cleanup);
		return;
	}
	/* The live transaction protects proc until we take our own reference. */
	proc->tmp_ref++;
	spin_unlock(&proc->inner_lock);
	spin_lock(&binder_cleanup_lock);
	hash_add(binder_cleanup_pending, &cleanup->entry, (unsigned long)current);
	spin_unlock(&binder_cleanup_lock);
}

static void line_binder_write_done(void *data, int ret)
{
	struct binder_cleanup_work *cleanup;
	struct hlist_node *next;

	spin_lock(&binder_cleanup_lock);
	hash_for_each_possible_safe(binder_cleanup_pending, cleanup, next, entry,
		(unsigned long)current) {
		if (cleanup->sender != current)
			continue;
		hash_del(&cleanup->entry);
		/* A failing write can still have accepted earlier commands. */
		cleanup->write_done = true;
		queue_work(binder_cleanup_wq, &cleanup->work);
	}
	spin_unlock(&binder_cleanup_lock);
}

static void binder_cleanup_find_tracepoints(struct tracepoint *tp, void *data)
{
	if (!strcmp(tp->name, "binder_transaction_alloc_buf"))
		binder_alloc_buf_tp = tp;
	else if (!strcmp(tp->name, "binder_write_done"))
		binder_write_done_tp = tp;
}
#endif

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
		goto unregister_alloc_hook;
	}
	rc = register_trace_android_vh_binder_reply(line_binder_reply, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_reply failed, rc=%d\n", rc);
		goto unregister_preset_hook;
	}
	rc = register_trace_android_vh_binder_trans(line_binder_transaction, NULL);
	if (rc != LINE_SUCCESS) {
		pr_err("register_trace_android_vh_binder_trans failed, rc=%d\n", rc);
		goto unregister_reply_hook;
	}
	return LINE_SUCCESS;

unregister_reply_hook:
	unregister_trace_android_vh_binder_reply(line_binder_reply, NULL);
unregister_preset_hook:
	unregister_trace_android_vh_binder_preset(line_binder_preset, NULL);
unregister_alloc_hook:
	unregister_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	return rc;
}

void unregister_binder(void)
{
	unregister_trace_android_vh_binder_alloc_new_buf_locked(line_binder_alloc_new_buf_locked, NULL);
	unregister_trace_android_vh_binder_preset(line_binder_preset, NULL);
	unregister_trace_android_vh_binder_reply(line_binder_reply, NULL);
	unregister_trace_android_vh_binder_trans(line_binder_transaction, NULL);
}

#ifdef CLEAN_UP_ASYNC_BINDER
static struct kprobe kp_kallsyms_lookup_name = {
	.symbol_name = "kallsyms_lookup_name"
};
int __nocfi register_binder_cleanup(void) {
	int rc = LINE_SUCCESS;
	void *rust_impl;

	rc = register_kprobe(&kp_kallsyms_lookup_name);
	if (rc != LINE_SUCCESS) {
		pr_err("register kprobe hooks failed, rc=%d\n", rc);
		return rc;
	}
	re_kallsyms_lookup_name = (void*)kp_kallsyms_lookup_name.addr;
	unregister_kprobe(&kp_kallsyms_lookup_name);

	/* C Binder symbols can remain present when Rust Binder is selected. */
	rust_impl = (void*)re_kallsyms_lookup_name("binder_use_rust");
	if (rust_impl &&
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
	    READ_ONCE(*(int *)rust_impl)) {
#else
	    READ_ONCE(*(bool *)rust_impl)) {
#endif
		pr_err("binder async cleanup: active Rust Binder requires a native Rust adapter\n");
		return -EOPNOTSUPP;
	}

	re_kernel_alloc_free_buf = (void*)re_kallsyms_lookup_name("binder_alloc_free_buf");
	re_kernel_proc_dec_tmpref = (void*)re_kallsyms_lookup_name("binder_proc_dec_tmpref");
	re_kernel_free_proc = (void*)re_kallsyms_lookup_name("binder_free_proc");
	re_kernel_stats = (void*)re_kallsyms_lookup_name("binder_stats");
	if (!re_kernel_alloc_free_buf || !re_kernel_stats) {
		pr_err("binder async cleanup: missing %s\n",
			!re_kernel_alloc_free_buf ? "binder_alloc_free_buf" : "binder_stats");
		return -ENOENT;
	}
	if (!re_kernel_proc_dec_tmpref && !re_kernel_free_proc) {
		pr_err("binder async cleanup: neither binder_proc_dec_tmpref nor binder_free_proc is available\n");
		return -ENOENT;
	}
	for_each_kernel_tracepoint(binder_cleanup_find_tracepoints, NULL);
	if (!binder_alloc_buf_tp || !binder_write_done_tp) {
		pr_err("binder async cleanup: missing %s tracepoint\n",
			!binder_alloc_buf_tp ? "binder_transaction_alloc_buf" : "binder_write_done");
		return -ENOENT;
	}

	binder_cleanup_wq = alloc_workqueue("rekernel_binder_cleanup", WQ_UNBOUND | WQ_MEM_RECLAIM, 1);
	if (!binder_cleanup_wq)
		return -ENOMEM;

	/* Install the completion callback before collecting any allocations. */
	rc = tracepoint_probe_register(binder_write_done_tp, line_binder_write_done, NULL);
	if (rc != LINE_SUCCESS)
		goto destroy_cleanup_wq;
	rc = tracepoint_probe_register(binder_alloc_buf_tp, line_binder_transaction_alloc_buf, NULL);
	if (rc != LINE_SUCCESS)
		goto unregister_write_done;

	return LINE_SUCCESS;

unregister_write_done:
	tracepoint_probe_unregister(binder_write_done_tp, line_binder_write_done, NULL);
	tracepoint_synchronize_unregister();
destroy_cleanup_wq:
	pr_err("register binder async cleanup tracepoints failed, rc=%d\n", rc);
	destroy_workqueue(binder_cleanup_wq);
	binder_cleanup_wq = NULL;
	return rc;
}

void unregister_binder_cleanup(void) {
	struct binder_cleanup_work *cleanup;
	struct hlist_node *next;
	int bucket;

	tracepoint_probe_unregister(binder_alloc_buf_tp, line_binder_transaction_alloc_buf, NULL);
	tracepoint_synchronize_unregister();
	tracepoint_probe_unregister(binder_write_done_tp, line_binder_write_done, NULL);
	tracepoint_synchronize_unregister();
	/* In-flight writes without write_done must only release their references. */
	hash_for_each_safe(binder_cleanup_pending, bucket, next, cleanup, entry) {
		hash_del(&cleanup->entry);
		queue_work(binder_cleanup_wq, &cleanup->work);
	}
	destroy_workqueue(binder_cleanup_wq);
	binder_cleanup_wq = NULL;
}
#endif
