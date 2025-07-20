#!/bin/bash

PATCHDIR=${0%/*}

[ -d drivers/rekernel ] || mkdir -p drivers/rekernel
cp -rp $PATCHDIR/rekernel/* drivers/rekernel/

rekernel_file=drivers/rekernel/rekernel.c
if grep -q 'struct proc_ops' include/linux/proc_fs.h; then
	sed -i 's/file_operations/proc_ops/' $rekernel_file
	sed -i 's/.open/.proc_open/' $rekernel_file
	sed -i 's/.read/.proc_read/' $rekernel_file
	sed -i 's/.llseek/.proc_llseek/' $rekernel_file
	sed -i 's/.release/.proc_release/' $rekernel_file
fi

patch_files=(
	arch/arm64/configs/defconfig
	drivers/Kconfig
	drivers/Makefile
	drivers/android/binder.c
	kernel/signal.c
)
for i in "${patch_files[@]}"; do

	if grep -iq "rekernel" $i; then
		echo "Warning: $i contains Re:Kernel"
		continue
	fi

	case $i in
	# Makefile
	arch/arm64/configs/defconfig)
		sed -i '$a\
CONFIG_REKERNEL=y\
CONFIG_REKERNEL_NETWORK=n' $i
		;;
	drivers/Kconfig)
		sed -i '/endmenu/i\
\
source "drivers/rekernel/Kconfig"' $i
		;;
	drivers/Makefile)
		sed -i '$a\
obj-$(CONFIG_REKERNEL) += rekernel/' $i
		;;

	# binder.c
	drivers/android/binder.c)
		if ! grep -q 'binder_proc_transaction() - sends a transaction to a process and wakes it up' $i; then
			echo "Error: Could not find 'binder_proc_transaction()' in $i"
			continue
		fi
		if ! grep -q 'binder_enqueue_work_ilocked(&t->work, &proc->todo)' $i; then
			echo "Error: Could not find 'binder_enqueue_work_ilocked(&t->work, &proc->todo);' in $i"
			continue
		fi
		sed -i '/#include <uapi\/linux\/android\/binder.h>/i\
#ifdef CONFIG_REKERNEL\
#include <../rekernel/rekernel.h>\
#endif /* CONFIG_REKERNEL */' $i

		if grep -q 'binder_find_outdated_transaction_ilocked' $i; then
			sed -i '/if ((t1->flags & t2->flags & (TF_ONE_WAY | TF_UPDATE_TXN)) !=/i\
#ifdef CONFIG_REKERNEL\
	if ((t1->flags & t2->flags & TF_ONE_WAY) != TF_ONE_WAY || !t1->to_proc || !t2->to_proc)\
#else' $i
			sed -i '/(TF_ONE_WAY | TF_UPDATE_TXN) || !t1->to_proc || !t2->to_proc)/a\
#endif /* CONFIG_REKERNEL */' $i

			sed -i '/if ((t->flags & TF_UPDATE_TXN) && proc->is_frozen) {/i\
#ifdef CONFIG_REKERNEL\
		if (frozen_task_group(proc->tsk)) {\
#else' $i
			sed -i '/if ((t->flags & TF_UPDATE_TXN) && proc->is_frozen) {/a\
#endif /* CONFIG_REKERNEL */' $i
		else
			binder_proc_transaction_line=$(awk '/binder_proc_transaction\(\) - sends a transaction to a process and wakes it up/{print NR}' $i)
			sed -i ''"$((binder_proc_transaction_line - 1))"'i\
#ifdef CONFIG_REKERNEL\
/**\
 * binder_can_update_transaction() - Can a txn be superseded by an updated one?\
 * @t1: the pending async txn in the frozen process\
 * @t2: the new async txn to supersede the outdated pending one\
 *\
 * Return:	true if t2 can supersede t1\
 *			false if t2 can not supersede t1\
 */\
static bool binder_can_update_transaction(struct binder_transaction *t1,\
						struct binder_transaction *t2)\
{\
	if ((t1->flags & t2->flags & TF_ONE_WAY) != TF_ONE_WAY || !t1->to_proc || !t2->to_proc)\
		return false;\
	if (t1->to_proc->tsk == t2->to_proc->tsk && t1->code == t2->code &&\
		t1->flags == t2->flags && t1->buffer->pid == t2->buffer->pid &&\
		t1->buffer->target_node->ptr == t2->buffer->target_node->ptr &&\
		t1->buffer->target_node->cookie == t2->buffer->target_node->cookie)\
		return true;\
	return false;\
}\
\
/**\
 * binder_find_outdated_transaction_ilocked() - Find the outdated transaction\
 * @t:		 new async transaction\
 * @target_list: list to find outdated transaction\
 *\
 * Return:	the outdated transaction if found\
 *			NULL if no outdated transacton can be found\
 *\
 * Requires the proc->inner_lock to be held.\
 */\
static struct binder_transaction *\
binder_find_outdated_transaction_ilocked(struct binder_transaction *t,\
					 struct list_head *target_list)\
{\
	struct binder_work *w;\
\
	list_for_each_entry(w, target_list, entry) {\
		struct binder_transaction *t_queued;\
\
		if (w->type != BINDER_WORK_TRANSACTION)\
			continue;\
		t_queued = container_of(w, struct binder_transaction, work);\
		if (binder_can_update_transaction(t_queued, t))\
			return t_queued;\
	}\
	return NULL;\
}\
#endif /* CONFIG_REKERNEL */\
' $i
			if ! grep -q 'pid to attribute the buffer to (caller)' drivers/android/binder_alloc.h; then
				sed -i 's/t1->flags == t2->flags && t1->buffer->pid == t2->buffer->pid &&/t1->flags == t2->flags \&\&/' $i
			fi

			sed -i '/bool pending_async = false;/a\
#ifdef CONFIG_REKERNEL\
	struct binder_transaction *t_outdated = NULL;\
#endif /* CONFIG_REKERNEL */' $i

			binder_enqueue_work_ilocked_line=$(awk '/binder_enqueue_work_ilocked\(&t->work, &proc->todo\);/{print NR}' $i)
				sed -i ''"$((binder_enqueue_work_ilocked_line + 1))"'a\
#ifdef CONFIG_REKERNEL\
		if (frozen_task_group(proc->tsk)) {\
			t_outdated = binder_find_outdated_transaction_ilocked(t,\
											&node->async_todo);\
			if (t_outdated) {\
				list_del_init(&t_outdated->work.entry);\
				proc->outstanding_txns--;\
			}\
		}\
#endif /* CONFIG_REKERNEL */' $i
			if ! grep -q 'proc->outstanding_txns++;' $i; then
				sed -i '/proc->outstanding_txns--;/d' $i
			fi

			binder_enqueue_work_ilocked_line=$(awk '/binder_enqueue_work_ilocked\(&t->work, &proc->todo\);/{print NR}' $i)
			binder_node_unlock_line=$(awk 'NR >= '"$binder_enqueue_work_ilocked_line"' && /binder_node_unlock\(node\);/{print NR; exit}' $i)
			sed -i ''"$binder_node_unlock_line"'a\
\
#ifdef CONFIG_REKERNEL\
	/*\
	 * To reduce potential contention, free the outdated transaction and\
	 * buffer after releasing the locks.\
	 */\
	if (t_outdated) {\
		struct binder_buffer *buffer = t_outdated->buffer;\
\
		t_outdated->buffer = NULL;\
		buffer->transaction = NULL;\
		binder_release_entire_buffer(proc, NULL, buffer, false);\
		binder_alloc_free_buf(&proc->alloc, buffer);\
		kfree(t_outdated);\
		binder_stats_deleted(BINDER_STAT_TRANSACTION);\
	}\
#endif /* CONFIG_REKERNEL */' $i
			if ! grep -q 'static inline void binder_release_entire_buffer' $i; then
				if grep -q 'binder_transaction_buffer_release(proc, buffer, 0, false);' $i; then
					sed -i 's/binder_release_entire_buffer(proc, NULL, buffer, false);/binder_transaction_buffer_release(proc, buffer, 0, false);/' $i
				elif grep -q 'binder_transaction_buffer_release(proc, buffer, NULL);' $i; then
					sed -i 's/binder_release_entire_buffer(proc, NULL, buffer, false);/binder_transaction_buffer_release(proc, buffer, NULL);/' $i
				else
					echo "Error: Could not find 'binder_transaction_buffer_release' in $i"
				fi
			fi
		fi

		binder_proc_transaction_line=$(awk '/binder_proc_transaction\(\) - sends a transaction to a process and wakes it up/{print NR}' $i)
		sed -i ''"$((binder_proc_transaction_line - 1))"'i\
#ifdef CONFIG_REKERNEL\
void rekernel_binder_transaction(bool reply, struct binder_transaction *t,\
			struct binder_node *target_node, struct binder_transaction_data *tr) {\
	struct binder_proc *to_proc;\
	struct binder_alloc *target_alloc;\
	if (!t->to_proc)\
		return;\
	to_proc = t->to_proc;\
\
	if (reply) {\
		binder_reply_handler(task_tgid_nr(current), current, to_proc->pid, to_proc->tsk, false, tr);\
	} else if (t->from) {\
		if (t->from->proc) {\
			binder_trans_handler(t->from->proc->pid, t->from->proc->tsk, to_proc->pid, to_proc->tsk, false, tr);\
		}\
	} else { // oneway=1\
		binder_trans_handler(task_tgid_nr(current), current, to_proc->pid, to_proc->tsk, true, tr);\
\
		target_alloc = &to_proc->alloc;\
		if (target_alloc->free_async_space < (target_alloc->buffer_size / 10 + 0x300)) {\
			binder_overflow_handler(task_tgid_nr(current), current, to_proc->pid, to_proc->tsk, true, tr);\
		}\
	}\
}\
#endif /* CONFIG_REKERNEL */\
' $i
		sed -i '/trace_binder_transaction(reply, t, target_node);/i\
#ifdef CONFIG_REKERNEL\
	rekernel_binder_transaction(reply, t, target_node, tr);\
#endif /* CONFIG_REKERNEL */' $i
		;;

	# signal.c
	kernel/signal.c)
		sed -i '/#include <asm\/cacheflush.h>/a\
#ifdef CONFIG_REKERNEL\
#include <uapi/asm/signal.h>\
#include <../drivers/rekernel/rekernel.h>\
#endif /* CONFIG_REKERNEL */' $i

		sed -i '/int ret = -ESRCH;/a\
#ifdef CONFIG_REKERNEL\
	if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT)\
		rekernel_report(SIGNAL, sig, task_tgid_nr(current), current, task_tgid_nr(p), p, false, NULL);\
#endif /* CONFIG_REKERNEL */' $i
		;;
	esac
done
