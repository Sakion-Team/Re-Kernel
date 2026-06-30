// SPDX-License-Identifier: GPL-2.0
#ifndef RK_BINDER_BPF_H
#define RK_BINDER_BPF_H

#include "rk_common.bpf.h"

struct rk_binder_transaction_data {
	union {
		__u32 handle;
		__u64 ptr;
	} target;
	__u64 cookie;
	__u32 code;
	__u32 flags;
	__s32 sender_pid;
	__u32 sender_euid;
	__u64 data_size;
	__u64 offsets_size;
	union {
		struct {
			__u64 buffer;
			__u64 offsets;
		} ptr;
		__u8 buf[8];
	} data;
};

struct rpc_stash {
	char  rpc_name[INTERFACETOKEN_BUFF_SIZE];
	__s32 code;
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct rpc_stash);
} async_stash SEC(".maps");

SEC("kprobe/binder_transaction")
int BPF_KPROBE(rk_binder_transaction, struct binder_proc *proc,
	       struct binder_thread *thread, struct binder_transaction_data *tr, int reply)
{
	if (reply) {
		struct binder_transaction *in;
		struct binder_proc *tproc;
		struct task_struct *ttsk, *stsk;
		struct rk_event *e;

		in = BPF_CORE_READ(thread, transaction_stack);
		if (!in)
			return 0;
		tproc = BPF_CORE_READ(in, from, proc);
		stsk  = BPF_CORE_READ(proc, tsk);
		if (!tproc || !stsk)
			return 0;
		ttsk = BPF_CORE_READ(tproc, tsk);
		if (!ttsk)
			return 0;
		if (task_uid(ttsk) > MAX_SYSTEM_UID)
			return 0;
		if (task_pid(stsk) == task_pid(ttsk))
			return 0;
		if (!task_is_frozen(ttsk))
			return 0;

		e = evt_reserve();
		if (!e)
			return 0;
		e->type              = RK_BINDER;
		e->binder.subtype    = RK_BINDER_REPLY;
		e->binder.oneway     = 0;
		e->binder.from_pid   = task_pid(stsk);
		e->binder.from_uid   = task_uid(stsk);
		e->binder.target_pid = task_pid(ttsk);
		e->binder.target_uid = task_uid(ttsk);
		e->binder.code       = -1;
		__builtin_memcpy(e->binder.rpc_name, "SYNC_BINDER_REPLY", sizeof("SYNC_BINDER_REPLY"));
		bpf_ringbuf_submit(e, 0);
		return 0;
	}

	struct rk_binder_transaction_data *trd = (void *)tr;
	if (BPF_PROBE_READ(trd, flags) & TF_ONE_WAY) {
		struct rpc_stash s = {};
		__u64 key = bpf_get_current_pid_tgid();
		const void *ubuf = (const void *)BPF_PROBE_READ(trd, data.ptr.buffer);
		__u64 dsize = BPF_PROBE_READ(trd, data_size);
		char tmp[INTERFACETOKEN_BUFF_SIZE] = {};
		__u32 rn = dsize < INTERFACETOKEN_BUFF_SIZE ? (__u32)dsize : INTERFACETOKEN_BUFF_SIZE;
		int oi = 0, j;

		s.code = BPF_PROBE_READ(trd, code);

		if (rn > PARCEL_OFFSET && ubuf &&
		    bpf_probe_read_user(tmp, rn & (INTERFACETOKEN_BUFF_SIZE - 1), ubuf) == 0) {
#pragma unroll
			for (j = PARCEL_OFFSET; j + 1 < INTERFACETOKEN_BUFF_SIZE; j += 2) {
				char c = tmp[j];
				if (c == '\0' || oi >= INTERFACETOKEN_BUFF_SIZE - 1)
					break;
				s.rpc_name[oi++] = c;
			}
		}
		s.rpc_name[oi] = '\0';
		bpf_map_update_elem(&async_stash, &key, &s, BPF_ANY);
	}
	return 0;
}

SEC("kprobe/binder_proc_transaction")
int BPF_KPROBE(rk_binder_proc_transaction, struct binder_transaction *t,
	       struct binder_proc *proc)
{
	struct task_struct *ttsk, *stsk = NULL;
	struct binder_proc *fproc;
	struct rk_event *e;
	__u32 flags, tuid;
	__s32 spid, tpid;
	__u8 oneway;

	if (!t || !proc)
		return 0;

	ttsk = BPF_CORE_READ(proc, tsk);
	if (!ttsk)
		return 0;
	tuid = task_uid(ttsk);
	if (tuid <= MIN_USERAPP_UID)
		return 0;

	fproc = BPF_CORE_READ(t, from, proc);
	if (fproc)
		stsk = BPF_CORE_READ(fproc, tsk);
	spid = stsk ? task_pid(stsk) : 0;
	tpid = task_pid(ttsk);
	if (spid == tpid)
		return 0;
	if (!task_is_frozen(ttsk))
		return 0;

	flags  = BPF_CORE_READ(t, flags);
	oneway = (flags & TF_ONE_WAY) ? 1 : 0;

	e = evt_reserve();
	if (!e)
		return 0;
	e->type              = RK_BINDER;
	e->binder.subtype    = RK_BINDER_TRANSACTION;
	e->binder.oneway     = oneway;
	e->binder.from_pid   = spid;
	e->binder.from_uid   = stsk ? task_uid(stsk) : 0;
	e->binder.target_pid = tpid;
	e->binder.target_uid = tuid;

	if (oneway) {
		__u64 key = bpf_get_current_pid_tgid();
		struct rpc_stash *s = bpf_map_lookup_elem(&async_stash, &key);
		if (s) {
			__builtin_memcpy(e->binder.rpc_name, s->rpc_name, sizeof(e->binder.rpc_name));
			e->binder.rpc_name[INTERFACETOKEN_BUFF_SIZE - 1] = '\0';
			e->binder.code = s->code;
			bpf_map_delete_elem(&async_stash, &key);
		} else {
			e->binder.rpc_name[0] = '\0';
			e->binder.code = BPF_CORE_READ(t, code);
		}
	} else {
		__builtin_memcpy(e->binder.rpc_name, "SYNC_BINDER", sizeof("SYNC_BINDER"));
		e->binder.code = -1;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("kprobe/binder_alloc_new_buf")
int BPF_KPROBE(rk_binder_alloc_new_buf, struct binder_alloc *alloc, __u64 data_size,
	       __u64 offsets_size, __u64 extra_buffers_size, int is_async)
{
	struct binder_proc *proc;
	struct task_struct *ttsk, *cur;
	struct rk_event *e;
	__u64 free_async, size, thresh;

	if (!alloc || !is_async)
		return 0;

	free_async = BPF_CORE_READ(alloc, free_async_space);
	size = ((data_size + 7) & ~7ULL) + ((offsets_size + 7) & ~7ULL) +
	       ((extra_buffers_size + 7) & ~7ULL);
	thresh = 3 * (size + sizeof(struct binder_buffer));
	if (!(free_async < thresh || free_async < WARN_AHEAD_SPACE))
		return 0;

	proc = (struct binder_proc *)((char *)alloc -
				      bpf_core_field_offset(struct binder_proc, alloc));
	ttsk = BPF_CORE_READ(proc, tsk);
	if (!ttsk || !task_is_frozen(ttsk))
		return 0;

	cur = (struct task_struct *)bpf_get_current_task();

	e = evt_reserve();
	if (!e)
		return 0;
	e->type              = RK_BINDER;
	e->binder.subtype    = RK_BINDER_FREE_BUFFER_FULL;
	e->binder.oneway     = 1;
	e->binder.from_pid   = task_pid(cur);
	e->binder.from_uid   = task_uid(cur);
	e->binder.target_pid = task_pid(ttsk);
	e->binder.target_uid = task_uid(ttsk);
	e->binder.code       = -1;
	__builtin_memcpy(e->binder.rpc_name, "FREE_BUFFER_FULL", sizeof("FREE_BUFFER_FULL"));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#endif
