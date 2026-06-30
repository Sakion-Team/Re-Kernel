// SPDX-License-Identifier: GPL-2.0
#ifndef RK_BINDER_TYPES_H
#define RK_BINDER_TYPES_H

#ifdef RK_DEFINE_BINDER_TYPES

#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

#if defined(__TARGET_ARCH_arm64)
struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};
#endif

struct binder_alloc {
	__u64 free_async_space;
};

struct binder_buffer {
	__u64 data_size;
	__u64 offsets_size;
	__u64 extra_buffers_size;
};

struct binder_proc {
	struct task_struct *tsk;
	struct binder_alloc alloc;
};

struct binder_thread {
	struct binder_proc *proc;
	struct binder_transaction *transaction_stack;
};

struct binder_transaction {
	struct binder_thread *from;
	unsigned int code;
	unsigned int flags;
};

#pragma clang attribute pop

#endif
#endif
