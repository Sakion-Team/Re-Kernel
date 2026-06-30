// SPDX-License-Identifier: GPL-2.0
#ifndef RK_COMMON_BPF_H
#define RK_COMMON_BPF_H

#include "vmlinux.h"
#include "rk_binder_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "rekernel.h"

extern int LINUX_KERNEL_VERSION __kconfig;
#define KVER(a, b, c) (((a) << 16) + ((b) << 8) + (c))

#define TF_ONE_WAY              0x01
#define MIN_USERAPP_UID         10000
#define MAX_SYSTEM_UID          2000
#define RESERVE_ORDER           17
#define WARN_AHEAD_SPACE        (1UL << RESERVE_ORDER)

#define SIGQUIT                 3
#define SIGABRT                 6
#define SIGKILL                 9
#define SIGTERM                 15

#define PF_FROZEN               0x00010000
#define TASK_FROZEN             0x00008000
#define JOBCTL_TRAP_FREEZE      (1UL << 23)

#define AF_INET                 2
#define AF_INET6                10

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} net_uid_map SEC(".maps");

struct task_struct___old { long state; } __attribute__((preserve_access_index));
struct task_struct___new { unsigned int __state; } __attribute__((preserve_access_index));

static __always_inline unsigned int task_state(struct task_struct *t)
{
	struct task_struct___new *n = (void *)t;
	if (bpf_core_field_exists(n->__state))
		return BPF_CORE_READ(n, __state);
	struct task_struct___old *o = (void *)t;
	return (unsigned int)BPF_CORE_READ(o, state);
}

static __always_inline __u32 task_uid(struct task_struct *t)
{
	return BPF_CORE_READ(t, cred, uid.val);
}

static __always_inline __s32 task_pid(struct task_struct *t)
{
	return BPF_CORE_READ(t, tgid);
}

static __always_inline bool task_is_frozen(struct task_struct *task)
{
	struct task_struct *gl;

	if (!task)
		return false;

	if (bpf_core_field_exists(task->frozen) &&
	    BPF_CORE_READ_BITFIELD_PROBED(task, frozen))
		return true;

	if (BPF_CORE_READ(task, jobctl) & JOBCTL_TRAP_FREEZE)
		return true;

	gl = BPF_CORE_READ(task, group_leader);
	if (!gl)
		return true;

	if (LINUX_KERNEL_VERSION >= KVER(6, 1, 0)) {
		if (task_state(gl) & TASK_FROZEN)
			return true;
	} else {
		if (BPF_CORE_READ(gl, flags) & PF_FROZEN)
			return true;
	}

	return false;
}

static __always_inline struct rk_event *evt_reserve(void)
{
	return bpf_ringbuf_reserve(&events, sizeof(struct rk_event), 0);
}

#endif
