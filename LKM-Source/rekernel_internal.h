/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_internal.h
 * Description: kernel-internal glue shared between the Re:Kernel module's
 *              translation units. (rekernel.h holds the on-the-wire ABI shared
 *              with userspace; this header is kernel-only and is NOT part of the
 *              userspace contract.)
 */
#ifndef REKERNEL_INTERNAL_H
#define REKERNEL_INTERNAL_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/freezer.h>
#include <linux/cgroup.h>
#include "rekernel.h"

#define USER_PORT			100
#define PACKET_SIZE			256

/* ---- freeze-state predicate (shared by binder / signal / netfilter) ---- */

static inline bool rekernel_is_frozen_state_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
	return READ_ONCE(task->__state) & TASK_FROZEN;
#else
	return frozen(task);
#endif
}

static inline bool rekernel_is_jobctl_frozen_compatible(struct task_struct *task)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 10, 0))
	return cgroup_task_freeze(task);
#else
	return ((task->jobctl & JOBCTL_TRAP_FREEZE) != 0);
#endif
}

static inline bool line_is_frozen(struct task_struct *task)
{
	if (cgroup_task_frozen(task) || rekernel_is_jobctl_frozen_compatible(task))
		return true;

	/* if task->group_leader is NULL, unfreeze it to avoid some unknown problems */
	if (NULL == task->group_leader)
		return true;

	return rekernel_is_frozen_state_compatible(task->group_leader) || freezing(task->group_leader);
}

/* ---- netlink transport (rekernel_netlink.c) ---- */
int sendMessage(char *packet_buffer, uint16_t len);
bool rekernel_netlink_ready(void);
int rekernel_netlink_start(void);
void rekernel_netlink_stop(void);

/* ---- network-monitor uid map (rekernel_netfilter.c) ---- */
void net_uid_add(uid_t uid);
void net_uid_del(uid_t uid);

/* ---- hook (un)registration ---- */
int register_binder(void);
void unregister_binder(void);
int register_signal(void);
void unregister_signal(void);
int register_netfilter(void);
void unregister_netfilter(void);
int register_kp(void);
void unregister_kp(void);

#endif /* REKERNEL_INTERNAL_H */
