// SPDX-License-Identifier: GPL-2.0
#ifndef RK_SIGNAL_BPF_H
#define RK_SIGNAL_BPF_H

#include "rk_common.bpf.h"

SEC("kprobe/do_send_sig_info")
int BPF_KPROBE(rk_do_send_sig_info, int sig, void *info, struct task_struct *dst)
{
	struct task_struct *killer;
	struct rk_event *e;

	if (!dst)
		return 0;
	if (sig != SIGKILL && sig != SIGTERM && sig != SIGABRT && sig != SIGQUIT)
		return 0;
	if (!task_is_frozen(dst))
		return 0;

	killer = (struct task_struct *)bpf_get_current_task();

	e = evt_reserve();
	if (!e)
		return 0;
	e->type              = RK_SIGNAL;
	e->signal.sig        = sig;
	e->signal.killer_pid = task_pid(killer);
	e->signal.killer_uid = task_uid(killer);
	e->signal.dst_pid    = task_pid(dst);
	e->signal.dst_uid    = task_uid(dst);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

#endif
