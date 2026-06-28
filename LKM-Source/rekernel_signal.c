/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_signal.c
 * Description: Re:Kernel signal hook. Emits an event when a fatal signal is
 *              delivered to a frozen task, via the android_vh_do_send_sig_info
 *              vendor hook.
 */
#include <linux/signal.h>
#include <trace/hooks/signal.h>
#include "rekernel_internal.h"

static void line_signal(void *data, int sig, struct task_struct *killer, struct task_struct *dst)
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
		if (rekernel_netlink_ready()) {
			char binder_kmsg[PACKET_SIZE];
			int len = scnprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", sig, task_tgid_nr(killer), task_uid(killer).val, task_tgid_nr(dst), task_uid(dst).val);
			sendMessage(binder_kmsg, len);
		}
	}
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

void unregister_signal(void)
{
	unregister_trace_android_vh_do_send_sig_info(line_signal, NULL);
}
