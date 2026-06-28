/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_main.c
 * Description: Re:Kernel module init/exit. Brings up the netlink transport, then
 *              registers the binder / signal / netfilter / kprobe hooks (and
 *              tears them down in reverse on exit).
 * Author: nep_timeline@outlook.com
 * Last Modification:  2026/06/28
 */
#include "rekernel_internal.h"

static int __init start_rekernel(void)
{
	pr_info("Thank you for choosing Re:Kernel!\n");
#ifdef DEBUG
	pr_info("Debug mode is enabled!\n");
#endif

	if (rekernel_netlink_start() != LINE_SUCCESS)
		return LINE_ERROR;

	pr_info("Re-Kernel start hooking!\n");

	if (register_binder() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook binder!\n", __func__);
		return LINE_ERROR;
	}

	if (register_signal() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook signal!\n", __func__);
		return LINE_ERROR;
	}

	if (register_netfilter() != LINE_SUCCESS) {
		pr_err("%s: Failed to hook netfilter!\n", __func__);
		return LINE_ERROR;
	}

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
	unregister_netfilter();
	unregister_kp();
	rekernel_netlink_stop();
}

module_init(start_rekernel);
module_exit(exit_rekernel);

MODULE_LICENSE("GPL");
