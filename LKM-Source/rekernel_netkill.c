/*
 * Copyright (c) Sakion Team. All rights reserved.
 *
 * File name: rekernel_netkill.c
 */
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <net/sock.h>
#include "rekernel_internal.h"

/*
 * ponytail: cap sockets-per-kill at 1024. A real app holds far fewer TCP/UDP
 * fds; if one legitimately exceeds this, raise the bound (8KB/kill at 1024).
 * The array is preallocated because the iterate_fd callback runs under the
 * files spinlock and must not sleep.
 */
#define REKERNEL_MAX_KILL_SOCKS 1024

struct rekernel_sock_set {
	struct sock **socks;
	int count;
};

/*
 * iterate_fd callback: runs under files->file_lock (atomic context). Only pins
 * matching sockets here (sock_hold is atomic); the actual abort, which sleeps
 * in lock_sock(), happens later outside the lock.
 */
static int rekernel_collect_socket(const void *p, struct file *file, unsigned fd)
{
	struct rekernel_sock_set *set = (struct rekernel_sock_set *)p;
	struct socket *sock;
	struct sock *sk;

	if (set->count >= REKERNEL_MAX_KILL_SOCKS)
		return 1; /* array full: stop iterating */

	if (!S_ISSOCK(file_inode(file)->i_mode))
		return 0;

	sock = file->private_data; /* socket files store their struct socket here */
	if (!sock)
		return 0;
	sk = sock->sk;
	if (!sk)
		return 0;

	if ((sk->sk_family == AF_INET || sk->sk_family == AF_INET6) &&
	    (sk->sk_protocol == IPPROTO_TCP || sk->sk_protocol == IPPROTO_UDP)) {
		sock_hold(sk);
		set->socks[set->count++] = sk;
	}
	return 0;
}

int rekernel_kill_net_connections(pid_t pid)
{
	struct task_struct *task;
	struct files_struct *files;
	struct pid *pid_struct;
	struct rekernel_sock_set set;
	int i, killed = 0;

	pid_struct = find_get_pid(pid);
	if (!pid_struct)
		return -ESRCH;
	task = get_pid_task(pid_struct, PIDTYPE_PID);
	put_pid(pid_struct);
	if (!task)
		return -ESRCH;

	set.count = 0;
	set.socks = kmalloc_array(REKERNEL_MAX_KILL_SOCKS, sizeof(struct sock *), GFP_KERNEL);
	if (!set.socks) {
		put_task_struct(task);
		return -ENOMEM;
	}

	/*
	 * Hold task_lock across iterate_fd: it keeps task->files from being torn
	 * down (exit_files() also takes task_lock before clearing ->files) without
	 * needing the unexported get/put_files_struct, and the callback never
	 * sleeps so nesting the file spinlock under it is safe.
	 */
	task_lock(task);
	files = task->files;
	if (files)
		iterate_fd(files, 0, rekernel_collect_socket, &set);
	task_unlock(task);

	/* Sockets are pinned by our own refs now; the task ref is no longer needed. */
	put_task_struct(task);

	for (i = 0; i < set.count; i++) {
		struct sock *sk = set.socks[i];

		if (sk->sk_prot && sk->sk_prot->diag_destroy) {
			sk->sk_prot->diag_destroy(sk, ECONNABORTED);
			killed++;
		}
		sock_put(sk);
	}
	kfree(set.socks);

#ifdef DEBUG
	pr_info("[Re-Kernel LKM] killNet pid=%d killed=%d\n", pid, killed);
#endif
	return killed;
}
