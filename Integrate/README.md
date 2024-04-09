# Integrate Re:Kernel for non GKI or QGKI kernels
First, you should be able to build a bootable kernel from your kernel source code. If the kernel is not open source, this is almost impossible.

If you have made the above preparations, you can integrate Re:Kernel into your kernel as follows

## Modification
Firstly, you should create a header or source file to store the NETLINK code, with a UNIT of 26, a port of 100, and a packet size of 128
```C++
#include <linux/init.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_REKERNEL     			26
#define NETLINK_REKERNEL_VIVO     		25
#define USER_PORT          100
#define PACKET_SIZE        128

struct sock *netlink = NULL;
extern struct net init_net;
int netlink_unit = NETLINK_REKERNEL;

static int send_netlink_message(char *msg, uint16_t len) {
    struct sk_buff *skbuffer;
    struct nlmsghdr *nlhdr;

    skbuffer = nlmsg_new(len, GFP_ATOMIC);
    if (!skbuffer) {
        printk("netlink alloc failure.\n");
        return -1;
    }

    nlhdr = nlmsg_put(skbuffer, 0, 0, NETLINK_REKERNEL, len, 0);
    if (!nlhdr) {
        printk("nlmsg_put failaure.\n");
        nlmsg_free(skbuffer);
        return -1;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return netlink_unicast(netlink, skbuffer, USER_PORT, MSG_DONTWAIT);
}

static void netlink_rcv_msg(struct sk_buff *skbuffer) { // Ignore recv msg.
}

struct netlink_kernel_cfg cfg = { 
    .input = netlink_rcv_msg,
};

static const struct proc_ops rekernel_unit_fops = {
	.proc_open   = rekernel_unit_open,
	.proc_read   = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release   = single_release,
};

static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;

static int start_rekernel_server(void) {
  if (netlink)
    return 0;
  nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_REKERNEL, &cfg);
  if (nlsk == NULL) {
        nlsk = (struct sock *)netlink_kernel_create(&init_net, NETLINK_REKERNEL_VIVO, &cfg);
        if (nlsk == NULL) {
    		printk("Failed to create Re:Kernel server!\n");
    		return -1;
    	}
        netlink_unit = NETLINK_REKERNEL_VIVO;
  }
  rekernel_dir = proc_mkdir("rekernel", NULL);
  if (!rekernel_dir)
      printk("create /proc/rekernel failed!\n");
  else {
      char buff[32];
      sprintf(buff, "%d", netlink_unit);
      rekernel_unit_entry = proc_create(buff, 0644, rekernel_dir, &rekernel_unit_fops);
      if (!rekernel_unit_entry)
          printk("create rekernel unit failed!\n");
  }
  return 0;
}
```
Then, add the calls to the kernel source code as follows:
```C++
// drivers/android/binder.c
static void binder_transaction(struct binder_proc *proc,
			       struct binder_thread *thread,
			       struct binder_transaction_data *tr, int reply,
			       binder_size_t extra_buffers_size)
{
........
    if (target_thread->transaction_stack != in_reply_to) {
			binder_user_error("%d:%d got reply transaction with bad target transaction stack %d, expected %d\n",
				proc->pid, thread->pid,
				target_thread->transaction_stack ?
				target_thread->transaction_stack->debug_id : 0,
				in_reply_to->debug_id);
			binder_inner_proc_unlock(target_thread->proc);
			return_error = BR_FAILED_REPLY;
			return_error_param = -EPROTO;
			return_error_line = __LINE__;
			in_reply_to = NULL;
			target_thread = NULL;
			goto err_dead_binder;
    }
		target_proc = target_thread->proc;
		target_proc->tmp_ref++;
		binder_inner_proc_unlock(target_thread->proc);
+   		if (start_rekernel_server() == 0) {
+     			char binder_kmsg[PACKET_SIZE];
+         		snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=%d,from=%d,target=%d;", tr->flags & TF_ONE_WAY, task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
+         		send_usrmsg(binder_kmsg, strlen(binder_kmsg));
+   		}
	} else {
		if (tr->target.handle) {
			struct binder_ref *ref;

			/*
			 * There must already be a strong ref
			 * on this node. If so, do a strong
			 * increment on the node to ensure it
			 * stays alive until the transaction is
			 * done.
			 */
			binder_proc_lock(proc);
			ref = binder_get_ref_olocked(proc, tr->target.handle,
						     true);
			if (ref) {
				target_node = binder_get_node_refs_for_txn(
						ref->node, &target_proc,
						&return_error);
			} else {
				binder_user_error("%d:%d got transaction to invalid handle\n",
						  proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
			}
			binder_proc_unlock(proc);
		} else {
			mutex_lock(&context->context_mgr_node_lock);
			target_node = context->binder_context_mgr_node;
			if (target_node)
				target_node = binder_get_node_refs_for_txn(
						target_node, &target_proc,
						&return_error);
			else
				return_error = BR_DEAD_REPLY;
			mutex_unlock(&context->context_mgr_node_lock);
			if (target_node && target_proc->pid == proc->pid) {
				binder_user_error("%d:%d got transaction to context manager from process owning it\n",
						  proc->pid, thread->pid);
				return_error = BR_FAILED_REPLY;
				return_error_param = -EINVAL;
				return_error_line = __LINE__;
				goto err_invalid_target_handle;
			}
		}
		if (!target_node) {
			/*
			 * return_error is set above
			 */
			return_error_param = -EINVAL;
			return_error_line = __LINE__;
			goto err_dead_binder;
		}
		e->to_node = target_node->debug_id;
+   		if (start_rekernel_server() == 0) {
+     			char binder_kmsg[PACKET_SIZE];
+         		snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from=%d,target=%d;", tr->flags & TF_ONE_WAY, task_uid(proc->tsk).val, task_uid(target_proc->tsk).val);
+         		send_usrmsg(binder_kmsg, strlen(binder_kmsg));
+   		}
		if (security_binder_transaction(proc->cred,
						target_proc->cred) < 0) {
			return_error = BR_FAILED_REPLY;
			return_error_param = -EPERM;
			return_error_line = __LINE__;
			goto err_invalid_target_handle;
		}
		binder_inner_proc_lock(proc);
........
}
```
```C++
// kernel/signal.c
int do_send_sig_info(int sig, struct siginfo *info, struct task_struct *p,
			bool group)
{
	unsigned long flags;
	int ret = -ESRCH;
+ 	if (sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT) {
+ 		if (start_rekernel_server() == 0) {
+     			char binder_kmsg[PACKET_SIZE];
+     			snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer=%d,dst=%d;", sig, task_uid(p).val, task_uid(current).val);
+     			send_usrmsg(binder_kmsg, strlen(binder_kmsg));
+ 		}
+ 	}
	if (lock_task_sighand(p, &flags)) {
		ret = send_signal(sig, info, p, group);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}
```
You should find the two functions in kernel source:

binder_transaction, usually in `drivers/android/binder.c`

do_send_sig_info, usually in `kernel/signal.c`

Finally, build your kernel again, Re:Kernel will be integrated into your kernel.
