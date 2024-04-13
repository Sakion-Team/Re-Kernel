# 为非GKI或QGKI内核集成Re:Kernel
在开始前，你必须有能力从你设备的内核源码编译出一个可以开机并且能正常使用的内核，如果内核不开源，这通常难以做到。

如果你已经做好了上述准备，那么你就可以按照以下方法将Re:Kernel集成到你的内核当中

## 修改
首先 你应该创建一个头或源文件 里面存放NETLINK的代码 其UNIT应为26 用户端口为100 包体大小为128
```C++
#include <linux/init.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>

#define NETLINK_REKERNEL_MAX     		26
#define NETLINK_REKERNEL_MIN     		22
#define USER_PORT        			100
#define PACKET_SIZE 				128

struct sock *rekernel_netlink = NULL;
extern struct net init_net;
int netlink_unit = NETLINK_REKERNEL_MIN;

static int send_netlink_message(char *msg, uint16_t len) {
    struct sk_buff *skbuffer;
    struct nlmsghdr *nlhdr;

    skbuffer = nlmsg_new(len, GFP_ATOMIC);
    if (!skbuffer) {
        printk("netlink alloc failure.\n");
        return -1;
    }

    nlhdr = nlmsg_put(skbuffer, 0, 0, netlink_unit, len, 0);
    if (!nlhdr) {
        printk("nlmsg_put failaure.\n");
        nlmsg_free(skbuffer);
        return -1;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return netlink_unicast(rekernel_netlink, skbuffer, USER_PORT, MSG_DONTWAIT);
}

static void netlink_rcv_msg(struct sk_buff *skbuffer) { // Ignore recv msg.
}

struct netlink_kernel_cfg rekernel_cfg = { 
    .input = netlink_rcv_msg,
};

static int rekernel_unit_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%d\n", netlink_unit);
	return 0;
}

static int rekernel_unit_open(struct inode *inode, struct file *file)
{
	return single_open(file, rekernel_unit_show, NULL);
}

static const struct file_operations rekernel_unit_fops = {
	.open   = rekernel_unit_open,
	.read   = seq_read,
	.llseek   = seq_lseek,
	.release   = single_release,
	.owner   = THIS_MODULE,
};

static struct proc_dir_entry *rekernel_dir, *rekernel_unit_entry;

static int start_rekernel_server(void) {
  if (rekernel_netlink)
    return 0;
  for (netlink_unit = NETLINK_REKERNEL_MIN; netlink_unit < NETLINK_REKERNEL_MAX; netlink_unit++) {
    rekernel_netlink = (struct sock *)netlink_kernel_create(&init_net, netlink_unit, &rekernel_cfg);
    if (rekernel_netlink != NULL)
      break;
  }
  printk("Created Re:Kernel server! NETLINK UNIT: %d\n", netlink_unit);
  if (rekernel_netlink == NULL) {
    printk("Failed to create Re:Kernel server!\n");
    return -1;
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
然后，将调用添加到内核源代码中，如下:
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
+                       snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
+         		send_netlink_message(binder_kmsg, strlen(binder_kmsg));
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
+                       snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;",  tr->flags & TF_ONE_WAY, proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
+         		send_netlink_message(binder_kmsg, strlen(binder_kmsg));
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
+     			send_netlink_message(binder_kmsg, strlen(binder_kmsg));
+ 		}
+ 	}
	if (lock_task_sighand(p, &flags)) {
		ret = send_signal(sig, info, p, group);
		unlock_task_sighand(p, &flags);
	}

	return ret;
}
```
主要修改两个地方：

binder_transaction，通常位于 drivers/android/binder.c

do_send_sig_info，通常位于 kernel/signal.c

改完之后重新编译内核，Re:Kernel将会融入你的内核当中。
