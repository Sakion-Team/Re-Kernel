#ifndef RK_FORMAT_H
#define RK_FORMAT_H

#include <stdio.h>
#include "rekernel.h"

static inline int rk_format(const struct rk_event *e, char *out, int cap)
{
	switch (e->type) {
	case RK_BINDER: {
		const struct rk_binder_event *b = &e->binder;
		const char *bt = b->subtype == RK_BINDER_REPLY ? "reply"
			       : b->subtype == RK_BINDER_FREE_BUFFER_FULL ? "free_buffer_full"
			       : "transaction";
		return snprintf(out, cap,
			"type=Binder,bindertype=%s,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d,rpc_name=%s,code=%d;",
			bt, b->oneway, b->from_pid, b->from_uid,
			b->target_pid, b->target_uid, b->rpc_name, b->code);
	}
	case RK_SIGNAL: {
		const struct rk_signal_event *s = &e->signal;
		return snprintf(out, cap,
			"type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;",
			s->sig, s->killer_pid, s->killer_uid, s->dst_pid, s->dst_uid);
	}
	case RK_NETWORK: {
		const struct rk_network_event *n = &e->network;
		return snprintf(out, cap,
			"type=Network,target=%d,proto=%s,data_len=%d;",
			n->target_uid, n->proto == RK_PROTO_IPV6 ? "ipv6" : "ipv4",
			n->data_len);
	}
	default:
		return 0;
	}
}

#endif
