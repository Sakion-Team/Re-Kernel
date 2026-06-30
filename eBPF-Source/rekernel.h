#ifndef REKERNEL_EBPF_H
#define REKERNEL_EBPF_H

#define INTERFACETOKEN_BUFF_SIZE        140
#define PARCEL_OFFSET                   16

#define RK_BINDER                       1
#define RK_SIGNAL                       2
#define RK_NETWORK                      3

#define RK_BINDER_TRANSACTION           0
#define RK_BINDER_REPLY                 1
#define RK_BINDER_FREE_BUFFER_FULL      2

#define RK_PROTO_IPV4                   4
#define RK_PROTO_IPV6                   6

struct rk_binder_event {
	__u8  subtype;
	__u8  oneway;
	__s32 from_pid;
	__s32 from_uid;
	__s32 target_pid;
	__s32 target_uid;
	__s32 code;
	char  rpc_name[INTERFACETOKEN_BUFF_SIZE];
};

struct rk_signal_event {
	__s32 sig;
	__s32 killer_pid;
	__s32 killer_uid;
	__s32 dst_pid;
	__s32 dst_uid;
};

struct rk_network_event {
	__u8  proto;
	__s32 target_uid;
	__s32 data_len;
};

struct rk_event {
	__u8 type;
	union {
		struct rk_binder_event  binder;
		struct rk_signal_event  signal;
		struct rk_network_event network;
	};
};

#define REKERNEL_SOCKET_NAME            "rekernel"
#define REKERNEL_VERSION                "10.0-ebpf"

#endif
