#ifndef REKERNEL_H
#define REKERNEL_H

#define CLEAN_UP_ASYNC_BINDER

#define MIN_USERAPP_UID                 (10000)
#define MAX_SYSTEM_UID                  (2000)
#define SYSTEM_APP_UID                  (1000)
#define RESERVE_ORDER					17
#define WARN_AHEAD_SPACE				(1 << RESERVE_ORDER)
#define INTERFACETOKEN_BUFF_SIZE        (140)
#define PARCEL_OFFSET                   (16) /* sync with the writeInterfaceToken */
#define LINE_ERROR                      (-1)
#define LINE_SUCCESS                    (0)

/* command types from userspace */
enum rekernel_cmd_type {
	REKERNEL_CMD_REMOVE_PROC = 1,
	REKERNEL_CMD_MONITOR_NET = 2,
};

struct rekernel_cmd {
	int type;
};

struct rekernel_monitor_net_args {
	int uid;
};

#endif
