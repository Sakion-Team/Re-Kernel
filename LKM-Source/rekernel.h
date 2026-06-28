#ifndef REKERNEL_H
#define REKERNEL_H

/* Re:Kernel version, single source of truth (used in logs and the version query). */
#define REKERNEL_VERSION                "9.5"

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

/*
 * Legacy raw-netlink protocol (used only when LEGACY_NETLINK is defined).
 * Command types from userspace.
 */
enum rekernel_cmd_type {
	REKERNEL_CMD_REMOVE_PROC = 1,
	REKERNEL_CMD_ADD_MONITOR_NET = 2,
	REKERNEL_CMD_DEL_MONITOR_NET = 3,
	REKERNEL_CMD_KILL_NET = 4,
};

struct rekernel_cmd {
	int type;
};

struct rekernel_monitor_net_args {
	int uid;
};

struct rekernel_kill_net_args {
	int pid;
};

/*
 * Generic Netlink protocol (used when LEGACY_NETLINK is NOT defined).
 * This is the ABI contract with the userspace daemon: the daemon resolves
 * the family by name via CTRL_CMD_GETFAMILY, joins the multicast group to
 * receive events, and sends MONITOR_NET / DEL_MONITOR_NET / KILL_NET commands.
 * There is no REMOVE_PROC command: genl does not create /proc/rekernel.
 */
#define REKERNEL_GENL_FAMILY_NAME       "rekernel"
#define REKERNEL_GENL_VERSION           1
#define REKERNEL_GENL_MCGRP_NAME        "events"

/* generic netlink commands */
enum rekernel_genl_cmd {
	REKERNEL_C_UNSPEC,
	REKERNEL_C_EVENT,            /* kernel -> user, multicast event (REKERNEL_A_MSG) */
	REKERNEL_C_ADD_MONITOR_NET,      /* user -> kernel, add uid (carries REKERNEL_A_UID) */
	REKERNEL_C_DEL_MONITOR_NET,  /* user -> kernel, remove uid (carries REKERNEL_A_UID) */
	REKERNEL_C_KILL_NET,         /* user -> kernel, kill a pid's TCP/UDP sockets (carries REKERNEL_A_PID) */
	REKERNEL_C_GET_VERSION,      /* user -> kernel, query version; kernel replies unicast with REKERNEL_A_MSG */
	__REKERNEL_C_MAX,
};
#define REKERNEL_C_MAX (__REKERNEL_C_MAX - 1)

/* generic netlink attributes */
enum rekernel_genl_attr {
	REKERNEL_A_UNSPEC,
	REKERNEL_A_MSG,   /* string: event payload in the legacy "key=value,...;" format */
	REKERNEL_A_UID,   /* u32: uid to monitor for MONITOR_NET */
	REKERNEL_A_PID,   /* u32: pid whose sockets KILL_NET should destroy */
	__REKERNEL_A_MAX,
};
#define REKERNEL_A_MAX (__REKERNEL_A_MAX - 1)

#endif
