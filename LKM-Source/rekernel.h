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

#define REKERNEL_FAMILY_VERSION  1
#define REKERNEL_FAMILY  "rekernel"
#define GENL_ID_GENERATE    0
#define NLA_DATA(na) ((char *)((char *)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD(len) (len - NLA_HDRLEN)

/* attribute type */
enum {
    REKERNEL_ATTR_UNSPEC = 0,
    REKERNEL_ATTR_UID,
    REKERNEL_ATTR_MSG,
    __REKERNEL_ATTR_MAX,
};
#define REKERNEL_ATTR_MAX (__REKERNEL_ATTR_MAX - 1)

/* cmd type */
enum {
    REKERNEL_CMD_UNSPEC = 0,
    REKERNEL_CMD_ADD_MONITOR,
    REKERNEL_CMD_DEL_MONITOR,
    REKERNEL_CMD_SEND_MSG,
    __REKERNEL_CMD_MAX,
};
#define REKERNEL_CMD_MAX (__REKERNEL_CMD_MAX - 1)

#endif
