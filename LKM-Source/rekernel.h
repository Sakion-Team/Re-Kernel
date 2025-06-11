#ifndef REKERNEL_H
#define REKERNEL_H

// define on your own
// #define KERNEL_5_10
// #define KERNEL_5_15
// #define KERNEL_6_1
// #define KERNEL_6_6
// #define KERNEL_6_12

#define MIN_USERAPP_UID                 (10000)
#define MAX_SYSTEM_UID                  (2000)
#define SYSTEM_APP_UID                  (1000)
#define RESERVE_ORDER					          17
#define WARN_AHEAD_SPACE				        (1 << RESERVE_ORDER)
#define INTERFACETOKEN_BUFF_SIZE        (140)
#define PARCEL_OFFSET                   (16) /* sync with the writeInterfaceToken */
#define LINE_ERROR                      (-1)
#define LINE_SUCCESS                    (0)

#endif
