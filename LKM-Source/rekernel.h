#ifndef FREEZER_GKI_H
#define FREEZER_GKI_H

// define on your own
// #define KERNEL_5_10
// #define KERNEL_5_15
// #define KERNEL_6_1

#define NETWORK_FILTER

#define MIN_USERAPP_UID (10000)
#define MAX_SYSTEM_UID  (2000)
#define RESERVE_ORDER					17
#define WARN_AHEAD_SPACE				(1 << RESERVE_ORDER)
#define LINE_ERROR (-1)
#define LINE_SUCCESS (0)

#endif
