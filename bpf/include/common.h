// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#ifndef __PHANTOMWATCH_COMMON_H__
#define __PHANTOMWATCH_COMMON_H__

#define MAX_PATH_LEN 256

enum pw_event_type {
    PW_EVT_EXEC = 1,
    PW_EVT_CONNECT = 2,
};


struct pw_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[MAX_PATH_LEN];
};

#endif
