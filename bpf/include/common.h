// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#ifndef __PHANTOMWATCH_COMMON_H__
#define __PHANTOMWATCH_COMMON_H__

#define MAX_PATH_LEN 256

enum pw_event_type {
    PW_EVT_EXEC = 1,
    PW_EVT_CONNECT = 2,
    PW_EVT_DUP = 3,
    PW_EVT_MEMFD = 4,
    PW_EVT_EXECVEAT = 5,
    PW_EVT_PTRACE = 6,
};


struct pw_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];

    union {
        struct {
            char filename[MAX_PATH_LEN];
            char argv[MAX_PATH_LEN];
        } exec;

        struct {
            __u32 addr_v4;
            __u16 port;
            __u16 family;
        } connect;

        struct {
            __s32 oldfd;
            __s32 newfd;
        } dup;

        struct {
            __s32 fd;
            __u32 flags;
        } memfd;

        struct {
            __s32 dirfd;
            __u32 flags;
        } execveat;

        struct {
            __u32 request;
            __u32 target_pid;
        } ptrace;
    };
};

#endif
