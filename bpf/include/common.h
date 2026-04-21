// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)
#ifndef __PHANTOMWATCH_COMMON_H__
#define __PHANTOMWATCH_COMMON_H__

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

enum pw_event_type {
    PW_EVT_EXEC = 1,
    PW_EVT_CONNECT = 2,
}
