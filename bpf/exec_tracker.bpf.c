// SPDX-License-Identifier: (GPL-2.0-only OR BSD-3-Clause)


#include "include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "include/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

    struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
    } events SEC(".maps");

    SEC("tracepoint/syscalls/sys_enter_execve")
    int handle_execve(struct trace_event_raw_sys_enter *ctx)
    {
        struct pw_event *e;
        struct task_struct *task;

        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            return 0;

        e->timestamp_ns = bpf_ktime_get_ns();
        e->event_type = PW_EVT_EXEC;
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

        task = (struct task_struct *)bpf_get_current_task();
        e->ppid = BPF_CORE_READ(task, real_parent, tgid);

        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_probe_read_user_str(e->filename, sizeof(e->filename),
            (const char *)ctx->args[0]);

        bpf_ringbuf_submit(e, 0);
        return 0;
    }
