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
	bpf_probe_read_user_str(e->exec.filename,
				sizeof(e->exec.filename),
				(const char *)ctx->args[0]);

	const char **argv_ptr = (const char **)ctx->args[1];
	const char *arg2;
	bpf_probe_read_user(&arg2, sizeof(arg2), &argv_ptr[2]);
	if (arg2)
	    bpf_probe_read_user_str(e->exec.argv, sizeof(e->exec.argv), arg2);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct pw_event *e;
	struct task_struct *task;
	struct sockaddr_in addr = {};

	bpf_probe_read_user(&addr, sizeof(addr),
			    (void *)ctx->args[1]);

	if (addr.sin_family != 2) /* AF_INET */
		return 0;

	__u32 ip = addr.sin_addr.s_addr;

	/* skip loopback 127.x.x.x */
	if ((ip & 0xFF) == 127)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = PW_EVT_CONNECT;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->connect.addr_v4 = ip;
	e->connect.port = __builtin_bswap16(addr.sin_port);
	e->connect.family = addr.sin_family;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int handle_dup2(struct trace_event_raw_sys_enter *ctx)
{
	struct pw_event *e;
	struct task_struct *task;
	__s32 newfd = (__s32)ctx->args[1];

	/* only care about stdin(0), stdout(1), stderr(2) */
	if (newfd > 2)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->timestamp_ns = bpf_ktime_get_ns();
	e->event_type = PW_EVT_DUP;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->dup.oldfd = (__s32)ctx->args[0];
	e->dup.newfd = newfd;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    struct pw_event *e;
    struct task_struct *task;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = PW_EVT_MEMFD;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->memfd.flags = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct pw_event *e;
    struct task_struct *task;
    __u32 flags = (__u32)ctx->args[4];

    /* AT_EMPTY_PATH = 0x1000 - this is the fileless indicator */
    if (!(flags & 0x1000))
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = PW_EVT_EXECVEAT;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->execveat.dirfd = (__s32)ctx->args[0];
    e->execveat.flags = flags;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct pw_event *e;
    struct task_struct *task;
    __u32 request = (__u32)ctx->args[0];

    if (request != 16 && request != 0x4206)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = PW_EVT_PTRACE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->ptrace.request = request;
    e->ptrace.target_pid = (__u32)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int handle_vm_writev(struct trace_event_raw_sys_enter *ctx)
{
    struct pw_event *e;
    struct task_struct *task;
    __u32 target_pid = (__u32)ctx->args[0];
    __u32 self_pid = bpf_get_current_pid_tgid() >> 32;

    if (target_pid == self_pid)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = PW_EVT_VM_WRITEV;
    e->pid = self_pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->vm_writev.target_pid = target_pid;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct pw_event *e;
    struct task_struct *task;
    __u32 flags = (__u32)ctx->args[2];
    char prefix[7] = {};

    if ((flags & 3) == 0)
        return 0;

    bpf_probe_read_user_str(prefix, sizeof(prefix),
        (const char *)ctx->args[1]);

    int is_proc = (prefix[0] == '/' && prefix[1] == 'p' && prefix[2] == 'r' && prefix[3] == 'o' && prefix[4] == 'c' && prefix[5] =='/');
    int is_etc = (prefix[0] == '/' && prefix[1] == 'e' && prefix[2] == 't' && prefix[3] == 'c' && prefix[4] == '/');
    if (!is_proc && !is_etc)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = PW_EVT_FILE_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(e->file_open.path, sizeof(e->file_open.path), (const char *)ctx->args[1]);
    e->file_open.flags = flags;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx)
{
    struct pw_event *e;
    struct task_struct *task;
    __u32 cmd = (__u32)ctx->args[0];

    if (cmd != 5)
        return 0;

    __u32 self_pid = bpf_get_current_pid_tgid() >> 32;
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (comm[0] == 'p' && comm[1] == 'h' && comm[2] == 'a' && comm[3] == 'n' && comm[4] == 't' && comm[5] == 'o' && comm[6] == 'm')
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type = PW_EVT_BPF_LOAD;
    e->pid = self_pid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    __builtin_memcpy(e->comm, comm, 16);
    e->bpf_load.cmd = cmd;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
