
#!/usr/bin/env python3

# ============================================================
# eBPF-Shield — Syscall-Aware Filesystem Collector
#
# Kernel hooks:
#   vfs_write
#   security_file_open
#
# Syscall tracepoints:
#   sys_enter_unlink
#   sys_enter_unlinkat
#   sys_enter_rename
#   sys_enter_renameat
#   sys_enter_renameat2
#
# Detection only — no process termination
# ============================================================

from bcc import BPF
import argparse
import ctypes
import datetime

parser = argparse.ArgumentParser(
    description="eBPF-Shield Syscall-Aware Collector"
)

parser.add_argument(
    "--cgroup",
    type=int,
    required=True,
    help="Target Docker cgroup v2 ID"
)

args = parser.parse_args()

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_WRITE   1
#define EVENT_UNLINK  2
#define EVENT_OPEN    3
#define EVENT_RENAME  4

struct event_t {
    u64 timestamp_ns;
    u64 cgroup_id;
    u32 tgid;
    u32 event_type;
    char comm[TASK_COMM_LEN];
};

BPF_ARRAY(target_cgroup, u64, 1);
BPF_PERF_OUTPUT(events);

static int submit_event(void *ctx, u32 event_type)
{
    u32 key = 0;

    u64 *target = target_cgroup.lookup(&key);

    if (!target)
        return 0;

    u64 cgroup_id = bpf_get_current_cgroup_id();

    if (cgroup_id != *target)
        return 0;

    struct event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.cgroup_id = cgroup_id;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.tgid = pid_tgid >> 32;

    event.event_type = event_type;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

// Kernel-level probes
int trace_vfs_write(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_WRITE);
}

int trace_security_file_open(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_OPEN);
}

// Syscall-entry tracepoints
TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    return submit_event(args, EVENT_UNLINK);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    return submit_event(args, EVENT_UNLINK);
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename)
{
    return submit_event(args, EVENT_RENAME);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat)
{
    return submit_event(args, EVENT_RENAME);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2)
{
    return submit_event(args, EVENT_RENAME);
}
"""


class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("cgroup_id", ctypes.c_uint64),
        ("tgid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]


EVENT_NAMES = {
    1: "WRITE",
    2: "UNLINK",
    3: "OPEN",
    4: "RENAME",
}

event_counts = {
    "WRITE": 0,
    "UNLINK": 0,
    "OPEN": 0,
    "RENAME": 0,
}

lost_events = 0


def handle_event(cpu, data, size):
    event = ctypes.cast(
        data,
        ctypes.POINTER(Event)
    ).contents

    event_name = EVENT_NAMES.get(
        event.event_type,
        "UNKNOWN"
    )

    event_counts[event_name] = (
        event_counts.get(event_name, 0) + 1
    )

    process_name = event.comm.decode(
        "utf-8",
        errors="replace"
    ).rstrip("\x00")

    timestamp = datetime.datetime.now().strftime(
        "%H:%M:%S.%f"
    )[:-3]

    print(
        f"{timestamp:<14} "
        f"{event_name:<8} "
        f"{event.tgid:<10} "
        f"{event.cgroup_id:<12} "
        f"{process_name}",
        flush=True
    )


def handle_lost_events(cpu, count):
    global lost_events

    lost_events += count

    print(
        f"[WARNING] Lost {count} events on CPU {cpu}",
        flush=True
    )


print("=" * 72)
print("                        eBPF-Shield")
print("                 Syscall-Aware Collector")
print("=" * 72)

b = BPF(text=program)

target_map = b["target_cgroup"]
target_map[ctypes.c_int(0)] = ctypes.c_ulonglong(
    args.cgroup
)

# Attach kernel probes
b.attach_kprobe(
    event="vfs_write",
    fn_name="trace_vfs_write"
)
print("[OK] Attached: vfs_write")

b.attach_kprobe(
    event="security_file_open",
    fn_name="trace_security_file_open"
)
print("[OK] Attached: security_file_open")

# TRACEPOINT_PROBE handlers attach automatically in BCC.
print("[OK] Syscall-entry tracepoints configured:")
print("     unlink, unlinkat, rename, renameat, renameat2")

b["events"].open_perf_buffer(
    handle_event,
    page_cnt=64,
    lost_cb=handle_lost_events
)

print()
print(f"[OK] Target cgroup: {args.cgroup}")
print("[OK] Kernel-side cgroup filtering enabled.")
print("[INFO] Monitoring started. Press Ctrl+C to stop.")
print("-" * 72)

print(
    f"{'TIME':<14} "
    f"{'EVENT':<8} "
    f"{'TGID':<10} "
    f"{'CGROUP':<12} "
    f"PROCESS"
)
print("-" * 72)

try:
    while True:
        b.perf_buffer_poll(timeout=1000)

except KeyboardInterrupt:
    print()
    print("=" * 72)
    print("                 eBPF-Shield Event Summary")
    print("=" * 72)

    for name, count in event_counts.items():
        print(f"{name:<10}: {count}")

    print(f"LOST      : {lost_events}")
    print("[INFO] Monitoring stopped.")
