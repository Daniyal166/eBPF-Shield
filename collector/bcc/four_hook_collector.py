
#!/usr/bin/env python3

# ============================================================
# eBPF-Shield — Four-Hook Filesystem Event Collector
#
# Hooks:
#   1. vfs_write
#   2. vfs_unlink
#   3. security_file_open
#   4. security_inode_rename
#
# Uses:
#   - BCC + eBPF
#   - Kernel-side cgroup filtering
#   - Perf buffer for structured event delivery
#
# Prototype for MS Cybersecurity Thesis
# ============================================================

from bcc import BPF
import argparse
import ctypes
import datetime

# ------------------------------------------------------------
# Command-line arguments
# ------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="eBPF-Shield Four-Hook Collector"
)

parser.add_argument(
    "--cgroup",
    type=int,
    required=True,
    help="Target Docker cgroup v2 ID"
)

args = parser.parse_args()

# ------------------------------------------------------------
# Embedded eBPF C program
# ------------------------------------------------------------

program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Event identifiers
#define EVENT_WRITE   1
#define EVENT_UNLINK  2
#define EVENT_OPEN    3
#define EVENT_RENAME  4

// Event structure shared with Python
struct event_t {
    u64 timestamp_ns;
    u64 cgroup_id;

    u32 tgid;
    u32 event_type;

    char comm[TASK_COMM_LEN];
};

// Target cgroup ID configured from Python
BPF_ARRAY(target_cgroup, u64, 1);

// Structured event output
BPF_PERF_OUTPUT(events);

// ------------------------------------------------------------
// Common event handler
// ------------------------------------------------------------

static int submit_event(
    struct pt_regs *ctx,
    u32 event_type
)
{
    u32 key = 0;

    u64 *target = target_cgroup.lookup(&key);

    if (!target)
        return 0;

    u64 current_cgroup = bpf_get_current_cgroup_id();

    // Kernel-side cgroup filtering
    if (current_cgroup != *target)
        return 0;

    struct event_t event = {};

    event.timestamp_ns = bpf_ktime_get_ns();
    event.cgroup_id = current_cgroup;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.tgid = pid_tgid >> 32;

    event.event_type = event_type;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    events.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );

    return 0;
}

// ------------------------------------------------------------
// Hook 1 — Filesystem write
// ------------------------------------------------------------

int trace_vfs_write(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_WRITE);
}

// ------------------------------------------------------------
// Hook 2 — File unlink
// ------------------------------------------------------------

int trace_vfs_unlink(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_UNLINK);
}

// ------------------------------------------------------------
// Hook 3 — File open security check
// ------------------------------------------------------------

int trace_security_file_open(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_OPEN);
}

// ------------------------------------------------------------
// Hook 4 — Inode rename security check
// ------------------------------------------------------------

int trace_security_inode_rename(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_RENAME);
}
"""

# ------------------------------------------------------------
# Compile eBPF program
# ------------------------------------------------------------

print("=" * 72)
print("                         eBPF-Shield")
print("                 Four-Hook Filesystem Collector")
print("=" * 72)

b = BPF(text=program)

# ------------------------------------------------------------
# Configure cgroup filter
# ------------------------------------------------------------

target_map = b["target_cgroup"]

target_map[ctypes.c_int(0)] = ctypes.c_ulonglong(
    args.cgroup
)

# ------------------------------------------------------------
# Attach four kernel probes
# ------------------------------------------------------------

hooks = [
    ("vfs_write", "trace_vfs_write"),
    ("vfs_unlink", "trace_vfs_unlink"),
    ("security_file_open", "trace_security_file_open"),
    ("security_inode_rename", "trace_security_inode_rename"),
]

for kernel_function, handler in hooks:

    b.attach_kprobe(
        event=kernel_function,
        fn_name=handler
    )

    print(f"[OK] Attached: {kernel_function}")

print()
print(f"[OK] Target cgroup ID: {args.cgroup}")
print("[OK] Kernel-side filtering enabled.")
print("[OK] Structured perf-buffer output enabled.")
print()

# ------------------------------------------------------------
# Python event structure
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# Event callback
# ------------------------------------------------------------

def handle_event(cpu, data, size):

    event = ctypes.cast(
        data,
        ctypes.POINTER(Event)
    ).contents

    event_name = EVENT_NAMES.get(
        event.event_type,
        "UNKNOWN"
    )

    process_name = event.comm.decode(
        "utf-8",
        errors="replace"
    ).rstrip("\x00")

    event_counts[event_name] = (
        event_counts.get(event_name, 0) + 1
    )

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


# ------------------------------------------------------------
# Open perf buffer
# ------------------------------------------------------------

b["events"].open_perf_buffer(
    handle_event,
    page_cnt=64,
    lost_cb=handle_lost_events
)

print("-" * 72)
print(
    f"{'TIME':<14} "
    f"{'EVENT':<8} "
    f"{'TGID':<10} "
    f"{'CGROUP':<12} "
    f"PROCESS"
)
print("-" * 72)

print("[INFO] Monitoring selected Docker cgroup.")
print("[INFO] Press Ctrl+C to stop.")
print()

# ------------------------------------------------------------
# Monitoring loop
# ------------------------------------------------------------

try:
    while True:
        b.perf_buffer_poll(timeout=1000)

except KeyboardInterrupt:

    print("\n" + "=" * 72)
    print("                  eBPF-Shield Event Summary")
    print("=" * 72)

    for name, count in event_counts.items():
        print(f"{name:<10}: {count}")

    print(f"LOST      : {lost_events}")

    print()
    print("[INFO] Monitoring stopped.")
