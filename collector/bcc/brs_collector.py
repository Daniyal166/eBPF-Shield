
#!/usr/bin/env python3

# ============================================================
# eBPF-Shield — Behavioral Risk Scoring Prototype
# Four eBPF hooks + Docker cgroup filtering + BRS
#
# Detection only: no process termination or file modification
# ============================================================

from bcc import BPF
import argparse
import ctypes
import time
from collections import deque

parser = argparse.ArgumentParser(
    description="eBPF-Shield Behavioral Risk Scoring"
)

parser.add_argument(
    "--cgroup",
    type=int,
    required=True,
    help="Target Docker cgroup v2 ID"
)

args = parser.parse_args()

# ------------------------------------------------------------
# BRS configuration (initial demonstration values)
# ------------------------------------------------------------

WINDOW_SECONDS = 5.0
ALERT_THRESHOLD = 0.60
ALERT_COOLDOWN = 5.0
REPORT_INTERVAL = 2.0

# Event counts needed for a normalized feature score of 1.0.
# These are demonstration settings, not calibrated thresholds.
NORMALIZATION = {
    "WRITE": 10,
    "OPEN": 20,
    "RENAME": 3,
    "UNLINK": 3,
}

WEIGHTS = {
    "WRITE": 0.25,
    "OPEN": 0.25,
    "RENAME": 0.25,
    "UNLINK": 0.25,
}

EVENT_NAMES = {
    1: "WRITE",
    2: "UNLINK",
    3: "OPEN",
    4: "RENAME",
}

# ------------------------------------------------------------
# eBPF kernel program
# ------------------------------------------------------------

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

static int submit_event(struct pt_regs *ctx, u32 event_type)
{
    u32 key = 0;
    u64 *target = target_cgroup.lookup(&key);

    if (!target)
        return 0;

    u64 cgroup_id = bpf_get_current_cgroup_id();

    // Drop events from other cgroups in kernel space.
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

int trace_vfs_write(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_WRITE);
}

int trace_vfs_unlink(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_UNLINK);
}

int trace_security_file_open(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_OPEN);
}

int trace_security_inode_rename(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_RENAME);
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


# ------------------------------------------------------------
# Behavioral scoring
# ------------------------------------------------------------

# Each record contains (receipt_time, event_name).
# Scoring is aggregated at the selected container/cgroup level.
window_events = deque()

total_counts = {
    name: 0 for name in NORMALIZATION
}

lost_events = 0
last_alert_time = 0.0
last_report_time = time.monotonic()

def remove_expired_events(now):
    cutoff = now - WINDOW_SECONDS

    while window_events and window_events[0][0] < cutoff:
        window_events.popleft()


def calculate_score(now):
    remove_expired_events(now)

    counts = {
        name: 0 for name in NORMALIZATION
    }

    for _, event_name in window_events:
        if event_name in counts:
            counts[event_name] += 1

    score = 0.0

    for name, count in counts.items():
        normalized = min(
            count / NORMALIZATION[name],
            1.0
        )

        score += WEIGHTS[name] * normalized

    return round(score, 3), counts


def handle_event(cpu, data, size):
    global last_alert_time

    event = ctypes.cast(
        data,
        ctypes.POINTER(Event)
    ).contents

    event_name = EVENT_NAMES.get(event.event_type)

    if event_name is None:
        return

    now = time.monotonic()

    window_events.append((now, event_name))
    total_counts[event_name] += 1

    score, counts = calculate_score(now)

    if score >= ALERT_THRESHOLD:
        if now - last_alert_time >= ALERT_COOLDOWN:
            process_name = event.comm.decode(
                "utf-8",
                errors="replace"
            ).rstrip("\x00")

            print()
            print("!" * 64)
            print("[ALERT] eBPF-Shield: Elevated filesystem activity")
            print(f"[ALERT] Cgroup ID : {event.cgroup_id}")
            print(f"[ALERT] Risk Score: {score:.3f}")
            print(f"[ALERT] Threshold : {ALERT_THRESHOLD:.2f}")
            print(f"[ALERT] Last Event: {event_name}")
            print(f"[ALERT] Last TGID : {event.tgid}")
            print(f"[ALERT] Process   : {process_name}")
            print(f"[ALERT] Counts   : {counts}")
            print("[ACTION] Alert only — no containment performed")
            print("!" * 64)
            print()

            last_alert_time = now


def handle_lost_events(cpu, count):
    global lost_events

    lost_events += count

    print(
        f"[WARNING] Perf buffer lost {count} events on CPU {cpu}",
        flush=True
    )


# ------------------------------------------------------------
# Initialize collector
# ------------------------------------------------------------

print("=" * 64)
print("                        eBPF-Shield")
print("              Behavioral Risk Scoring Engine")
print("=" * 64)

b = BPF(text=program)

target_map = b["target_cgroup"]

target_map[ctypes.c_int(0)] = ctypes.c_ulonglong(
    args.cgroup
)

hooks = [
    ("vfs_write", "trace_vfs_write"),
    ("vfs_unlink", "trace_vfs_unlink"),
    ("security_file_open", "trace_security_file_open"),
    ("security_inode_rename", "trace_security_inode_rename"),
]

for function, handler in hooks:
    b.attach_kprobe(event=function, fn_name=handler)
    print(f"[OK] Attached: {function}")

b["events"].open_perf_buffer(
    handle_event,
    page_cnt=64,
    lost_cb=handle_lost_events
)

print("-" * 64)
print(f"[OK] Target Docker cgroup: {args.cgroup}")
print(f"[OK] Scoring window     : {WINDOW_SECONDS} seconds")
print(f"[OK] Alert threshold    : {ALERT_THRESHOLD:.2f}")
print("[OK] Detection-only mode")
print("[INFO] Monitoring started. Press Ctrl+C to stop.")
print("-" * 64)


# ------------------------------------------------------------
# Main monitoring loop
# ------------------------------------------------------------

try:
    while True:
        b.perf_buffer_poll(timeout=250)

        now = time.monotonic()

        if now - last_report_time >= REPORT_INTERVAL:
            score, counts = calculate_score(now)

            print(
                f"[BRS] Score={score:.3f} "
                f"WRITE={counts['WRITE']} "
                f"OPEN={counts['OPEN']} "
                f"RENAME={counts['RENAME']} "
                f"UNLINK={counts['UNLINK']}",
                flush=True
            )

            last_report_time = now

except KeyboardInterrupt:
    print()
    print("=" * 64)
    print("                 eBPF-Shield Final Summary")
    print("=" * 64)

    for name, count in total_counts.items():
        print(f"{name:<10}: {count}")

    print(f"LOST      : {lost_events}")
    print("[INFO] BRS monitoring stopped.")
