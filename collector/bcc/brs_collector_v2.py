
#!/usr/bin/env python3

# ============================================================
# eBPF-Shield — Behavioral Risk Scoring Engine v2
# Kernel probes + syscall-aware rename/unlink counting
#
# Detection only — no process termination
# ============================================================

from bcc import BPF
import argparse
import ctypes
import time
from collections import deque

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

parser = argparse.ArgumentParser(
    description="eBPF-Shield BRS v2"
)

parser.add_argument(
    "--cgroup",
    type=int,
    required=True,
    help="Target Docker cgroup v2 ID"
)

parser.add_argument(
    "--threshold",
    type=float,
    default=0.60,
    help="Alert threshold (default: 0.60)"
)

args = parser.parse_args()

if not 0.0 <= args.threshold <= 1.0:
    parser.error("--threshold must be between 0 and 1")

WINDOW_SECONDS = 5.0
ALERT_COOLDOWN = 5.0
REPORT_INTERVAL = 2.0

# Initial demonstration settings — not calibrated.
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
# eBPF C program
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
    event.tgid = bpf_get_current_pid_tgid() >> 32;
    event.event_type = event_type;

    bpf_get_current_comm(
        &event.comm,
        sizeof(event.comm)
    );

    events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}

// Kernel-level filesystem observations

int trace_vfs_write(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_WRITE);
}

int trace_security_file_open(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_OPEN);
}

// Syscall-entry rename requests

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

// Syscall-entry unlink requests

TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    return submit_event(args, EVENT_UNLINK);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    return submit_event(args, EVENT_UNLINK);
}
"""

# ------------------------------------------------------------
# Shared event structure
# ------------------------------------------------------------

class Event(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("cgroup_id", ctypes.c_uint64),
        ("tgid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
    ]

# ------------------------------------------------------------
# Behavioral Risk Scoring
# ------------------------------------------------------------

window_events = deque()

total_counts = {
    name: 0 for name in NORMALIZATION
}

lost_events = 0
last_alert_time = None
last_report_time = time.monotonic()
max_observed_score = 0.0
alert_count = 0


def calculate_score(now):
    cutoff = now - WINDOW_SECONDS

    while window_events and window_events[0][0] < cutoff:
        window_events.popleft()

    counts = {
        name: 0 for name in NORMALIZATION
    }

    for timestamp, event_name in window_events:
        counts[event_name] += 1

    score = 0.0

    for event_name, count in counts.items():
        normalized = min(
            count / NORMALIZATION[event_name],
            1.0
        )
        score += WEIGHTS[event_name] * normalized

    return round(score, 3), counts


def handle_event(cpu, data, size):
    global last_alert_time
    global max_observed_score
    global alert_count

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

    max_observed_score = max(
        max_observed_score,
        score
    )

    if score >= args.threshold:
        if (
            last_alert_time is None
            or now - last_alert_time >= ALERT_COOLDOWN
        ):
            process = event.comm.decode(
                "utf-8",
                errors="replace"
            ).rstrip("\x00")

            alert_count += 1
            last_alert_time = now

            print()
            print("!" * 65)
            print("[ALERT] eBPF-Shield BRS v2")
            print(f"[ALERT] Cgroup ID : {event.cgroup_id}")
            print(f"[ALERT] Risk Score: {score:.3f}")
            print(f"[ALERT] Threshold : {args.threshold:.2f}")
            print(f"[ALERT] Last TGID : {event.tgid}")
            print(f"[ALERT] Process   : {process}")
            print(f"[ALERT] Last Event: {event_name}")
            print(f"[ALERT] Counts   : {counts}")
            print("[ACTION] Detection only — no containment")
            print("!" * 65)
            print()


def handle_lost_events(cpu, count):
    global lost_events

    lost_events += count

    print(
        f"[WARNING] Lost {count} perf events on CPU {cpu}",
        flush=True
    )


# ------------------------------------------------------------
# Initialize and attach probes
# ------------------------------------------------------------

print("=" * 65)
print("                       eBPF-Shield")
print("              Behavioral Risk Scoring v2")
print("=" * 65)

b = BPF(text=program)

target_map = b["target_cgroup"]

target_map[ctypes.c_int(0)] = ctypes.c_ulonglong(
    args.cgroup
)

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

# TRACEPOINT_PROBE functions are automatically attached by BCC.
print("[OK] Syscall tracepoints:")
print("     rename, renameat, renameat2")
print("     unlink, unlinkat")

b["events"].open_perf_buffer(
    handle_event,
    page_cnt=64,
    lost_cb=handle_lost_events
)

print("-" * 65)
print(f"[OK] Docker cgroup  : {args.cgroup}")
print(f"[OK] Scoring window : {WINDOW_SECONDS} seconds")
print(f"[OK] Alert threshold: {args.threshold:.2f}")
print("[OK] Syscall-aware RENAME/UNLINK counting")
print("[OK] Detection-only mode")
print("[INFO] Press Ctrl+C to stop.")
print("-" * 65)

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
                f"[BRS-v2] Score={score:.3f} "
                f"WRITE={counts['WRITE']} "
                f"OPEN={counts['OPEN']} "
                f"RENAME={counts['RENAME']} "
                f"UNLINK={counts['UNLINK']}",
                flush=True
            )

            last_report_time = now

except KeyboardInterrupt:
    print()
    print("=" * 65)
    print("                  eBPF-Shield BRS v2 Summary")
    print("=" * 65)

    for name, count in total_counts.items():
        print(f"{name:<10}: {count}")

    print(f"ALERTS    : {alert_count}")
    print(f"MAX BRS   : {max_observed_score:.3f}")
    print(f"LOST      : {lost_events}")
    print("[INFO] Monitoring stopped.")
