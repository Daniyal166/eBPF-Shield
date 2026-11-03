
#!/usr/bin/env python3
"""
eBPF-Shield - ML Feature Collector v1

Exports non-overlapping five-second filesystem activity windows
for controlled, labeled Docker experiments.

Labels:
    0 = benign workload
    1 = synthetic high-activity workload

These labels describe the test scenario, not confirmed ransomware.
"""

import argparse
import csv
import ctypes
import os
import time
from collections import Counter
from pathlib import Path

from bcc import BPF


parser = argparse.ArgumentParser(
    description="eBPF-Shield ML Feature Collector"
)

parser.add_argument("--cgroup", type=int, required=True)
parser.add_argument("--label", type=int, choices=[0, 1], required=True)
parser.add_argument("--run-id", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--window", type=float, default=5.0)

args = parser.parse_args()

if args.window <= 0:
    parser.error("--window must be positive")

if not args.run_id.strip():
    parser.error("--run-id cannot be empty")

EVENT_NAMES = {
    1: "WRITE",
    2: "UNLINK",
    3: "OPEN",
    4: "RENAME",
}

SCALES = {
    "WRITE": 10,
    "OPEN": 20,
    "RENAME": 3,
    "UNLINK": 3,
}

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define EVENT_WRITE 1
#define EVENT_UNLINK 2
#define EVENT_OPEN 3
#define EVENT_RENAME 4

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

int trace_vfs_write(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_WRITE);
}

int trace_security_file_open(struct pt_regs *ctx)
{
    return submit_event(ctx, EVENT_OPEN);
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

TRACEPOINT_PROBE(syscalls, sys_enter_unlink)
{
    return submit_event(args, EVENT_UNLINK);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat)
{
    return submit_event(args, EVENT_UNLINK);
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


OUTPUT_COLUMNS = [
    "run_id",
    "label",
    "cgroup_id",
    "window_index",
    "window_seconds",
    "write_count",
    "open_count",
    "rename_count",
    "unlink_count",
    "total_events",
    "brs_score",
    "lost_events",
]

counts = Counter()
lost_events = 0
window_index = 0


def calculate_brs(counts):
    score = 0.0

    for name, scale in SCALES.items():
        score += 0.25 * min(
            counts[name] / scale,
            1.0
        )

    return round(score, 3)


def handle_event(cpu, data, size):
    event = ctypes.cast(
        data,
        ctypes.POINTER(Event)
    ).contents

    name = EVENT_NAMES.get(event.event_type)

    if name is not None:
        counts[name] += 1


def handle_lost(cpu, count):
    global lost_events
    lost_events += count


def save_window(writer, output_file):
    global window_index
    global lost_events

    window_index += 1

    total = sum(counts.values())
    score = calculate_brs(counts)

    row = {
        "run_id": args.run_id,
        "label": args.label,
        "cgroup_id": args.cgroup,
        "window_index": window_index,
        "window_seconds": args.window,
        "write_count": counts["WRITE"],
        "open_count": counts["OPEN"],
        "rename_count": counts["RENAME"],
        "unlink_count": counts["UNLINK"],
        "total_events": total,
        "brs_score": score,
        "lost_events": lost_events,
    }

    # Skip completely idle windows, but preserve loss information.
    if total > 0 or lost_events > 0:
        writer.writerow(row)
        output_file.flush()

        print(
            f"[WINDOW {window_index}] "
            f"WRITE={counts['WRITE']} "
            f"OPEN={counts['OPEN']} "
            f"RENAME={counts['RENAME']} "
            f"UNLINK={counts['UNLINK']} "
            f"BRS={score:.3f} "
            f"LOST={lost_events}",
            flush=True
        )
    else:
        print(
            f"[WINDOW {window_index}] Idle - skipped",
            flush=True
        )

    counts.clear()
    lost_events = 0


def main():
    output_path = Path(args.output).expanduser()
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if output_path.exists():
        raise SystemExit(
            f"Output file already exists: {output_path}\n"
            "Use a new filename for each experiment."
        )

    print("=" * 65)
    print("              eBPF-Shield ML Feature Collector")
    print("=" * 65)

    b = BPF(text=BPF_PROGRAM)

    b["target_cgroup"][ctypes.c_int(0)] = (
        ctypes.c_ulonglong(args.cgroup)
    )

    b.attach_kprobe(
        event="vfs_write",
        fn_name="trace_vfs_write"
    )

    b.attach_kprobe(
        event="security_file_open",
        fn_name="trace_security_file_open"
    )

    b["events"].open_perf_buffer(
        handle_event,
        page_cnt=64,
        lost_cb=handle_lost
    )

    print(f"[OK] Cgroup : {args.cgroup}")
    print(f"[OK] Run ID : {args.run_id}")
    print(f"[OK] Label  : {args.label}")
    print(f"[OK] Window : {args.window} seconds")
    print(f"[OK] Output : {output_path}")
    print("[OK] Kernel probes and syscall tracepoints active")
    print("[INFO] Press Ctrl+C to stop.")

    # Exclusive creation protects existing experiment files.
    with output_path.open("x", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=OUTPUT_COLUMNS
        )
        writer.writeheader()
        f.flush()

        next_boundary = time.monotonic() + args.window

        try:
            while True:
                remaining = next_boundary - time.monotonic()

                if remaining > 0:
                    timeout_ms = max(
                        1,
                        min(250, int(remaining * 1000))
                    )
                    b.perf_buffer_poll(timeout=timeout_ms)
                else:
                    # Drain any queued events before closing window.
                    b.perf_buffer_poll(timeout=0)
                    save_window(writer, f)
                    next_boundary += args.window

                    if next_boundary <= time.monotonic():
                        next_boundary = (
                            time.monotonic() + args.window
                        )

        except KeyboardInterrupt:
            print()
            print("[INFO] Collector stopped.")
            print("[INFO] Incomplete final window discarded.")
            print(f"[INFO] Complete windows processed: {window_index}")
            print(f"[INFO] CSV saved: {output_path}")
            print(
                "[NOTE] Loss reports for an incomplete final "
                "window are not included."
            )


if __name__ == "__main__":
    main()
