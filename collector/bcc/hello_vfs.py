
#!/usr/bin/env python3

from bcc import BPF
import argparse
import ctypes

# ============================================================
# eBPF-Shield — VFS Write Monitor
# Host-level eBPF with kernel-side cgroup filtering
# ============================================================

parser = argparse.ArgumentParser(
    description="eBPF-Shield: Monitor filesystem writes by cgroup"
)

parser.add_argument(
    "--cgroup",
    type=int,
    required=True,
    help="Numeric cgroup v2 ID to monitor"
)

args = parser.parse_args()

# This C code executes inside the Linux kernel.
program = r"""
#include <uapi/linux/ptrace.h>

// Holds the target cgroup ID provided by Python.
BPF_ARRAY(target_cgroup, u64, 1);

int trace_vfs_write(struct pt_regs *ctx)
{
    u32 key = 0;

    u64 *target = target_cgroup.lookup(&key);

    if (!target)
        return 0;

    u64 cgroup_id = bpf_get_current_cgroup_id();

    // Ignore events from unrelated cgroups.
    if (cgroup_id != *target)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;

    bpf_trace_printk("WRITE tgid=%u cgroup=%llu\n",
                     tgid, cgroup_id);

    return 0;
}
"""

print("=" * 60)
print("                 eBPF-Shield")
print("           Kernel VFS Write Monitor")
print("=" * 60)

# Compile the eBPF C program.
b = BPF(text=program)

# Configure the target cgroup in a BPF map.
target_map = b["target_cgroup"]

target_map[ctypes.c_int(0)] = ctypes.c_ulonglong(args.cgroup)

# Attach to the Linux kernel's vfs_write function.
b.attach_kprobe(
    event="vfs_write",
    fn_name="trace_vfs_write"
)

print("[OK] vfs_write kprobe attached.")
print(f"[OK] Kernel-side cgroup filter: {args.cgroup}")
print("[INFO] Monitoring matching filesystem writes only.")
print("[INFO] Press Ctrl+C to stop.")
print("-" * 60)

# Read events from the kernel's temporary trace buffer.
try:
    while True:
        task, pid, cpu, flags, ts, msg = b.trace_fields()

        # Decode bytes and display a clean event line.
        if isinstance(task, bytes):
            task = task.decode("utf-8", errors="replace")

        if isinstance(msg, bytes):
            msg = msg.decode("utf-8", errors="replace")

        print(
            f"[{ts:12.6f}] "
            f"PROCESS={task:<16} "
            f"{msg}",
            flush=True
        )

except KeyboardInterrupt:
    print("\n[INFO] Monitoring stopped.")

