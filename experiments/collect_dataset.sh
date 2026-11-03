#!/usr/bin/env bash
#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# eBPF-Shield — Automated ML Experiment Controller
#
# Usage:
#   sudo ./experiments/collect_dataset.sh benign run001
#   sudo ./experiments/collect_dataset.sh synthetic run002
#
# Labels:
#   benign    = 0
#   synthetic = 1
#
# Synthetic means high filesystem activity, NOT ransomware.
# ============================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

COLLECTOR="$PROJECT_DIR/collector/bcc/brs_feature_collector.py"
WORKLOAD="$PROJECT_DIR/experiments/run_workload.sh"

DATA_DIR="$PROJECT_DIR/ml/datasets"
LOG_DIR="$PROJECT_DIR/results/experiment_logs"

CGROUP_ID="11658"
WINDOW_SECONDS=5

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <benign|synthetic> <run_id>"
    exit 1
fi

MODE="$1"
RUN_ID="$2"

if [[ "$MODE" != "benign" && "$MODE" != "synthetic" ]]; then
    echo "[ERROR] Mode must be benign or synthetic"
    exit 1
fi

if [[ ! "$RUN_ID" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "[ERROR] Invalid run ID"
    exit 1
fi

if [[ "$MODE" == "benign" ]]; then
    LABEL=0
else
    LABEL=1
fi

mkdir -p "$DATA_DIR" "$LOG_DIR"

CSV_FILE="$DATA_DIR/${MODE}_${RUN_ID}.csv"
LOG_FILE="$LOG_DIR/${MODE}_${RUN_ID}.log"

if [[ -e "$CSV_FILE" || -e "$LOG_FILE" ]]; then
    echo "[ERROR] Experiment files already exist."
    echo "[INFO] Use a unique run ID."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run this script using sudo."
    exit 1
fi

COLLECTOR_PID=""

cleanup() {
    if [[ -n "$COLLECTOR_PID" ]]; then
        if kill -0 "$COLLECTOR_PID" 2>/dev/null; then
            kill -TERM "$COLLECTOR_PID" 2>/dev/null || true

            for i in $(seq 1 20); do
                if ! kill -0 "$COLLECTOR_PID" 2>/dev/null; then
                    break
                fi
                sleep 0.1
            done

            if kill -0 "$COLLECTOR_PID" 2>/dev/null; then
                echo "[WARNING] Collector did not stop; forcing termination."
                kill -KILL "$COLLECTOR_PID" 2>/dev/null || true
            fi

            wait "$COLLECTOR_PID" 2>/dev/null || true
        fi
    fi
}

trap cleanup EXIT
trap 'exit 130' INT TERM

echo "================================================"
echo "          eBPF-Shield ML Data Collection"
echo "================================================"
echo "[INFO] Mode     : $MODE"
echo "[INFO] Label    : $LABEL"
echo "[INFO] Run ID   : $RUN_ID"
echo "[INFO] Cgroup   : $CGROUP_ID"
echo "[INFO] Window   : $WINDOW_SECONDS seconds"
echo "[INFO] CSV      : $CSV_FILE"
echo "[INFO] Log      : $LOG_FILE"
echo "================================================"

echo "[STEP 1] Starting eBPF collector..."

python3 -u "$COLLECTOR" \
    --cgroup "$CGROUP_ID" \
    --label "$LABEL" \
    --run-id "${MODE}_${RUN_ID}" \
    --window "$WINDOW_SECONDS" \
    --output "$CSV_FILE" \
    > "$LOG_FILE" 2>&1 &

COLLECTOR_PID=$!

# Allow time for BCC compilation and probe attachment.
sleep 8

if ! kill -0 "$COLLECTOR_PID" 2>/dev/null; then
    echo "[ERROR] Collector exited unexpectedly."
    cat "$LOG_FILE"
    exit 1
fi

if ! grep -q "Kernel probes and syscall tracepoints active" "$LOG_FILE"; then
    echo "[ERROR] Collector did not become ready."
    cat "$LOG_FILE"
    exit 1
fi

echo "[OK] Collector is running."

echo "[STEP 2] Executing Docker workload..."

"$WORKLOAD" "$MODE" "$RUN_ID"

echo "[STEP 3] Completing observation window..."

# Wait long enough for the current window to close.
sleep $((WINDOW_SECONDS + 2))

echo "[STEP 4] Stopping collector..."

cleanup
COLLECTOR_PID=""

echo "[STEP 5] Checking CSV output..."

if [[ ! -f "$CSV_FILE" ]]; then
    echo "[ERROR] CSV file was not created."
    exit 1
fi

ROW_COUNT=$(($(wc -l < "$CSV_FILE") - 1))

if [[ "$ROW_COUNT" -le 0 ]]; then
    echo "[WARNING] No active feature windows collected."
    echo "[INFO] Check the experiment log:"
    echo "$LOG_FILE"
    exit 1
fi

echo "================================================"
echo "[SUCCESS] Experiment completed."
echo "[RESULT] CSV: $CSV_FILE"
echo "[RESULT] Log: $LOG_FILE"
echo "[RESULT] Active windows: $ROW_COUNT"
echo "================================================"

cat "$CSV_FILE"
