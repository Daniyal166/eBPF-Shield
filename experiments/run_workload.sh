
#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# eBPF-Shield — Controlled Workload Generator
# Labels:
#   benign    = 0
#   synthetic = 1 (high filesystem activity, NOT ransomware)
#
# Usage:
#   ./experiments/run_workload.sh benign run001
#   ./experiments/run_workload.sh synthetic run002
# ============================================================

CONTAINER="ebpf-shield-test"

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <benign|synthetic> <run_id>"
    exit 1
fi

MODE="$1"
RUN_ID="$2"

if [[ "$MODE" != "benign" && "$MODE" != "synthetic" ]]; then
    echo "[ERROR] Mode must be benign or synthetic"
    exit 1
fi

# Prevent path traversal and shell injection via run IDs.
if [[ ! "$RUN_ID" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "[ERROR] Run ID must contain only letters, numbers, _ or -"
    exit 1
fi

echo "================================================"
echo "           eBPF-Shield Workload Test"
echo "================================================"
echo "[INFO] Container : $CONTAINER"
echo "[INFO] Mode      : $MODE"
echo "[INFO] Run ID    : $RUN_ID"
echo "[INFO] Real ransomware: NO"
echo "================================================"

if ! sudo docker inspect \
    --format '{{.State.Running}}' "$CONTAINER" \
    2>/dev/null | grep -qx true; then
    echo "[ERROR] Docker test container is not running"
    exit 1
fi

if [[ "$MODE" == "benign" ]]; then

    sudo docker exec -i "$CONTAINER" bash -s -- "$RUN_ID" <<'INNER'
set -euo pipefail

RUN_ID="$1"
WORKDIR="/tmp/ebpf-shield-experiments/benign_${RUN_ID}"

mkdir -p "$WORKDIR"

for i in $(seq 1 20); do
    printf "Normal document %s for test %s\n" \
        "$i" "$RUN_ID" > "$WORKDIR/document_${i}.txt"
done

tar -czf "${WORKDIR}.tar.gz" \
    -C "$(dirname "$WORKDIR")" \
    "$(basename "$WORKDIR")"

echo "[OK] Benign workload completed"
INNER

else

    sudo docker exec -i "$CONTAINER" bash -s -- "$RUN_ID" <<'INNER'
set -euo pipefail

RUN_ID="$1"
WORKDIR="/tmp/ebpf-shield-experiments/synthetic_${RUN_ID}"

mkdir -p "$WORKDIR"

for i in $(seq 1 20); do
    printf "Synthetic test data %s for test %s\n" \
        "$i" "$RUN_ID" > "$WORKDIR/file_${i}.txt"

    mv "$WORKDIR/file_${i}.txt" \
       "$WORKDIR/renamed_${i}.txt"

    rm "$WORKDIR/renamed_${i}.txt"
done

echo "[OK] Synthetic high-activity workload completed"
INNER

fi

echo "[OK] Experiment finished: $MODE / $RUN_ID"
