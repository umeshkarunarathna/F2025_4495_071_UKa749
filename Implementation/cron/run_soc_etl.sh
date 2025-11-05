#!/usr/bin/env bash
set -euo pipefail

# --- config ---
ETL_PY="/opt/soc_etl/.venv/bin/python"
ETL_PATH="/opt/soc_etl/etl_wazuh_to_pg.py"
ENV_FILE="/etc/soc-etl.env"

LOG_DIR="/var/log/soc-etl"
LOCK_FILE="/var/lock/soc-etl.lock"
LAST_RUN_FILE="$LOG_DIR/last_run.txt"

# --- env ---
if [[ -f "$ENV_FILE" ]]; then
  # export all variables in the file
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

mkdir -p "$LOG_DIR"
: > /dev/null # no-op, ensures the script continues if mkdir already exists
[[ -f "$LAST_RUN_FILE" ]] || : > "$LAST_RUN_FILE"

# --- serialize runs (no overlap) ---
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  echo "[$(date -Is)] ETL skipped: another run is in progress" >> "$LOG_DIR/etl.log"
  exit 0
fi

ts="$(date -Is)"
echo "[$ts] running ETL (cron/manual)..." >> "$LOG_DIR/etl.log"

if "$ETL_PY" "$ETL_PATH" >> "$LOG_DIR/etl.log" 2>&1; then
  echo "$ts" > "$LAST_RUN_FILE"
  echo "[$ts] done ✓" >> "$LOG_DIR/etl.log"
  exit 0
else
  rc=$?
  echo "[$ts] failed (rc=$rc)" >> "$LOG_DIR/etl.log"
  exit $rc
fi
