#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import datetime as dt
from ipaddress import ip_address

import psycopg2
from psycopg2.extras import Json
from dateutil import parser as dtp

# ----------------------------
# Config
# ----------------------------
ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"
STATE_FILE  = "/opt/soc_etl/last_ts.txt"  # stores last processed ISO8601 UTC timestamp

PGHOST = os.getenv("PGHOST", "127.0.0.1")
PGPORT = int(os.getenv("PGPORT", "5432"))
PGDB   = os.getenv("PGDATABASE", "soc_logs")
PGUSER = os.getenv("PGUSER", "soc_user")
PGPW   = os.getenv("PGPASSWORD", "")

# ----------------------------
# Helpers
# ----------------------------
def utcify(ts: dt.datetime | None) -> dt.datetime | None:
    """Return an aware UTC datetime (or None)."""
    if ts is None:
        return None
    if ts.tzinfo is None:
        # assume timestamp is UTC if naive
        return ts.replace(tzinfo=dt.timezone.utc)
    return ts.astimezone(dt.timezone.utc)

def parse_ts(value) -> dt.datetime | None:
    """Parse Wazuh timestamps like @timestamp/timestamp → aware UTC dt."""
    if not value:
        return None
    try:
        return utcify(dtp.parse(value))
    except Exception:
        return None

def to_inet(v: str | None) -> str | None:
    if not v:
        return None
    try:
        ip_address(v)
        return v
    except Exception:
        return None

def ensure_state_dir():
    d = os.path.dirname(STATE_FILE)
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

def get_last_ts() -> dt.datetime:
    """Read last processed ts from STATE_FILE; default far past in UTC."""
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        return utcify(dtp.parse(raw))
    except FileNotFoundError:
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    except Exception:
        # on any parse issue, start from min
        return dt.datetime.min.replace(tzinfo=dt.timezone.utc)

def save_last_ts(ts: dt.datetime):
    ensure_state_dir()
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        f.write(ts.astimezone(dt.timezone.utc).isoformat())

def open_db():
    return psycopg2.connect(
        host=PGHOST, port=PGPORT, dbname=PGDB, user=PGUSER, password=PGPW
    )

# ----------------------------
# Main
# ----------------------------
def main():
    # Check file presence early; fail with non-zero so /etl/run shows error
    if not os.path.exists(ALERTS_PATH):
        print(f"alerts.json not found at {ALERTS_PATH}")
        sys.exit(1)

    # DB connect
    conn = open_db()
    conn.autocommit = True
    cur = conn.cursor()

    # Ensure dedupe index exists (idempotent)
    cur.execute("""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_indexes
                WHERE schemaname = 'public' AND indexname = 'ux_logs_raw_sha256'
            ) THEN
                BEGIN
                    EXECUTE 'CREATE UNIQUE INDEX ux_logs_raw_sha256 ON logs (raw_sha256)';
                EXCEPTION WHEN duplicate_table THEN
                    -- index created elsewhere
                    NULL;
                END;
            END IF;
        END$$;
    """)

    last_ts = get_last_ts()
    new_ts  = last_ts
    inserted = 0
    scanned  = 0
    skipped_old = 0
    skipped_dupe = 0

    # Stream line-by-line (JSON per line)
    with open(ALERTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            scanned += 1

            # quick hash for dedupe
            raw_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

            try:
                j = json.loads(line)
            except Exception:
                # ignore malformed lines
                continue

            # timestamp
            ts = parse_ts(j.get("@timestamp") or j.get("timestamp"))
            if ts is None:
                # some lines may lack ts; skip
                continue

            # skip if already processed in previous runs
            if ts <= last_ts:
                skipped_old += 1
                continue

            # flatten fields
            agent = j.get("agent") or {}
            rule  = j.get("rule") or {}
            data  = j.get("data") or {}

            agent_name = agent.get("name")
            agent_id   = agent.get("id")
            rule_id    = rule.get("id")
            rule_level = rule.get("level")
            rule_desc  = rule.get("description")
            src_ip     = to_inet(data.get("srcip") or j.get("srcip"))
            user_name  = data.get("user") or j.get("user")

            try:
                cur.execute("""
                    INSERT INTO logs
                        (ts, agent_name, agent_id, rule_id, rule_level, rule_desc, src_ip, user_name, full_log, raw_sha256)
                    VALUES
                        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (raw_sha256) DO NOTHING
                """, (
                    ts, agent_name, agent_id, rule_id, rule_level, rule_desc,
                    src_ip, user_name, Json(j), raw_hash
                ))
                if cur.rowcount == 1:
                    inserted += 1
                    if ts > new_ts:
                        new_ts = ts
                else:
                    # conflict hit (duplicate)
                    skipped_dupe += 1
            except psycopg2.Error as e:
                # Keep going on individual row errors
                # (Optional) print a short diagnostic line:
                # print(f"DB error on insert: {e.pgerror or str(e)}", file=sys.stderr)
                continue

    # If we inserted anything (or scanned newer data), advance the state
    if new_ts > last_ts:
        save_last_ts(new_ts)

    cur.close()
    conn.close()

    print(
        f"Ingest complete. Scanned={scanned}, inserted={inserted}, "
        f"skipped_old={skipped_old}, skipped_dupe={skipped_dupe}, "
        f"last_ts={last_ts.isoformat()}, new_ts={new_ts.isoformat()}"
    )

if __name__ == "__main__":
    main()
