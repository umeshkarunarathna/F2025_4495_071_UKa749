#!/usr/bin/env python3
import os, json, hashlib, psycopg2
from dateutil import parser as dtp
from ipaddress import ip_address

# Wazuh alerts file
ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"

# PostgreSQL connection (from env vars)
PGHOST = os.getenv("PGHOST", "127.0.0.1")
PGPORT = int(os.getenv("PGPORT", "5432"))
PGDB   = os.getenv("PGDATABASE", "soc_logs")
PGUSER = os.getenv("PGUSER", "soc_user")
PGPW   = os.getenv("PGPASSWORD", "")

def to_ts(v):
    if not v: return None
    try: return dtp.parse(v)
    except: return None

def to_inet(v):
    if not v: return None
    try:
        ip_address(v)
        return v
    except: return None

def main():
    if not os.path.exists(ALERTS_PATH):
        print(f"alerts.json not found at {ALERTS_PATH}")
        return

    conn = psycopg2.connect(host=PGHOST, port=PGPORT, dbname=PGDB, user=PGUSER, password=PGPW)
    conn.autocommit = True
    cur = conn.cursor()

    inserted = 0
    with open(ALERTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            h = hashlib.sha256(line.encode()).hexdigest()
            try:
                j = json.loads(line)
            except:
                continue

            ts = to_ts(j.get("@timestamp") or j.get("timestamp"))
            agent = j.get("agent", {}) or {}
            agent_name, agent_id = agent.get("name"), agent.get("id")
            rule = j.get("rule", {}) or {}
            rule_id, rule_level, rule_desc = rule.get("id"), rule.get("level"), rule.get("description")
            data = j.get("data", {}) or {}
            src_ip = to_inet(data.get("srcip") or j.get("srcip"))
            user_name = data.get("user") or j.get("user")

            cur.execute("""
                INSERT INTO logs (ts, agent_name, agent_id, rule_id, rule_level, rule_desc, src_ip, user_name, full_log, raw_sha256)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (raw_sha256) DO NOTHING
            """, (ts, agent_name, agent_id, rule_id, rule_level, rule_desc, src_ip, user_name, json.dumps(j), h))
            inserted += 1

    cur.close()
    conn.close()
    print(f"Ingest complete. Inserted {inserted} rows.")

if __name__ == "__main__":
    main()
