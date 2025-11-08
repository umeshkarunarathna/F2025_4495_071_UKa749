import os
import subprocess, shlex, textwrap, sys
import re
import json
import time
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# -------------------------
# Config
# -------------------------
ETL_PATH   = os.getenv("ETL_PATH", "/opt/soc_etl/etl_wazuh_to_pg.py")
ETL_PY     = os.getenv("ETL_PY", "/opt/soc_etl/.venv/bin/python")
ETL_TOKEN  = os.getenv("ETL_TOKEN", "123!")

PGHOST = os.getenv("PGHOST", "127.0.0.1")
PGPORT = int(os.getenv("PGPORT", "5432"))
PGDB   = os.getenv("PGDATABASE", "soc_logs")
PGUSER = os.getenv("PGUSER", "soc_user")
PGPW   = os.getenv("PGPASSWORD", "")

OLLAMA_BASE  = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")

MAX_ROWS = int(os.getenv("MAX_ROWS", "200"))
DEFAULT_WINDOW_HOURS = int(os.getenv("DEFAULT_WINDOW_HOURS", "24"))

ETL_LAST_RUN_FILE = os.getenv("ETL_LAST_RUN_FILE", "/var/log/soc-etl/last_run.txt")
CRON_SPEC = os.getenv("ETL_CRON_SPEC", "0 * * * *")  # top of each hour by default


# -------------------------
# Prompt / schema hint
# -------------------------
SCHEMA_HINT = """
You are a SOC analyst assistant that converts natural language to PostgreSQL SQL.

Database: PostgreSQL
Only generate a single SQL statement (no explanations).

Table schema:

logs(
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ,          -- event timestamp
  agent_name TEXT,
  agent_id TEXT,
  rule_id INTEGER,
  rule_level INTEGER,
  rule_desc TEXT,
  src_ip INET,
  user_name TEXT,
  full_log JSONB           -- raw wazuh alert
)

Rules:
- Do NOT add a time filter unless the user explicitly mentions one (e.g., “last 24 hours”).
- Limit results to {limit} rows unless user explicitly requests more (for aggregates still add LIMIT).
- SELECT-only. Do not use INSERT/UPDATE/DELETE/ALTER/DROP/TRUNCATE.
- Prefer simple SELECT with WHERE/GROUP BY/ORDER BY.
- Return only one SQL SELECT (no prose, no comments).
- If the user does not specify columns, default to:
  SELECT id, ts, agent_name, src_ip, user_name, rule_level, rule_id, rule_desc
- If the user asks for counts/tops/most, use COUNT(*) AS count, ORDER BY count DESC, and a sensible GROUP BY.
- When the user says success / successful, include rule_desc ILIKE '%success%' and exclude failures with rule_desc NOT ILIKE '%fail%'.
- When the user says failed / failure / invalid / denied, include (rule_desc ILIKE '%fail%' OR rule_desc ILIKE '%invalid%' OR rule_desc ILIKE '%denied%').
- Always keep rule_desc ILIKE '%sshd%' for SSH-related requests.
- Never use JSON paths (full_log->>…) unless explicitly requested. Prefer the flattened columns.
- Use rule_desc for keyword filtering. When the user mentions terms like authentication, ssh, sudo, login, failed, success, anomaly, interpret them as rule_desc ILIKE '%term%' conditions (combine with AND/OR as needed).
- Avoid guessing severities. Do not use rule_level < 7 or similar unless the user asks for “high severity”.

KEYWORD → FILTER MAPPINGS (use rule_desc ILIKE unless the user asks otherwise)
- Brute force:         rule_desc ILIKE '%brute%'
- SSH:                 rule_desc ILIKE '%sshd%'
- Authentication:      (rule_desc ILIKE '%auth%' OR rule_desc ILIKE '%PAM%' OR rule_desc ILIKE '%login%')
- Failed logins:       (rule_desc ILIKE '%fail%' OR rule_desc ILIKE '%invalid%' OR rule_desc ILIKE '%denied%')
- Successful logins:   rule_desc ILIKE '%success%' AND rule_desc NOT ILIKE '%fail%'
- sudo activity:       rule_desc ILIKE '%sudo%'
- Agent lifecycle:     rule_desc ILIKE '%Wazuh agent%'
- Anomaly/rootcheck:   (rule_desc ILIKE '%anomaly%' OR rule_desc ILIKE '%rootcheck%')
- System audit/SCA:    (rule_desc ILIKE '%System audit%' OR rule_desc ILIKE '%SCA%')
- FTP:                 rule_desc ILIKE '%ftp%'
- Telnet:              rule_desc ILIKE '%telnet%'
- Web server:          (rule_desc ILIKE '%httpd%' OR rule_desc ILIKE '%apache%' OR rule_desc ILIKE '%nginx%')
- Kernel messages:     rule_desc ILIKE '%kernel%'
- Service start/stop:  (rule_desc ILIKE '%started%' OR rule_desc ILIKE '%stopped%')
- Port scan:           rule_desc ILIKE '%scan%'

AGGREGATE PATTERN FOR “FAILED VS SUCCESSFUL SSH” (use this when user asks comparisons/percentages/graph):
SELECT
  CASE
    WHEN rule_desc ILIKE '%success%' AND rule_desc NOT ILIKE '%fail%' THEN 'successful'
    WHEN (rule_desc ILIKE '%fail%' OR rule_desc ILIKE '%invalid%' OR rule_desc ILIKE '%denied%') THEN 'failed'
    ELSE 'other'
  END AS status,
  COUNT(*) AS count
FROM logs
WHERE rule_desc ILIKE '%sshd%'
-- optionally add agent_name='Name' or time windows if user asked
GROUP BY 1
ORDER BY count DESC
LIMIT {limit};
""".strip().format(hours=DEFAULT_WINDOW_HOURS, limit=MAX_ROWS)

DENYLIST = re.compile(r"\b(INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE|CREATE|GRANT|REVOKE)\b", re.IGNORECASE)

# -------------------------
# API models
# -------------------------
class AskRequest(BaseModel):
    question: str

class ChartPayload(BaseModel):
    type: str                    # "pie", etc.
    title: str                   # chart title
    labels: list[str]            # e.g. ["Failed","Successful"]
    values: list[float]          # e.g. [23,77]
    percentages: list[float] = []  # optional convenience

class AskResponse(BaseModel):
    sql: str
    rows: list
    rowcount: int
    latency_ms: int
    chart: ChartPayload | None = None

# -------------------------
# App + static UI
# -------------------------
app = FastAPI(title="LLM-Powered SOC Assistant (NL → SQL)", version="0.1")

from fastapi.staticfiles import StaticFiles
app.mount("/ui", StaticFiles(directory="ui", html=True), name="ui")

# -------------------------
# Helpers
# -------------------------
def _tail(txt: str, n=40):
    lines = (txt or "").splitlines()[-n:]
    return "\n".join(lines)

def _wants_chart(question: str) -> bool:
    """
    Detect simple chart/percentage/comparison intent for SSH.
    """
    q = (question or "").lower()
    triggers = [
        "failed vs successful", "success vs failed", "compare", "comparison",
        "percentage", "percent", "chart", "graph", "visual", "visualize", "plot"
    ]
    return ("ssh" in q or "sshd" in q) and any(t in q for t in triggers)

def _build_failed_success_chart_from_rows(rows: list) -> ChartPayload | None:
    """
    Expect rows shaped like: [{'status': 'failed', 'count': 12}, {'status': 'successful', 'count': 34}, ...]
    If not found, return None.
    """
    if not rows:
        return None

    # normalize keys (case-insensitive)
    def norm_key(k): return (k or "").strip().lower()

    # detect columns
    status_key = None
    count_key  = None
    for k in rows[0].keys():
        nk = norm_key(k)
        if nk in ("status", "state", "result", "outcome"):
            status_key = k
        if nk in ("count", "total", "cnt", "events"):
            count_key = k
    if not status_key or not count_key:
        return None

    buckets = {}
    for r in rows:
        label = str(r.get(status_key) or "other").lower()
        try:
            c = float(r.get(count_key) or 0)
        except:
            c = 0.0
        buckets[label] = buckets.get(label, 0.0) + c

    labels = []
    values = []

    # Always put Failed, Successful first if present
    for lbl in ["failed", "successful"]:
        labels.append(lbl.capitalize())
        values.append(buckets.get(lbl, 0.0))

    # Add 'Other' if any residual
    other_sum = sum(v for k, v in buckets.items() if k not in ("failed", "successful"))
    if other_sum > 0:
        labels.append("Other")
        values.append(other_sum)

    total = sum(values) or 1.0
    percentages = [round(v * 100.0 / total, 2) for v in values]

    return ChartPayload(
        type="pie",
        title="SSH: Failed vs Successful",
        labels=labels,
        values=values,
        percentages=percentages
    )

# -------------------------
# ETL trigger
# -------------------------
@app.post("/etl/run")
def etl_run(x_etl_token: str = Header(default="")):
    # simple guard
    if ETL_TOKEN and x_etl_token != ETL_TOKEN:
        raise HTTPException(status_code=401, detail="bad token")

    env = dict(os.environ)
    cmd = [ETL_PY, ETL_PATH]

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=60)
        return {
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout_tail": _tail(p.stdout),
            "stderr_tail": _tail(p.stderr),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "ok": False,
            "error": "timeout",
            "stdout_tail": _tail(e.stdout or ""),
            "stderr_tail": _tail(e.stderr or ""),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

# -------------------------
# LLM + SQL execution
# -------------------------
def call_ollama_for_sql(question: str) -> str:
    """
    Calls Ollama /api/chat with a system+user prompt and returns raw text.
    """
    url = f"{OLLAMA_BASE}/api/chat"
    payload = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": SCHEMA_HINT},
            {"role": "user", "content": f"Question: {question}\nReturn only SQL for PostgreSQL."}
        ],
        "stream": False
    }
    r = requests.post(url, json=payload, timeout=120)
    # If Ollama returns non-200, expose the text for easier debugging
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Ollama error {r.status_code}: {r.text[:300]}")
    data = r.json()
    text = data.get("message", {}).get("content", "")
    return text.strip()

def extract_sql(text: str) -> str:
    """
    Extract the SQL from model output (handles code fences or plain text).
    """
    m = re.search(r"```(?:sql)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        sql = m.group(1).strip()
    else:
        semi = text.find(";")
        sql = text[:semi+1].strip() if semi != -1 else text.strip()

    # enforce SELECT-only
    if DENYLIST.search(sql):
        raise HTTPException(status_code=400, detail="Generated SQL contains non-SELECT statements. Aborting.")
    if not re.match(r"^\s*SELECT\b", sql, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Generated SQL is not a SELECT.")
    return sql

def run_sql(sql: str):
    """
    Executes SQL with a per-query timeout and returns rows as dicts.
    """
    t0 = time.time()
    conn = psycopg2.connect(host=PGHOST, port=PGPORT, dbname=PGDB, user=PGUSER, password=PGPW)
    try:
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SET LOCAL statement_timeout = 8000;")
                cur.execute(sql)
                rows = cur.fetchall()
    finally:
        conn.close()
    latency_ms = int((time.time() - t0) * 1000)
    return rows, latency_ms

# -------------------------
# /ask endpoint
# -------------------------
@app.post("/ask", response_model=AskResponse)
def ask(req: AskRequest):
    # 1) ask LLM for SQL
    raw = call_ollama_for_sql(req.question)
    sql = extract_sql(raw)

    # 2) add LIMIT if missing (protect huge scans)
    if re.search(r"\bLIMIT\b", sql, re.IGNORECASE) is None:
        sql = f"{sql.rstrip(';')} LIMIT {MAX_ROWS};"

    # 3) run
    try:
        rows, latency_ms = run_sql(sql)
    except psycopg2.Error as e:
        raise HTTPException(status_code=400, detail=f"SQL execution error: {e.pgerror or str(e)}")

    # 4) Optional chart when user asks for comparison/percentages/graphs for SSH
    chart = None
    if _wants_chart(req.question):
        chart = _build_failed_success_chart_from_rows(rows)

    return AskResponse(sql=sql, rows=rows, rowcount=len(rows), latency_ms=latency_ms, chart=chart)

# -------------------------
# Health
# -------------------------
@app.get("/healthz")
def health():
    try:
        rows, _ = run_sql("SELECT 1 as ok;")
        return {"ok": True, "db": rows[0]["ok"] == 1}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------------------------------------------------------
# Show Last Updated Time
# ----------------------------------------------------------
from datetime import datetime, timedelta, timezone

def _read_last_run_iso(path: str) -> str | None:
    try:
        with open(path, "r") as f:
            s = f.read().strip()
            # accept either ISO with/without tz
            try:
                return datetime.fromisoformat(s).astimezone(timezone.utc).isoformat()
            except Exception:
                return None
    except FileNotFoundError:
        return None
    except Exception:
        return None

def _next_run_iso(now_utc: datetime | None = None) -> str:
    """
    For CRON_SPEC '0 * * * *', next run = top of next hour.
    If you later change CRON_SPEC, update this function accordingly.
    """
    now_utc = now_utc or datetime.now(timezone.utc)
    nxt = (now_utc.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
    return nxt.isoformat()

@app.get("/etl/status")
def etl_status():
    server_time = datetime.now(timezone.utc).isoformat()
    last_run = _read_last_run_iso(ETL_LAST_RUN_FILE)
    next_run = _next_run_iso()
    return {
        "server_time": server_time,
        "last_run": last_run,         # ISO8601 or null if never
        "next_run": next_run,         # ISO8601 (UTC)
        "cron": CRON_SPEC,
        "last_run_file": ETL_LAST_RUN_FILE,
    }
