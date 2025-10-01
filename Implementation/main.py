import os
import re
import json
import time
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

PGHOST = os.getenv("PGHOST", "127.0.0.1")
PGPORT = int(os.getenv("PGPORT", "5432"))
PGDB   = os.getenv("PGDATABASE", "soc_logs")
PGUSER = os.getenv("PGUSER", "soc_user")
PGPW   = os.getenv("PGPASSWORD", "")

OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")

MAX_ROWS = int(os.getenv("MAX_ROWS", "200"))
DEFAULT_WINDOW_HOURS = int(os.getenv("DEFAULT_WINDOW_HOURS", "24"))

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
- Always include a time filter if the user gives one; otherwise default to last {hours} hours using: ts >= now() - interval '{hours} hours'.
- Limit results to {limit} rows unless user explicitly requests more.
- Only add time filters (ts >= now() - interval 'X hours/days') if the user explicitly mentions a time window.
- SELECT-only. Do not use INSERT/UPDATE/DELETE/ALTER/DROP/TRUNCATE.
- Prefer simple SELECT with WHERE/GROUP BY/ORDER BY.
- Return only one SQL SELECT (no prose, no comments).
- If the user does not specify columns, default to:
	SELECT id, ts, agent_name, src_ip, user_name, rule_level, rule_id, rule_desc
- If the user asks for counts/tops/most, use COUNT(*) AS count, ORDER BY count DESC, and a sensible GROUP BY.
- When the user says success / successful, include rule_desc ILIKE '%success%' and exclude failures with rule_desc NOT ILIKE '%fail%'.
- When the user says failed / failure / invalid / denied, include (rule_desc ILIKE '%fail%' OR '%invalid%' OR '%denied%').
- Always keep rule_desc ILIKE '%sshd%' for SSH-related requests.
- Never use JSON paths (full_log->>…) unless explicitly requested. Prefer the flattened columns (ts, agent_name, src_ip, user_name, rule_level, rule_id, rule_desc).
- Use rule_desc for keyword filtering. When the user mentions terms like authentication, ssh, sudo, login, failed, success, anomaly, interpret them as rule_desc ILIKE '%term%' conditions (combine with AND/OR as needed).
- Avoid JSON paths (full_log->>…) unless explicitly asked by the user.
- Avoid guessing severities. Do not use rule_level < 7 or similar unless the user asks for “high severity”.
- Preferred mappings:
	Authentication events: rule_desc ILIKE '%auth%' OR rule_desc ILIKE '%PAM%' OR rule_desc ILIKE '%sshd%'
	SSH events: rule_desc ILIKE '%sshd%'
	Failed logins: rule_desc ILIKE '%fail%' OR rule_desc ILIKE '%invalid%' OR rule_desc ILIKE '%denied%'
	Success logins: rule_desc ILIKE '%success%'
	sudo events: rule_desc ILIKE '%sudo%'
	agent lifecycle: rule_desc ILIKE '%Wazuh agent%'
- Always prefer flattened columns: ts, agent_name, src_ip, user_name, rule_level, rule_id, rule_desc.
- If user asks for “top” or “most”, use ORDER BY DESC with LIMIT.
- When filtering by substrings in rule_desc, use ILIKE '%term%'.
""".strip().format(hours=DEFAULT_WINDOW_HOURS, limit=MAX_ROWS)

DENYLIST = re.compile(r"\b(INSERT|UPDATE|DELETE|ALTER|DROP|TRUNCATE|CREATE|GRANT|REVOKE)\b", re.IGNORECASE)

class AskRequest(BaseModel):
    question: str

class AskResponse(BaseModel):
    sql: str
    rows: list
    rowcount: int
    latency_ms: int

app = FastAPI(title="LLM-Powered SOC Assistant (NL → SQL)", version="0.1")

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
    r = requests.post(url, json=payload, timeout=60)
    r.raise_for_status()
    data = r.json()
    text = data.get("message", {}).get("content", "")
    return text.strip()

def extract_sql(text: str) -> str:
    """
    Extract the SQL from model output (handles code fences or plain text).
    """
    # ```sql ... ```
    m = re.search(r"```(?:sql)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        sql = m.group(1).strip()
    else:
        # take up to first semicolon if present
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
                # per-transaction timeout (in ms)
                cur.execute("SET LOCAL statement_timeout = 8000;")
                cur.execute(sql)
                rows = cur.fetchall()
    finally:
        conn.close()
    latency_ms = int((time.time() - t0) * 1000)
    return rows, latency_ms

@app.post("/ask", response_model=AskResponse)
def ask(req: AskRequest):
    # 1) ask LLM for SQL
    raw = call_ollama_for_sql(req.question)
    sql = extract_sql(raw)

    # 2) sanity: add LIMIT if missing (to protect from huge scans)
    if re.search(r"\bLIMIT\b", sql, re.IGNORECASE) is None:
        sql = f"{sql.rstrip(';')} LIMIT {MAX_ROWS};"

    # 3) run
    try:
        rows, latency_ms = run_sql(sql)
    except psycopg2.Error as e:
        # bubble up DB errors but keep message concise
        raise HTTPException(status_code=400, detail=f"SQL execution error: {e.pgerror or str(e)}")

    return AskResponse(sql=sql, rows=rows, rowcount=len(rows), latency_ms=latency_ms)

@app.get("/healthz")
def health():
    # quick check that DB is reachable
    try:
        rows, _ = run_sql("SELECT 1 as ok;")
        return {"ok": True, "db": rows[0]["ok"] == 1}
    except Exception as e:
        return {"ok": False, "error": str(e)}
