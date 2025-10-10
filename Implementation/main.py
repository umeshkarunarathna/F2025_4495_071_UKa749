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

KEYWORD → FILTER MAPPINGS (use rule_desc ILIKE unless the user asks otherwise)

- Brute force:	      rule_desc ILIKE '%brute%'
- SSH:                rule_desc ILIKE '%sshd%'
- Authentication:     (rule_desc ILIKE '%auth%' OR rule_desc ILIKE '%PAM%' OR rule_desc ILIKE '%login%')
- Failed logins:      (rule_desc ILIKE '%fail%' OR rule_desc ILIKE '%invalid%' OR rule_desc ILIKE '%denied%')
- Successful logins:  rule_desc ILIKE '%success%' AND rule_desc NOT ILIKE '%fail%'
- sudo activity:      rule_desc ILIKE '%sudo%'
- Agent lifecycle:    rule_desc ILIKE '%Wazuh agent%'
- Anomaly/rootcheck:  (rule_desc ILIKE '%anomaly%' OR rule_desc ILIKE '%rootcheck%')
- System audit/SCA:   (rule_desc ILIKE '%System audit%' OR rule_desc ILIKE '%SCA%')
- FTP:                rule_desc ILIKE '%ftp%'
- Telnet:             rule_desc ILIKE '%telnet%'
- Web server:         (rule_desc ILIKE '%httpd%' OR rule_desc ILIKE '%apache%' OR rule_desc ILIKE '%nginx%')
- Kernel messages:    rule_desc ILIKE '%kernel%'
- Service start/stop: (rule_desc ILIKE '%started%' OR rule_desc ILIKE '%stopped%')
- Port scan:          rule_desc ILIKE '%scan%'

SEVERITY / GROUPING
- If user asks “high severity”, use rule_level >= 7.
- For “top/most” requests: SELECT the grouping key(s), COUNT(*) AS count, GROUP BY those key(s), ORDER BY count DESC, LIMIT N.
- Use COALESCE for nullable group keys when helpful (e.g., COALESCE(src_ip::text, '(null)')).

AGENT / IP / USER FILTERS
- If the user names an agent: add WHERE agent_name = 'ExactName'.
- If the user mentions an IP: add WHERE src_ip = 'x.x.x.x' (or src_ip <<= 'CIDR' if they give a subnet).
- If the user mentions a username: add WHERE user_name = 'name'.

RAW ROWS vs. AGGREGATES
- If the user says “Return raw rows (no grouping)”, do NOT use GROUP BY; return the default column set sorted by ts DESC.
- Otherwise infer reasonably: counting, top N, or raw rows based on the request wording.

PROHIBITED
- No INSERT/UPDATE/DELETE/ALTER/DROP/TRUNCATE/CREATE/GRANT/REVOKE.
- No multi-statement queries.

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
