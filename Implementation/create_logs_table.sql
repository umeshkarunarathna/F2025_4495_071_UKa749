sudo -u postgres psql <<'SQL'
CREATE USER soc_user WITH PASSWORD 'ChangeMe_Strong!';
CREATE DATABASE soc_logs OWNER soc_user;
\c soc_logs
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS logs (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ,
  agent_name TEXT,
  agent_id TEXT,
  rule_id INTEGER,
  rule_level INTEGER,
  rule_desc TEXT,
  src_ip INET,
  user_name TEXT,
  full_log JSONB NOT NULL,
  raw_sha256 CHAR(64) UNIQUE
);
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO soc_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO soc_user;
SQL