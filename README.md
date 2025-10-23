# LLM-Powered SOC Assistant

## Douglas College – Fall 2025  
**Course:** CSIS 4495 – Applied Research Project  
**Section:** 071  
**Instructor:** Bambang A.B. Sarif  

---

## Team Information

| Name                        | Student ID | Email                                             | 
|-----------------------------|------------|---------------------------------------------------|
| Umesh Kalupathirannehelage  | 300389749  | kalupathiranneu@student.douglascollege.ca         |

---

## Project Overview

The **LLM-Powered SOC Assistant** is an applied research project designed to augment Security Operations Center (SOC) analysts by combining:

- **Wazuh** → Log collection, monitoring, and alerting.  
- **PostgreSQL** → Centralized storage of structured Wazuh alerts.  
- **ETL Pipeline (Python)** → Extracts Wazuh alerts, transforms into schema, loads into Postgres.  
- **FastAPI Backend** → Provides a REST API interface for natural language queries.  
- **Ollama (LLM)** → Generates SQL queries from natural language requests (NL → SQL).  
- **Ubuntu VM (Cloud/Local)** → Runs Wazuh, ETL, Postgres, and API.  
- **Windows Host (Hybrid)** → Runs Ollama for efficient LLM execution.  

The assistant enables analysts to query security events (e.g., SSH failed logins, anomalies, brute-force attempts) using plain English and receive structured results directly from logs.

---

# LLM-Powered SOC Assistant — Architecture & File Map

## 1. End-to-End Flow
1. **Wazuh Agent(s)** (Kali, Ubuntu) collect system/auth events and send them to the **Wazuh Manager**.  
2. **Wazuh Manager** writes security events to `alerts.json`.  
3. **ETL Script** on the manager reads `alerts.json` and loads parsed alerts into **PostgreSQL** (`soc_logs.logs`).  
4. **FastAPI Backend** transforms natural-language queries into SQL via **Ollama**, runs the query, and returns JSON results.  
5. **Web UI** allows users to ask questions, run on-demand ETL updates, and visualize logs in dynamic charts.

---

## 2. Wazuh — Key Paths & Configurations

### Manager (AWS EC2 Ubuntu)
- **Alerts location**
  - `/var/ossec/logs/alerts/alerts.json` ← JSON alerts (read by ETL)
  - `/var/ossec/logs/alerts/alerts.log` ← text logs
  - `/var/ossec/logs/alerts/YYYY/` ← archived daily logs  
- **Configuration**
  - `/var/ossec/etc/ossec.conf`  
    - `<jsonout_output>yes</jsonout_output>`  
    - Local rules/decoders:  
      `/var/ossec/etc/rules/local_rules.xml`,  
      `/var/ossec/etc/decoders/local_decoder.xml`  
- **Service**
  - `sudo systemctl status wazuh-manager`
- **Logs**
  - `/var/ossec/logs/ossec.log`

### Agent (Ubuntu / Kali)
- **Manager IP Configuration**
  - `/var/ossec/etc/ossec.conf`
    ```xml
    <client>
      <server>
        <address>MANAGER_IP</address>
        <port>1514</port>
        <protocol>udp</protocol>
      </server>
    </client>
    ```
- **Logs collected**
  - `/var/log/auth.log`, `/var/log/syslog`, `/var/log/kern.log`, plus sudo, ssh, PAM, and anomaly events.
- **Services**
  - `sudo systemctl status wazuh-agent`
  - `sudo tail -f /var/ossec/logs/ossec.log`

---

## 3. ETL — Wazuh → PostgreSQL

- **Script:** `/opt/soc_etl/etl_wazuh_to_pg.py`
- **Virtual environment:** `/opt/soc_etl/.venv/`
- **State file:** `/opt/soc_etl/last_ts.txt` (tracks last processed timestamp)
- **Reads from:** `/var/ossec/logs/alerts/alerts.json`
- **Database credentials:** from environment variables (`PGHOST`, `PGPORT`, `PGDATABASE`, `PGUSER`, `PGPASSWORD`)
- **Run manually:**
  ```bash
  sudo -E /opt/soc_etl/.venv/bin/python /opt/soc_etl/etl_wazuh_to_pg.py

---

