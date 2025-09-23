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

## Repository Structure

F2025_4495_071_UKa749/
│
├── Documents/ # Project reports (Proposal, Progress Reports, Midterm, Final Report)
│ ├── Project_UKa749_Report1.pdf
│ └── ...
│
├── Implementation/ # Source code and scripts
│ ├── etl_wazuh_to_pg.py # ETL script (Wazuh -> PostgreSQL)
│ ├── main.py # FastAPI app (NL -> SQL)
│ ├── create_logs_table.sql # Postgres schema
│ ├── ab
│ └── ...
│
├── README.md
└── Misc/
