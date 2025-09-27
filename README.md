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



<img width="721" height="396" alt="image" src="https://github.com/user-attachments/assets/8c5205d7-e1cd-4393-b9ac-c501041d224e" />


---

