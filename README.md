# T2-PS7 – Privilege Escalation Activity Monitor 🛡️

A complete, beginner-friendly, and audit-grade cybersecurity monitoring tool designed to detect potentially unauthorized privilege escalation, administrator account creation, suspicious group membership changes, and risky permission modifications from system audit logs.

Developed using **Python**, **Pandas**, **Rule-Based Detection**, **SQLite**, **Matplotlib**, and **Streamlit**.

---

## 📌 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Architecture & Data Flow](#-architecture--data-flow)
4. [Detection Rules Catalog & MITRE ATT&CK Mapping](#-detection-rules-catalog--mitre-attck-mapping)
5. [Technology Stack](#-technology-stack)
6. [Folder Structure](#-folder-structure)
7. [Installation & Setup](#-installation--setup)
8. [Running the Application](#-running-the-application)
9. [Sample Data & Detection Verification](#-sample-data--detection-verification)
10. [Automated Testing](#-automated-testing)
11. [Audit Report Generation](#-audit-report-generation)
12. [Project Demonstration Workflow (Hackathon / Review)](#-project-demonstration-workflow-hackathon--review)
13. [Limitations & Ethical Disclaimer](#-limitations--ethical-disclaimer)

---

## 🎯 Project Overview

Privilege escalation represents one of the most critical stages in the cyber kill chain (MITRE ATT&CK Tactic **TA0004**). After acquiring initial footholds via low-privileged accounts or compromised endpoints, adversaries elevate privileges to gain domain administrator, root, or global admin rights.

**T2-PS7: Privilege Escalation Activity Monitor** ingests system audit event logs (CSV/JSON), parses and validates them against untrusted input attacks, and executes deterministic rule-based security heuristics to flag risky actions. Flagged events are classified by risk (High, Medium, Low), explained with causal security narratives, stored safely in a local SQLite database, and exported as compliance audit reports.

---

## 🚀 Key Features

- **Interactive Cyber SOC Dashboard:** Visual metrics cards (Total Analyzed, Suspicious Flagged, High/Med/Low counts, Admin Creataions, Role Escalations), dynamic Matplotlib risk distribution pie charts, rule breakdown bar charts, and recent activity streams.
- **Resilient Multi-Format Ingestion:** Ingests CSV, standard JSON, and newline-delimited JSON (`ndjson`). Features schema mapping, missing-field fallbacks, and sanitization to thwart XSS and injection.
- **Deterministic 8-Rule Security Engine:**
  1. *Administrator Account Creation* (`RULE-01`)
  2. *Privilege Escalation* (`RULE-02`)
  3. *Privileged Group Membership Addition* (`RULE-03`)
  4. *Unauthorized Privilege Modification Actor* (`RULE-04`)
  5. *Repeated Failed Administrative Operations* (`RULE-05`)
  6. *Suspicious Permission Changes* (`RULE-06`)
  7. *After-Hours Privileged Operations* (`RULE-07`)
  8. *Rapid Privilege Changes* (`RULE-08`)
- **Forensic Alert Dossier:** Detailed explanation of why each event was flagged, before/after role elevation visualizer, actor/target metadata, and actionable investigation playbooks.
- **Search & Multi-Dimensional Filtering:** Search across actor, target user, IP, action, resource, rule type, and risk level.
- **Persistent SQLite Audit Storage:** Tracks analysis runs, deduplicates raw audit events via parameterized queries, and records historical detection alerts.
- **Audit Report Generator:** Generates downloadable compliance reports in executive TXT format, structured CSV data, and machine-readable JSON.
- **Dynamic Configuration Tuning:** Allows administrators to modify privileged roles, groups, authorized actors whitelist, working hours, and failure thresholds directly from the UI.
- **Built-in Synthetic Test Data:** Pre-packaged sample audit log files containing both benign baseline actions and synthetic attack patterns.

---

## 🏗️ Architecture & Data Flow

```
                      +-----------------------------+
                      |   System Audit Logs Input   |
                      |     (CSV / JSON Formats)    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |         Log Parser          |
                      |  - Schema Normalization     |
                      |  - Input Sanitization (XSS) |
                      |  - Timestamp Parsing        |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |    Rule Detection Engine    |
                      |  - 8 Deterministic Rules    |
                      |  - Temporal Windows Tracker |
                      |  - Actor Whitelist Check    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |       Risk Classifier       |
                      |  - Multi-Rule Correlation   |
                      |  - High / Medium / Low      |
                      |  - Causal Narrative Gen     |
                      +--------------+--------------+
                                     |
              +----------------------+----------------------+
              |                                             |
              v                                             v
+---------------------------+                 +---------------------------+
|      SQLite Database      |                 |    Streamlit Frontend     |
| - audit_events            |                 | - Interactive Dashboard   |
| - detection_alerts        |                 | - Filterable Tables       |
| - analysis_runs           |                 | - Matplotlib Visuals      |
| - rule_config             |                 | - Downloadable Reports    |
+---------------------------+                 +---------------------------+
```

---

## 🛡️ Detection Rules Catalog & MITRE ATT&CK Mapping

| Rule ID | Rule Name | Risk | Detection Logic Summary | MITRE ATT&CK Technique |
| :--- | :--- | :---: | :--- | :--- |
| **RULE-01** | Admin Account Creation | **HIGH** | `action` in user-create set AND (`new_role` in privileged roles OR `group_name` in privileged groups). | T1136.001 / T1136.002 |
| **RULE-02** | Privilege Escalation | **HIGH** | Role change from Standard/None to Administrator, root, superuser. | T1548 / T1078 |
| **RULE-03** | Privileged Group Membership | **HIGH** | User added to sensitive security groups (e.g. Domain Admins, sudo, wheel). | T1098 |
| **RULE-04** | Unauthorized Actor | **HIGH** | Privileged operation executed by an actor not in the authorized admin whitelist. | T1078 |
| **RULE-05** | Repeated Failed Admin Actions | **MEDIUM** | Failed administrative attempts reach configured threshold (default $\ge 3$) within window. | T1110 |
| **RULE-06** | Suspicious Permission Changes | **MEDIUM** | Modifications to sensitive resources (`/etc/sudoers`, SAM) or granting `777` / Full Control. | T1222 |
| **RULE-07** | After-Hours Privileged Activity| **MEDIUM** | Privileged operations executed outside working hours (08:00 - 18:00) or on weekends. | T1078 (Anomalous Timing) |
| **RULE-08** | Rapid Privilege Changes | **HIGH** | Multiple privilege changes on the same target account within 15 minutes. | T1098 (Rapid Elevation) |

---

## 💻 Technology Stack

- **Core Language:** Python 3.9+
- **Data Manipulation:** Pandas
- **Visualization:** Matplotlib (dark theme)
- **Web UI & Dashboard:** Streamlit
- **Database Engine:** SQLite3 (parameterized queries, thread-safe)
- **Testing:** Pytest / Unittest
- **Data Serialization:** CSV, JSON

---

## 📂 Folder Structure

```
privilege_escalation_activity_monitor/
├── app.py                      # Main Streamlit Dashboard Application
├── requirements.txt            # Python Dependencies
├── README.md                   # Comprehensive Project Documentation
├── run_tests.py                # Standalone Test Runner Script
├── data/                       # Synthetic Audit Log Datasets
│   ├── sample_audit_logs.csv   # Synthetic audit log (CSV format)
│   └── sample_audit_logs.json  # Synthetic audit log (JSON format)
├── database/                   # SQLite Storage & Schema Management
│   ├── __init__.py
│   └── db_manager.py           # SQLite Database Manager class
├── detection/                  # Core Detection Engine
│   ├── __init__.py
│   ├── rules.py                # 8 Security detection rules & configurations
│   ├── risk_classifier.py      # Severity scoring & compound alert evaluator
│   └── analyzer.py             # DataFrame batch processor & metrics calculator
├── utils/                      # Helper & Reporting Utilities
│   ├── __init__.py
│   ├── log_parser.py           # Multi-format CSV/JSON parser & sanitizer
│   └── report_generator.py     # TXT, CSV, and JSON report generator
├── tests/                      # Automated Test Suite
│   ├── __init__.py
│   └── test_detection.py       # Unit & integration tests
└── reports/                    # Exported audit reports storage
    └── .gitkeep
```

---

## ⚙️ Installation & Setup

### 1. Clone or Open the Project
Open the project directory in your terminal or VS Code:
```bash
cd privilege_escalation_activity_monitor
```

### 2. Set Up a Python Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Required Dependencies
```bash
pip install -r requirements.txt
```

---

## 🖥️ Running the Application

Launch the Streamlit web dashboard locally:

```bash
streamlit run app.py
```

The application will launch and open in your default browser at:
`http://localhost:8501`

---

## 🧪 Sample Data & Detection Verification

The application comes bundled with realistic synthetic audit logs:
- `data/sample_audit_logs.csv`
- `data/sample_audit_logs.json`

### Verification Steps:
1. When you first open the app, it automatically loads the sample logs and populates the dashboard with telemetry.
2. In the sidebar, click **"📥 Upload Audit Logs"** to inspect the data stream.
3. Switch to **"🛡️ Detection Results"** to see all 8 rules triggered:
   - **EVT-1003:** Triggers `RULE-01` (Admin Account Creation for `ghost_admin`).
   - **EVT-1005:** Triggers `RULE-02` (Privilege Escalation for `arun` from Standard User to Administrator).
   - **EVT-1007:** Triggers `RULE-03` (Addition of `svc_backup` to `Domain Admins`).
   - **EVT-1009:** Triggers `RULE-02` and `RULE-04` (`intern_dev` self-elevating to root).
   - **EVT-1011 to EVT-1013:** Triggers `RULE-05` (3 repeated failed elevation attempts by `guest_contractor`).
   - **EVT-1015:** Triggers `RULE-06` (Modification to `/etc/sudoers` with Full Control).
   - **EVT-1017:** Triggers `RULE-03`, `RULE-04`, and `RULE-07` (Privilege change at 02:45 AM on Sunday).
   - **EVT-1019 & EVT-1020:** Triggers `RULE-08` (Rapid successive privilege modifications on `temp_consultant` within 3 minutes).
   - **EVT-1001, 1002, 1004, 1006, 1008, 1014, 1016:** Benign actions verified as clean (no false positives).

---

## 🧪 Automated Testing

Run the automated test suite to verify detection rules, input validation, database deduplication, and reporting:

### Option A: Using the Standalone Runner
```bash
python run_tests.py
```

### Option B: Using Pytest
```bash
pytest tests/ -v
```

All 15 automated test cases validate the integrity of each detection rule and edge condition.

---

## 📄 Audit Report Generation

Navigate to the **"📄 Reports & Export"** page in the Streamlit application:
1. Review the executive summary preview.
2. Optional: Add custom **Auditor / Analyst Remarks** into the notes field.
3. Click:
   - **📥 Download Audit Report (TXT):** Full readable compliance report with findings and security recommendations.
   - **📥 Download Alerts Data (CSV):** Spread-sheet format with all flagged events and investigation steps.
   - **📥 Download Machine Report (JSON):** Structured JSON format for integration into SIEM or ticketing tools.

---

## 🎓 Project Demonstration Workflow (Hackathon / Review)

Follow this 5-minute presentation workflow when demonstrating this project to professors, evaluators, or hackathon judges:

1. **Introduction (30 sec):** Explain why privilege escalation monitoring is vital in enterprise security and why deterministic rule-based analysis prevents AI hallucinations in compliance audits.
2. **Dashboard Overview (1 min):** Showcase the dark SOC dashboard, point out the KPI metrics, the risk distribution donut chart, and the breakdown by rule frequency.
3. **Log Ingestion & Sanitization (1 min):** Navigate to *Upload Audit Logs*, explain how the parser validates schemas, sanitizes untrusted input, and deduplicates records into SQLite.
4. **Detection Results & Forensics (1.5 min):**
   - Filter by `High Risk`.
   - Select event `EVT-1005` (user `arun` elevated to Administrator).
   - Switch to *Alert Details & Deep Dive* to show the Before/After role visualizer and the step-by-step investigation checklist.
   - Show `EVT-1009` (intern account self-promoting) demonstrating compound rule detection (`RULE-02` + `RULE-04`).
5. **Report Generation (30 sec):** Download the TXT Executive Report and display the structured security recommendations.
6. **Code Architecture (30 sec):** Highlight the modular separation between `detection/`, `database/`, `utils/`, and `tests/`.

---

## ⚠️ Limitations & Ethical Disclaimer

- **Rule-Based Heuristics:** Detection rules reflect common privilege escalation patterns. Novel zero-day evasion techniques or highly distributed low-and-slow attacks may require correlation across months of telemetry.
- **Detections vs. Incidents:** Flagged events represent *potential policy violations or anomalies*, not guaranteed malicious cyberattacks. Legitimate emergency changes may trigger after-hours or elevation rules.
- **Educational & Audit Use:** This tool is developed strictly for educational purposes and authorized defensive auditing. It does not perform any system privilege modifications or offensive operations.
