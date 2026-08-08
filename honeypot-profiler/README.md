# Honeypot Attacker Profiling System

A cybersecurity analytics tool that simulates honeypot attack traffic, profiles attacker behavior, maps activity to the MITRE ATT&CK framework, and visualizes everything through an interactive real-time dashboard.

## Overview

This project generates (or ingests) honeypot log data and runs it through a multi-stage pipeline:

1. **Mock Data Generation** — simulates realistic attacker log events
2. **Attacker Profiling** — classifies attackers into behavioral categories (e.g. Casual Scanner, Driven Explorer, Targeted Attacker)
3. **MITRE ATT&CK Mapping** — maps observed attack types (SQL Injection, Credential Stuffing, Brute Force, XSS, etc.) to MITRE techniques, tactics, and severity
4. **Behavioral Analysis** — assigns attacker personas (Script Kiddie, Researcher/Scanner, Opportunist) based on activity patterns
5. **Geo Enrichment** — maps attacker IPs to geographic origin for visualization
6. **Dashboard** — a Plotly Dash web app presenting all findings live

## Dashboard Tabs

- **Overview** — total events, attack frequency by hour, attacker profile distribution, top attack-source countries, live threat feed
- **MITRE ATT&CK** — full threat feed table (IP, country, attack type, MITRE ID/technique/tactic, severity, threat score, attacker profile) and tactic distribution chart
- **Geo Map** — world map showing attack volume by region
- **Threat Scores** — threat score distribution by attacker profile, and threat score vs. login attempts scatter plot

## Tech Stack

- Python
- Plotly Dash / Flask
- Pandas (data processing)
- MITRE ATT&CK framework mapping

## Setup

```bash
# Clone the repo
git clone <your-repo-url>
cd honeypot-profiler

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate  # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

## Usage

### 1. Generate mock data and run the profiling pipeline

```bash
python main.py --mock --profile
```

Add `--geo` to also generate geolocation data for the map view:

```bash
python main.py --mock --profile --geo
```

This produces:
- `data/mock_logs.csv` — simulated honeypot log events
- `data/profiles.csv` — attacker profiles enriched with MITRE ATT&CK mapping and behavioral personas

### 2. Launch the dashboard

```bash
python dashboard.py
```

Then open **http://127.0.0.1:8050** in your browser.

## Notes

- All data used in this project is **synthetically generated** (`--mock` flag) for demonstration and portfolio purposes — no real attacker or victim data is involved.
- Data files in `data/` are excluded from version control (see `.gitignore`) since they can be regenerated on demand.

## Disclaimer

This project is for educational and portfolio purposes only, simulating threat intelligence workflows using mock data.
