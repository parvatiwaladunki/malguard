# MalGuard — Fileless Malware Detection Dashboard

A hybrid fileless malware detection system using **Random Forest ML + YARA rule engine** on process memory data, with a real-time SOC-style web dashboard.

---

## Quick Start

### Mac / Linux
```bash
chmod +x start.sh
./start.sh
```

### Windows
Double-click `start.bat`

The browser opens automatically at **http://localhost:5000**

> **Requires Python 3.9+** — download from https://python.org (Windows: check "Add Python to PATH")

---

## What it does

- Scans 60 simulated process memory snapshots on load
- Detects fileless attack techniques: Process Hollowing, DLL Injection, Reflective Loading, PowerShell abuse, LOLBins, WMI execution, and more
- Hybrid scoring: `0.6 × ML probability + 0.4 × YARA score`
- Live rescan with real-time streaming results

## Dashboard features

| Section | What you see |
|---|---|
| Overview | KPI cards, 24h detection timeline, live threat feed, risk distribution |
| Threat Alerts | Cards for every detected malicious process |
| Process List | Sortable table of all 60 scanned processes |
| ML Analytics | Feature importance, model metrics, score distribution |

**Download button** (top-right) exports:
- `PDF` — full analyst report with summary, threats table, YARA rules, ML metrics
- `CSV` — raw scan data, opens in Excel / Google Sheets

---

## Project structure

```
├── app.py              # Flask web dashboard
├── main.py             # Train / evaluate ML models
├── demo_scan.py        # CLI live-scan demo
├── src/
│   ├── hybrid_detector.py   # Core detection engine
│   ├── ml_models.py         # Random Forest + GB + SVM
│   ├── yara_engine.py       # YARA-like rule engine (10 rules)
│   ├── feature_extractor.py # 31 memory features
│   └── data_generator.py    # Synthetic process data
├── models/             # Pre-trained model (included)
├── yara_rules/         # YARA signature rules
└── templates/          # Dashboard HTML
```

## Retrain the model
```bash
# Mac/Linux
source venv/bin/activate && python main.py

# Windows
venv\Scripts\activate && python main.py
```
