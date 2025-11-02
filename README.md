# SIEM Detection Simulator

Overview
This small Python project demonstrates simple SIEM-style detection rules using two open datasets:

- SecurityDatasets (Windows / Sysmon examples) — for PowerShell & privilege escalation detection.
- CIC-IDS2017 (CICFlowMeter-style flows) — for network flow detection (external IP on unusual port).

Place sample CSV files (optional) at `data/real/`:

- `data/real/sysmon_sample.csv` — Sysmon/Windows CSV (or convert EVTX → CSV; instructions below)
- `data/real/cicflows_sample.csv` — CIC flow CSV (CICFlowMeter-like)

Quick start (Windows PowerShell)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements.txt
python -m src.main
```

If sample files are missing the loaders will print a [WARN] with download instructions.

Detections

- Suspicious PowerShell Command (High)
- User Privilege Escalation (Medium)
- External IP Connection on Unusual Port (Low / escalates for C2 ports)

Output

- `alerts.csv` — merged alerts (rule_name, timestamp, source, dest_or_command, description, severity, dataset_source)
- `alerts_summary.png` — visual summary (counts per rule and timeline)

Datasets & download instructions

- SecurityDatasets Sysmon examples: https://securitydatasets.com
  - If you have EVTX logs, convert on Windows using PowerShell:
    ```powershell
    # Example: export Sysmon Operational log to CSV (Admin)
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Export-Csv -Path sysmon_sample.csv -NoTypeInformation
    ```
  - Or download a prepared CSV sample from SecurityDatasets and place as `data/real/sysmon_sample.csv`.

- CIC-IDS2017 flows (info & downloads): https://www.unb.ca/cic/datasets/ids-2017.html
  - Use CICFlowMeter output or prepared flow CSV. Place as `data/real/cicflows_sample.csv`.

Notes

- Loaders perform best-effort header normalization (case-insensitive aliases).
- Reverse-DNS enrichment for network alerts is attempted but non-fatal (requires internet).
