# CyberSentinel v2.0.0

Advanced File Integrity Monitoring & Threat Detection Platform built with Python and CustomTkinter.

Author: Saad Zaffar Laghari (FA23-BCS-169)

## Features
- Real-time file integrity monitoring and change detection
- Threat intelligence analysis and custom rules engine
- Quarantine vault and restore/delete workflows
- Network port scanning with risk scoring
- Process monitoring and system health metrics
- Honeypot decoy deployment and monitoring
- Encrypted audit trail with chain hashing
- Analytics dashboard with charts and export tools
- Modern dark-themed CustomTkinter GUI

## Project Structure
```
CyberSentinel/
├── app.py
├── config.py
├── utils.py
├── requirements.txt
├── core/
├── database/
├── gui/
└── data/
```

## Setup
1. Ensure Python 3.10+ is installed.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the app:
   ```bash
   python app.py
   ```

## First Run
- On first launch, you may set a password or leave it blank to skip authentication.
- The default monitoring folder is `~/Desktop/monitor_folder`. You can change it in **Settings**.
- Runtime data (reports, audit logs, quarantine) is stored under the `data/` folder and is auto-created.

## Notes
- This tool is intended for defensive/security monitoring use cases.
- Email alerts require SMTP credentials configured in the Settings panel.
