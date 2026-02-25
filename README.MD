![Project Logo](shfwoiuh394790.png)

# SYNINT v2

[![Version](https://img.shields.io/badge/version-v2-blue.svg)](#whats-new-in-v2)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)

SYNINT v2 is a modular OSINT framework that runs multiple intelligence agents concurrently and writes structured outputs under `reports/`.

## What's New in v2
- Real-data-first behavior across agents (removed built-in sample/default indicator injection).
- SIEM pipeline hardened for edge cases (structured `skipped` output instead of crashes).
- Runtime fingerprinting added to reports:
  - `run_id`
  - `git_commit_hash`
  - `python_version`
  - `platform`
  - dependency snapshot file path
- Report generation standardized under `reports/`.
- Root directory cleanup model applied (generated artifacts not kept in project root).

## Core Features
- Modular agent model via `agents/base_agent.py` (`OSINTAgent` abstract class).
- Parallel execution via `agent_manager.py` using a thread pool.
- JSON + HTML reporting with execution metadata.
- Input-safe agents that return structured `ok`/`skipped`/`error` responses where applicable.

## Project Structure

```text
SYNINT/
├── README.MD
├── agent_manager.py
├── main.py
├── runtime_fingerprint.py
├── requirements.txt
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE
├── shfwoiuh394790.png
├── reports/
└── agents/
    ├── __init__.py
    ├── base_agent.py
    ├── cybint_agent.py
    ├── ids_agent.py
    ├── mitm_agent.py
    ├── siem_agent.py
    ├── social_media_agent.py
    ├── techint_agent.py
    ├── threat_analyzer_agent.py
    └── whois_agent.py
```

Runtime outputs are generated in:
- `reports/synint_report.json`
- `reports/synint_report.html`
- `reports/runtime_pip_freeze.txt`

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run all agents:

```bash
python main.py <target>
```

Example:

```bash
python main.py openai.com
```

## Agents
- `SocialMediaAgent`: Checks reachability of major platform profile URLs.
- `WhoisAgent`: Performs validated `whois` lookups.
- `CybintAgent`: Runs observable network checks (resolution, common ports, TLS/header findings).
- `IDSAgent`: Performs anomaly detection on newline-separated IDS logs.
- `MITMAgent`: Graph-based analysis from `source -> destination` network lines.
- `SIEMAgent`: Clusters newline-separated SIEM events with robust small-input handling.
- `TechIntAgent`: Host/service observations or frequency-domain image analysis.
- `ThreatAnalyzerAgent`: Aggregates provided threat indicators and computes risk.

## License
This project is licensed under the [MIT License](LICENSE).

## Contributing
See [CONTRIBUTING.md](CONTRIBUTING.md).

## Code of Conduct
See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
