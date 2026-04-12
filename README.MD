![SYNINT Logo](docs/assets/synint-logo.png)

# SYNINT v3

SYNINT is a local-first OSINT investigation framework with staged execution, pluggable collection engines, centralized evidence/entity registries, and structured export reporting.

## Release Snapshot

- Full agent suite: 46 agents (canonical order from `agents.AGENT_ORDER`)
- Execution models:
  - Concurrent run-all (default)
  - Staged pipeline (`quick`, `standard`, `deep`)
- Collection modes:
  - `low_noise`
  - `balanced`
  - `stealth`
  - `deep_browser`
- Report outputs per run:
  - `synint.log`
  - `synint_report.json`
  - `synint_report.html`
  - `collection_artifacts/`
  - Investigation export bundle (`summary.json`, `report.md`, and related files)
- Path handling is project-root anchored via `synint_paths.py` for consistent output behavior.

## Release Notes (v3.0.0 - April 12, 2026)

- Major framework refresh for SYNINT v3 with staged pipeline orchestration and concurrent run-all execution.
- Expanded intelligence coverage to 46 agents spanning collection, entity resolution, history, media forensics, infrastructure pivoting, and synthesis/export.
- Added multi-engine collector abstraction with graceful fallback across `StaticHttp`, `Scrapling`, `Scrapy`, and `Camoufox`.
- Improved report generation with per-run artifact directories and structured export bundles (`summary.json`, `evidence_register.csv`, `report.md`, graph/timeline/leads JSON).
- Hardened runtime path behavior using project-root anchored paths (`synint_paths.py`) for reliable output from different working directories.
- Refreshed documentation and release packaging for cleaner onboarding and publish readiness.

Full publish-ready release text: [RELEASE_NOTES_v3.0.0.md](RELEASE_NOTES_v3.0.0.md)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

Run from project root:

```bash
python3 main.py https://target.tld
```

List available agents:

```bash
python3 main.py --list-agents
```

Run specific agents:

```bash
python3 main.py https://target.tld --agents WhoisAgent,DNSEnumAgent
```

Exclude specific agents:

```bash
python3 main.py https://target.tld --exclude-agents IDSAgent,MITMAgent
```

## Pipeline Execution

Standard staged pipeline:

```bash
python3 main.py https://target.tld --pipeline --pipeline-mode standard
```

Quick profile:

```bash
python3 main.py https://target.tld --pipeline --pipeline-mode quick
```

Deep profile:

```bash
python3 main.py https://target.tld --pipeline --pipeline-mode deep
```

Set collection mode explicitly:

```bash
python3 main.py https://target.tld --pipeline --pipeline-mode deep --collection-mode stealth
```

## Runtime Knobs

Prefer a collector globally:

```bash
SYNINT_PREFER_COLLECTOR=scrapling python3 main.py https://target.tld
```

Tune Wayback request bounds:

```bash
SYNINT_WAYMORE_LIMIT_REQUESTS=40 SYNINT_WAYMORE_TIMEOUT=240 python3 main.py https://target.tld
```

Compatibility mode (same as default run-all behavior):

```bash
python3 main.py https://target.tld --legacy-run-all
```

## Reports And Artifacts

Each run writes to:

- `reports/<target-mm.dd.yy-HHMM>/`

Per-run files:

- `synint.log`
- `synint_report.json`
- `synint_report.html`
- `collection_artifacts/`
  - `raw_html/`
  - `rendered_html/`
  - `screenshots/`
  - `headers/`
  - `response_meta/`
  - `extracted_text/`
  - `downloads/`

`ReportBuilderAgent` additionally writes investigation exports (for example `summary.json`, `evidence_register.csv`, `report.md`) into the run directory.

## Collector Engines

- `StaticHttpCollector`: Default bounded HTTP collector.
- `ScraplingCollector` (optional): Structured HTML parsing when installed.
- `ScrapyCollector` (optional): Scrapy-compatible crawl path with fallback behavior.
- `CamoufoxCollector` (optional): Stealth/browser-capable collection when runtime is available.

Missing optional engines degrade gracefully without crashing a run.

## Agent Catalog (46 Total)

### Core OSINT Agents

| Agent | What It Provides |
|---|---|
| `CybintAgent` | Baseline network and security-header reconnaissance for the target. |
| `SocialMediaAgent` | Public profile and handle discovery across major social platforms. |
| `WhoisAgent` | WHOIS lookup parsing for registrar and domain registration context. |
| `IDSAgent` | Local anomaly detection over IDS-like event patterns. |
| `MITMAgent` | Traffic relationship mapping and suspicious intermediary path signals. |
| `SIEMAgent` | SIEM-style event clustering and correlated activity grouping. |
| `TechIntAgent` | Infrastructure and technical exposure profiling of target systems. |
| `ThreatAnalyzerAgent` | Consolidated risk synthesis across outputs, contradictions, and leads. |
| `DNSEnumAgent` | DNS record enumeration and basic subdomain posture checks. |
| `EmailHarvestAgent` | Candidate email artifact generation and scoring. |
| `MetadataExtractionAgent` | File metadata extraction, hashing, and suspicious naming indicators. |
| `GitHubIntelAgent` | GitHub target-context enrichment for user/repository intelligence. |
| `SSLCertAnalysisAgent` | Certificate metadata analysis, trust cues, and expiry risk checks. |
| `IPReputationAgent` | IP posture classification and local network-context signals. |
| `DarkWebMonitorAgent` | Local-first breach/dark-web style indicator matching scaffold. |
| `WaybackAnalysisAgent` | Historical URL discovery through local `waymore` integration. |
| `JobPostingIntelAgent` | Hiring and capability signal extraction from job-posting text. |
| `PortfolioMappingAgent` | Related asset mapping from domain and naming relationships. |
| `BlockchainIntelAgent` | Blockchain address artifact detection with chain hints. |
| `PhishingDetectionAgent` | Typosquat/permutation and phishing-style lexical risk scoring. |

### Collection Agents

| Agent | What It Provides |
|---|---|
| `WebCrawlerAgent` | Bounded crawl with link graphing, forms, contacts, and artifacts. |
| `DocumentIngestAgent` | Text extraction and entity parsing from local/downloaded documents. |
| `ArchiveFileDiscoveryAgent` | Probing of sensitive archive/backup file paths. |
| `DirectoryBruteAgent` | Curated path probing for admin/login/api/config exposure points. |
| `SearchEngineDiscoveryAgent` | Indexed-intel parsing from local search exports/corpora. |

### Entity And Identity Agents

| Agent | What It Provides |
|---|---|
| `ContactDiscoveryAgent` | Contact artifact normalization (emails, phones, addresses, pages). |
| `UsernameCorrelationAgent` | Username-variant generation and reuse correlation. |
| `PersonProfileAgent` | Person-centric profile assembly from aliases and source artifacts. |
| `EntityResolutionAgent` | Deterministic deduplication and confidence-weighted entity merges. |
| `RelationshipGraphAgent` | Graph-ready node/edge construction with source traceability. |

### Timeline And History Agents

| Agent | What It Provides |
|---|---|
| `TimelineReconstructionAgent` | Timestamp normalization into chronological investigation timelines. |
| `HistoricalDNSAgent` | Current vs historical DNS posture comparison from local snapshots. |
| `DomainRegistrationPatternAgent` | Registrar/TLD/age pattern analysis for campaign-style similarity. |

### File And Media Agents

| Agent | What It Provides |
|---|---|
| `OCRIngestAgent` | OCR text extraction from images when OCR tooling is available. |
| `ImageForensicsAgent` | Image fingerprinting, EXIF extraction, and lightweight forensic flags. |
| `TranscriptExtractionAgent` | Transcript parsing for entities, contradictions, and escalation cues. |
| `FileRelationshipAgent` | Cross-file correlation by hash, metadata, naming, and extracted entities. |

### Infrastructure And Pivot Agents

| Agent | What It Provides |
|---|---|
| `HostFingerprintAgent` | Deterministic host fingerprints and certificate/SAN pivot hints. |
| `ServiceBannerAgent` | Bounded banner collection across selected network services. |
| `CertificatePivotAgent` | Certificate CN/SAN pivoting into related domain hypotheses. |
| `ContentSimilarityAgent` | Content/template similarity clustering across collected assets. |
| `InfrastructureClusterAgent` | Evidence-based infrastructure clustering with explicit reason codes. |

### Synthesis And Export Agents

| Agent | What It Provides |
|---|---|
| `EvidenceScoringAgent` | Evidence tiering and confidence scoring normalization. |
| `ContradictionDetectionAgent` | Cross-source contradiction detection with citation-friendly outputs. |
| `LeadGenerationAgent` | Prioritized next-step investigative lead generation. |
| `ReportBuilderAgent` | Final markdown/JSON/CSV export bundle generation. |

## Testing

Run the local test suite:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Legal And Operational Note

Only run SYNINT against targets you are authorized to investigate. Collection behavior should be tuned to legal scope, policy, and engagement rules.
