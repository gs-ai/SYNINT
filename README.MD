![SYNINT Logo](docs/assets/synint-logo.png)

# SYNINT v4

SYNINT is a local-first OSINT investigation framework with staged execution, pluggable collection engines, centralized evidence and entity registries, resumable runs, and structured forensic reporting.

## V4 Highlights

- Full agent suite: 46 agents in canonical order from `agents.AGENT_ORDER`.
- Execution models:
  - Concurrent run-all (default).
  - Staged pipeline (`quick`, `standard`, `deep`).
- Forensic runtime hardening:
  - Append-only chain-of-custody ledger in `chain_of_custody.jsonl`.
  - Per-agent checkpointing with resume support in `synint_checkpoint.json`.
  - Strict normalized-result validation before registry and report ingestion.
  - Local SQLite investigation store in `investigation.sqlite`.
- Runtime controls:
  - Manager-level `--agent-timeout` and `--agent-retries`.
  - Resume support through `--resume-checkpoint`.
- Reporting:
  - `synint.log`, `synint_report.json`, and `synint_report.html`.
  - `collection_artifacts/` plus the investigation export bundle (`summary.json`, `report.md`, and related files).
  - Forensic metadata paths included in exported reporting.
- Operational continuity:
  - Preserves the existing pipeline and run-all flow.
  - Keeps project-root anchored path handling via `synint_paths.py`.

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

Execution behavior:

- `python3 main.py https://target.tld --collection-mode stealth`
  - Runs the full program in default run-all mode.
  - Executes all selected agents.
  - Runs regular agents concurrently, then runs fusion/context-heavy agents in dependency-aware order.
- `python3 main.py https://target.tld --pipeline --pipeline-mode deep --collection-mode stealth`
  - Runs the deep staged pipeline only.
  - Executes only the agents included in the `deep` stage plan.
  - Preserves stage-by-stage context flow and result propagation between agents.

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

Resume a previous run from its checkpoint:

```bash
python3 main.py https://target.tld --pipeline --pipeline-mode deep --resume-checkpoint reports/example-06.12.26-1200/synint_checkpoint.json
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

Set manager-level timeout and retry controls:

```bash
python3 main.py https://target.tld --agent-timeout 30 --agent-retries 1
```

Compatibility mode (same as default run-all behavior):

```bash
python3 main.py https://target.tld --legacy-run-all --collection-mode stealth
```

## Reports And Artifacts

Each run writes to:

- `reports/<target-mm.dd.yy-HHMM>/`

Per-run files:

- `synint.log`
- `synint_report.json`
- `synint_report.html`
- `synint_checkpoint.json`
- `chain_of_custody.jsonl`
- `investigation.sqlite`
- `collection_artifacts/`
  - `raw_html/`
  - `rendered_html/`
  - `screenshots/`
  - `headers/`
  - `response_meta/`
  - `extracted_text/`
  - `downloads/`

`ReportBuilderAgent` also writes the investigation export bundle into the run directory and includes the v4 forensic paths in `report.md`.

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
| `CybintAgent` | Performs lightweight host reconnaissance including DNS resolution, common-port checks, SSL certificate signals, and security-header observations. |
| `SocialMediaAgent` | Checks likely public profile URLs across major platforms and classifies discovered, blocked, or ambiguous account results. |
| `WhoisAgent` | Runs WHOIS lookups for domains or IPs and surfaces registrar, registration, and raw-record context. |
| `IDSAgent` | Scores IDS-style event payloads for suspicious activity patterns and anomaly-oriented signal clustering. |
| `MITMAgent` | Analyzes network-path and relay-style indicators for intermediary, interception, or suspicious routing cues. |
| `SIEMAgent` | Correlates SIEM-like event text using vectorization and clustering to group related security events. |
| `TechIntAgent` | Collects real host/service observations such as IP resolution, reachable ports, and HTTP technology fingerprints. |
| `ThreatAnalyzerAgent` | Fuses upstream evidence, entities, contradictions, and leads into a consolidated threat and risk picture. |
| `DNSEnumAgent` | Enumerates A, AAAA, MX, NS, TXT, SPF, DMARC, DKIM, and common subdomain findings for DNS posture review. |
| `EmailHarvestAgent` | Generates and scores candidate email artifacts from target naming patterns and discovered text. |
| `MetadataExtractionAgent` | Extracts file metadata, hashes, naming cues, and basic suspicious-document indicators from local files. |
| `GitHubIntelAgent` | Enriches investigations with GitHub-oriented username, repository, and public code-surface intelligence. |
| `SSLCertAnalysisAgent` | Parses live SSL/TLS certificate details including SAN scope, issuer data, expiry state, and wildcard exposure. |
| `IPReputationAgent` | Classifies IP-oriented risk posture using local heuristics, reserved-range awareness, and basic network context. |
| `DarkWebMonitorAgent` | Provides local-first dark-web and breach-corpus matching readiness with entropy and target profiling scaffolds. |
| `WaybackAnalysisAgent` | Uses optional `waymore` integration to gather archived URLs, sensitive historical paths, and historical file exposure leads. |
| `JobPostingIntelAgent` | Extracts hiring, stack, capability, and organizational signals from job-posting text or collected artifacts. |
| `PortfolioMappingAgent` | Maps related brands, assets, and naming relationships to expand likely target portfolio coverage. |
| `BlockchainIntelAgent` | Detects wallet patterns, identifies likely chain families, and prepares blockchain artifacts for downstream enrichment. |
| `PhishingDetectionAgent` | Scores phishing and typosquat risk through lexical patterns, brand-style spoofing cues, and domain-shape heuristics. |

### Collection Agents

| Agent | What It Provides |
|---|---|
| `WebCrawlerAgent` | Performs bounded crawling with page summaries, link extraction, contact discovery, forms, and collected-file awareness. |
| `DocumentIngestAgent` | Ingests local or downloaded documents, extracts text, runs metadata extraction, and derives structured entities. |
| `ArchiveFileDiscoveryAgent` | Probes curated backup, archive, and sensitive file paths with bounded request classification. |
| `DirectoryBruteAgent` | Checks a small high-value path list for reachable admin, login, config, upload, and staging endpoints. |
| `SearchEngineDiscoveryAgent` | Parses local search exports or cached corpora to recover indexed URLs, admin-path hints, and mention signals. |

### Entity And Identity Agents

| Agent | What It Provides |
|---|---|
| `ContactDiscoveryAgent` | Aggregates and normalizes emails, phones, addresses, and contact pages from prior collection results. |
| `UsernameCorrelationAgent` | Generates username variants and correlates them against collected text and prior findings. |
| `PersonProfileAgent` | Builds person-centric profiles from aliases, usernames, contact artifacts, and supporting context. |
| `EntityResolutionAgent` | Deduplicates and merges entities deterministically with confidence-weighted normalization and source attribution. |
| `RelationshipGraphAgent` | Converts resolved entities and pivots into graph-ready nodes and edges with traceable relationships. |

### Timeline And History Agents

| Agent | What It Provides |
|---|---|
| `TimelineReconstructionAgent` | Normalizes temporal tokens from multi-agent findings into an ISO-ordered investigation timeline. |
| `HistoricalDNSAgent` | Compares current and historical DNS-oriented findings to surface hosting and resolution change patterns. |
| `DomainRegistrationPatternAgent` | Analyzes registrar, TLD, age, and registration-pattern similarities for campaign-style clustering. |

### File And Media Agents

| Agent | What It Provides |
|---|---|
| `OCRIngestAgent` | Extracts OCR text from images and image-based documents when local OCR tooling is available. |
| `ImageForensicsAgent` | Produces image hashes, EXIF-derived context, and lightweight tamper or anomaly indicators. |
| `TranscriptExtractionAgent` | Parses transcript-style text for speakers, entities, timeline cues, and contradiction-relevant statements. |
| `FileRelationshipAgent` | Correlates files by hashes, metadata, naming conventions, and extracted entity overlap. |

### Infrastructure And Pivot Agents

| Agent | What It Provides |
|---|---|
| `HostFingerprintAgent` | Builds deterministic host fingerprints from observed services, certificates, and resolved infrastructure cues. |
| `ServiceBannerAgent` | Collects small-scope network service banners from curated ports for quick infrastructure profiling. |
| `CertificatePivotAgent` | Pivots from SSL findings into SAN, wildcard, and certificate-scope related-domain hypotheses. |
| `ContentSimilarityAgent` | Compares collected textual content to detect template reuse, cloning, or strong similarity overlap. |
| `InfrastructureClusterAgent` | Groups related infrastructure using evidence-backed clustering logic and explicit reason annotations. |

### Synthesis And Export Agents

| Agent | What It Provides |
|---|---|
| `EvidenceScoringAgent` | Assigns evidence tiers, confidence levels, and collection-value distinctions across prior agent outputs. |
| `ContradictionDetectionAgent` | Detects cross-source conflicts in ownership, location, hostname, and timeline-related findings. |
| `LeadGenerationAgent` | Produces prioritized next-step investigative leads from high-value findings, gaps, and contradictions. |
| `ReportBuilderAgent` | Writes the final markdown, JSON, CSV, graph, timeline, and lead export bundle for the run. |

## Testing

Run the local test suite:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Legal And Operational Note

Only run SYNINT against targets you are authorized to investigate. Collection behavior should be tuned to legal scope, policy, and engagement rules.
