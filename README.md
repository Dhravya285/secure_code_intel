# AI-Powered Secure Code Intelligence & Prioritization Engine

A hybrid static analysis + ML scoring + LLM reasoning system that detects, scores, and prioritizes security vulnerabilities in Python codebases — with a full web UI and one-click PDF report export.

**F1 Score: 0.92 | Precision: 0.94 | Recall: 0.91 | 8 Vulnerability Types | 53 Findings Detected**

---

## Architecture

```
Source Code (.py files)
        │
        ▼
┌─────────────────────┐
│   Static Scanner    │  AST-based detection (no regex)
│   ast_scanner.py    │  8 vulnerability detectors
└────────┬────────────┘
         │  raw findings: {type, file, line, code, details}
         ▼
┌─────────────────────┐
│ Feature Engineering │  Converts findings → numeric feature vectors
│ feature_engineer.py │  uses_user_input, uses_concat, dangerous_function...
└────────┬────────────┘
         │  features + feature_signal (0–1)
         ▼
┌─────────────────────┐
│   Static Scorer     │  Risk Score = 0.6 * base_severity
│   risk_scorer.py    │            + 0.4 * feature_signal
└────────┬────────────┘
         │  static_risk_score (0–1)
         ▼
┌─────────────────────┐
│    LLM Engine       │  Local Llama via Ollama
│    llm_client.py    │  Structured JSON: explanation, exploit,
│  prompt_templates   │  patched_code, cwe, severity_confidence
└────────┬────────────┘
         │  llm_response
         ▼
┌─────────────────────┐
│  Patch Validator    │  1. ast.parse() syntax check
│ patch_validator.py  │  2. Re-run scanner on patch
└────────┬────────────┘  3. Penalize score if still vulnerable
         │  validation result + score_penalty
         ▼
┌─────────────────────┐
│   Hybrid Scorer     │  Final Risk = 0.6 * static_score
│  hybrid_scorer.py   │            + 0.4 * llm_confidence
└────────┬────────────┘            - score_penalty
         │  final_risk (0–1) per vulnerability
         ▼
┌─────────────────────┐
│    Aggregator       │  Groups findings by type + module
│   aggregator.py     │  Builds clusters with stats
└────────┬────────────┘
         │  clusters: {type, count, affected_files, avg_risk...}
         ▼
┌─────────────────────┐
│  Cluster Scorer     │  Priority = 0.4 * avg_risk
│  cluster_scorer.py  │           + 0.2 * frequency
└────────┬────────────┘           + 0.2 * exploit_confidence
         │                        + 0.2 * module_weight
         ▼
┌─────────────────────┐
│ Business Explainer  │  LLM explains top 3 clusters
│business_explainer   │  why_critical, business_impact,
└────────┬────────────┘  fix_order, estimated_effort
         │
         ▼
┌─────────────────────┐
│    Evaluation       │  Precision / Recall / F1
│   eval_runner.py    │  Static vs Hybrid comparison
│     compare.py      │
└─────────────────────┘
         │
         ▼
   Ranked Security Report (6 JSON output files + PDF export)
```

---

## Vulnerability Types Detected

| # | Type | CWE | Severity |
|---|------|-----|----------|
| 1 | SQL Injection | CWE-89 | 0.90 |
| 2 | Command Injection | CWE-78 | 0.95 |
| 3 | Hardcoded Credentials | CWE-798 | 0.75 |
| 4 | Path Traversal | CWE-22 | 0.85 |
| 5 | Insecure Deserialization | CWE-502 | 0.92 |
| 6 | SSRF | CWE-918 | 0.88 |
| 7 | Weak Cryptography | CWE-327 | 0.70 |
| 8 | Debug Mode | CWE-94 | 0.60 |

---

## Project Structure

```
secure-code-intel/
│
├── config.py                    # Central config: weights, severities, CWE map
├── main.py                      # Full pipeline runner (CLI)
├── app.py                       # Flask web backend (REST API + static serving)
├── requirements.txt
│
├── ui/
│   └── index.html               # Web UI — drag & drop, scan, PDF export
│
├── scanner/
│   ├── ast_scanner.py           # 8 AST-based vulnerability detectors
│   └── feature_engineer.py      # Feature extraction + signal scoring
│
├── scoring/
│   ├── risk_scorer.py           # Static risk scoring
│   └── hybrid_scorer.py         # Ensemble static + LLM scoring
│
├── llm/
│   ├── llm_client.py            # Ollama client with 4-strategy JSON parsing
│   ├── prompt_templates.py      # Structured prompts for vuln + cluster analysis
│   └── patch_validator.py       # Syntax check + re-scan feedback loop
│
├── prioritization/
│   ├── aggregator.py            # Group findings into clusters by type + module
│   ├── cluster_scorer.py        # Priority scoring model for clusters
│   └── business_explainer.py   # LLM business-level cluster explanations
│
├── evaluation/
│   ├── eval_runner.py           # Precision / Recall / F1 against ground truth
│   └── compare.py               # Static-only vs Hybrid scoring comparison
│
├── data/
│   ├── vulnerable/              # 12 intentionally vulnerable Python files
│   │   ├── admin_panel.py       # All 8 vulnerability types
│   │   ├── auth_service.py      # SQL + Weak Crypto + Hardcoded + SSRF
│   │   ├── user_service.py      # SQL + SSRF + Hardcoded
│   │   ├── file_manager.py      # Path Traversal + Command Injection + Weak Crypto
│   │   ├── api_server.py        # Debug Mode + SQL + Command Injection
│   │   ├── data_pipeline.py     # Deserialization + Path Traversal + Hardcoded
│   │   ├── auth.py              # SQL Injection
│   │   ├── login.py             # SQL Injection
│   │   ├── config.py            # Hardcoded Credentials
│   │   ├── db.py                # SQL + Command Injection
│   │   ├── api.py               # Command Injection
│   │   └── utils.py             # Command Injection + Hardcoded Credentials
│   │
│   └── safe/                    # 6 safe counterpart files (for evaluation)
│
└── outputs/
    ├── scan_results.json        # Raw AST detections
    ├── scored_vulns.json        # After static scoring
    ├── final_report.json        # Full hybrid scored findings
    ├── cluster_report.json      # Ranked clusters + business explanations
    ├── evaluation_results.json  # Precision / Recall / F1
    └── comparison_report.json   # Static vs Hybrid delta analysis
```

---

## Setup & Installation

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed and running (only required for Full Pipeline mode)

### Install

```bash
# Clone the repo
git clone https://github.com/yourusername/secure-code-intel.git
cd secure-code-intel

# Install Python dependencies
pip install flask flask-cors ollama

# Pull the LLM model — required only for Full Pipeline mode (~2 GB)
ollama pull llama3.2:3b

# Start Ollama server in a separate terminal (Full Pipeline only)
ollama serve
```

### Run — Web UI (recommended)

```bash
python app.py
# Open http://localhost:5000
```

Upload `.py` files via drag & drop, choose a scan mode, and hit **Run Scan**.

### Run — CLI

```bash
# Full pipeline on default data/vulnerable/ directory
python main.py

# Scan a specific directory
python main.py --target path/to/your/code
```

---

## Web UI

The web interface is served by `app.py` and lives in `ui/index.html`. No build step required.

### Scan Modes

| Mode | Description | Speed |
|------|-------------|-------|
| **Static Scan** | AST-based detection only, no LLM | < 3 seconds |
| **Full Pipeline** | Static + LLM analysis, patch generation, business explanations | 1–3 minutes |

### Views

**Upload** — drag & drop `.py` files, select scan mode, start scan.

**Overview** — stat cards (total findings, clusters, critical count, avg risk), findings-by-type bar chart, risk distribution histogram, and top priority clusters.

**Findings** — filterable, sortable table of all vulnerabilities. Click any row to open a detail panel showing: risk scores, vulnerable code, LLM explanation, exploit scenario, patched code, CWE reference, and patch validation status.

**Clusters** — expandable cluster cards ranked by priority score, each showing avg risk, finding count, estimated effort, affected modules, and LLM-generated business impact and fix guidance.

**Evaluation** — severity breakdown, type distribution, patch rate, and (in Full Pipeline mode) a static vs hybrid delta table showing how much the LLM adjusted each score.

### PDF Export

After any scan completes, the **⬇ Export PDF** button in the header becomes active. Clicking it generates and downloads a multi-page PDF report entirely in the browser — no server call required.

The PDF contains:

- **Cover page** — project branding, scan metadata, summary stat cards, cluster priority table
- **All Findings** — full sortable table with type, file, line, risk score, severity, CWE, and patch status
- **Cluster Analysis** — per-cluster cards with risk metrics, effort estimate, affected modules, and LLM business context
- **Detailed Finding Analysis** — per-finding deep-dive with code snippets, explanations, exploit scenarios, and patches (Full Pipeline only)
- **Metrics & Risk Distribution** — severity breakdown bars, type distribution, and static vs hybrid scoring delta

The filename is auto-stamped: `scie-report-YYYY-MM-DD-HH-MM-SS.pdf`.

---

## Scoring Models

### Static Risk Score
```
Risk Score = 0.6 × base_severity + 0.4 × feature_signal
```
- `base_severity` — domain knowledge score per vulnerability type (from `config.py`)
- `feature_signal` — weighted sum of binary features extracted from the AST

### Hybrid Risk Score
```
Final Risk = 0.6 × static_score + 0.4 × llm_confidence − score_penalty
```
- `llm_confidence` — LLM's assessment of exploitability (0–1)
- `score_penalty` — 0.15 for a syntax error in the generated patch, 0.10 if the patch still contains the vulnerability

### Cluster Priority Score
```
Priority = 0.4 × avg_final_risk
         + 0.2 × normalized_frequency
         + 0.2 × exploit_confidence
         + 0.2 × module_weight
```
Module weights: `auth/*` = 1.0, `admin/*` = 0.9, `db/*` = 0.8, `config/*` = 0.7, `utils/*` = 0.5

---

## Results

### Cluster Rankings (on test dataset)

| Rank | Type | Count | Avg Risk | Priority | Label |
|------|------|-------|----------|----------|-------|
| #1 | Hardcoded Credentials | 14 | 0.657 | 0.833 | P0 — IMMEDIATE |
| #2 | Command Injection | 7 | 0.790 | 0.766 | P0 — IMMEDIATE |
| #3 | SQL Injection | 6 | 0.772 | 0.765 | P0 — IMMEDIATE |
| #4 | Path Traversal | 7 | 0.754 | 0.752 | P0 — IMMEDIATE |
| #5 | SSRF | 5 | 0.765 | 0.747 | P1 — HIGH |
| #6 | Insecure Deserialization | 5 | 0.731 | 0.714 | P1 — HIGH |
| #7 | Weak Cryptography | 5 | 0.640 | 0.697 | P1 — HIGH |
| #8 | Debug Mode | 4 | 0.580 | 0.639 | P1 — HIGH |

### Evaluation Metrics

| Metric | Score |
|--------|-------|
| Precision | 0.9355 |
| Recall | 0.9062 |
| F1 Score | **0.9206** |
| True Positives | 29 |
| False Positives | 2 |
| False Negatives | 3 |

---

## API Reference

`app.py` exposes two endpoints consumed by the UI.

### `POST /api/scan`

Upload files and start a scan job.

| Field | Type | Description |
|-------|------|-------------|
| `files` | multipart | One or more `.py` files |
| `mode` | string | `"static"` or `"full"` |

Returns `{ "job_id": "<8-char id>" }`.

### `GET /api/status/<job_id>`

Poll scan progress. While running, returns `{ id, status, progress, step, log }`.
When complete (`status: "done"`), also returns `findings`, `clusters`, and `metrics`.

---

## Design Decisions

**Why AST over regex?**
AST parsing understands code structure — it knows `execute` is a method call on a `cursor` object, not just a word in a string. Regex matches text; AST matches semantics.

**Why local LLM (Ollama)?**
No API costs, no data leaving the machine, consistent availability. Works on 8 GB RAM with `llama3.2:3b`.

**Why cluster-based prioritization over individual ranking?**
53 individual findings is noise. 8 ranked clusters is actionable. A team can fix "all SQL Injection across auth modules" — they can't meaningfully fix "vulnerability #23".

**Why patch validation?**
LLMs sometimes generate syntactically invalid patches or patches that don't actually fix the vulnerability. The validation loop provides a feedback signal — bad patches reduce the final risk score.

**Why client-side PDF generation?**
Using `jsPDF` + `jsPDF-AutoTable` in the browser means no server-side PDF libraries, no temp files, no extra routes. The entire report is assembled from the already-loaded scan data and downloaded instantly.

---

## Extending the Scanner

Adding a new vulnerability type requires touching exactly 3 files:

```python
# 1. config.py — add severity and CWE
BASE_SEVERITY["New Vuln Type"] = 0.85
CWE_MAP["New Vuln Type"]       = "CWE-XXX"
PATCH_HINT["New Vuln Type"]    = "safe_alternative()"

# 2. scanner/ast_scanner.py — add detector function
def detect_new_vuln(tree, source_lines):
    findings = []
    # ... AST walking logic
    return findings

# register it in scan_file():
findings += detect_new_vuln(tree, source_lines)

# 3. scanner/feature_engineer.py — add feature extractor
def extract_new_vuln_features(finding):
    return { "feature_name": 1, ... }

# register it in FEATURE_EXTRACTORS dict:
FEATURE_EXTRACTORS["New Vuln Type"] = extract_new_vuln_features
```

Everything else — scoring, LLM, validation, clustering, PDF export, evaluation — works automatically.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| AST parsing | `ast` (built-in) |
| Web backend | Flask + flask-cors |
| LLM inference | Ollama (`llama3.2:3b`) |
| UI fonts | JetBrains Mono, Syne, Inter (Google Fonts) |
| PDF generation | jsPDF 2.5 + jsPDF-AutoTable 3.8 (client-side) |
| Output format | JSON (6 files) + PDF |

No ML frameworks. No heavy dependencies. Runs entirely on a laptop with 8 GB RAM.

---

## Output Files

| File | Description |
|------|-------------|
| `outputs/scan_results.json` | Raw AST detections |
| `outputs/scored_vulns.json` | Static scored findings |
| `outputs/final_report.json` | Full hybrid scored findings with LLM data |
| `outputs/cluster_report.json` | Ranked clusters with business explanations |
| `outputs/evaluation_results.json` | Precision / Recall / F1 per file |
| `outputs/comparison_report.json` | Static vs Hybrid delta analysis |
| `scie-report-<timestamp>.pdf` | Downloaded via browser — full multi-page report |