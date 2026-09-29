# OMEGA: Sovereign IPsec Security Intelligence & Assessment Platform

**Smart India Hackathon 2026** — Problem Statement **SIH26160**  
**Organization:** National Technical Research Organisation (NTRO), Government of India  
**System Classification:** Internal Critical Infrastructure / Air-Gapped Network Defense Platform  

---

## 1. Executive Overview

**OMEGA** is an air-gapped, passive IPsec VPN protocol analyzer, security compliance framework, and cryptographic intelligence workstation. It analyzes network packet traces (`.pcap` / `.pcapng`) containing IPsec traffic **without requiring pre-shared keys (PSK), private keys, VPN credentials, or payload decryption**.

### Fundamental Epistemic Principle
$$\mathbf{OBSERVED} \neq \mathbf{DERIVED} \neq \mathbf{INFERRED} \neq \mathbf{UNOBSERVABLE}$$

- **OBSERVED (100% Confidence):** Direct cleartext packet header fields (IKE versions, SPIs, DH Groups, Transforms, ESP Sequence Numbers).
- **DERIVED (100% Confidence):** Deterministically computed cross-packet metrics (Effective rekey intervals, sequence gaps, replay attempts, traffic duration).
- **INFERRED (Probabilistic):** Machine learning flow classification (XGBoost) and statistical anomaly detection with explicit confidence percentages.
- **UNOBSERVABLE (Explicitly Bounded):** ESP inner payloads, encapsulated inner IP headers, inner TCP/UDP ports, PSKs, and private keys are declared cryptographically protected and never fabricated.

---

## 2. Core Architectural Components

```
d:\IPsec/
├── backend/                       # Python 3.12+ FastAPI Sovereign Engine
│   ├── app/
│   │   ├── api/                   # REST API Routers (/captures, /tunnels, /findings, /reports, /compare, /system)
│   │   ├── core/                  # Configuration & 4-Tier Visibility Boundary Model
│   │   ├── db/                    # SQLite (Embedded) & PostgreSQL-Ready SQLAlchemy Database
│   │   ├── engines/               # Deterministic Rules, SA Correlator, Digital Twin, Anomaly, Risk Engines
│   │   ├── ml/                    # ESP Flow Feature Extractor, XGBoost Classifier, SHAP Explainability
│   │   ├── models/                # SQLAlchemy Relational Models (12 Normalized Entities)
│   │   ├── parsers/               # Resilient Scapy/Dpkt IKEv1, IKEv2, ESP (Proto 50), NAT-T (UDP 4500) Parsers
│   │   ├── reports/               # Audit-Grade ReportLab PDF & Machine-Readable JSON Generators
│   │   ├── rules/                 # Declarative Auditable YAML Rule Pack (RFC 8247, RFC 7296, NIST SP 800-77 Rev. 1)
│   │   ├── schemas/               # Typed Pydantic Request/Response DTOs
│   │   ├── services/              # 12-Stage Asynchronous Pipeline Orchestrator
│   │   └── utils/                 # Cryptographic Lookups, Synthetic PCAP & Database Seeder
│   └── tests/                     # Pytest End-to-End Test Suite
├── frontend/                      # React 19 + TypeScript + Vite + Tailwind CSS Console
│   └── src/
│       ├── components/            # Institutional AppShell, Header, Sidebar, Visibility & Severity Badges
│       ├── pages/                 # Overview, Capture Center, Tunnels, Findings, Intelligence, Evidence, Compare, Reports, Standards, System
│       ├── services/              # Typed REST API Client
│       └── types/                 # Domain Type Definitions
├── sample_captures/               # Ingestible PCAPs (Legacy 3DES IKEv1, Hardened IKEv2 AES-GCM, NAT-T Encapsulation)
└── scripts/                       # Native Execution Launchers (run_backend, run_frontend, run_all)
```

---

## 3. The 12-Stage Ingestion & Assessment Pipeline

When a `.pcap` or `.pcapng` file is submitted to `POST /api/v1/captures`, OMEGA executes:

1. **Validation:** File integrity check and cryptographic SHA-256 calculation.
2. **Packet Parsing:** Resilient streaming frame extraction using Scapy.
3. **IKE Classification:** UDP 500 / 4500 header detection and exchange identification.
4. **ESP & NAT-T Parsing:** IP Protocol 50 and UDP 4500 Non-ESP marker disambiguation.
5. **Session Aggregation:** Bidirectional tunnel clustering by endpoint IP pairs.
6. **IKE Feature Extraction:** Transform inspection (Encryption, PRF, Integrity, DH groups).
7. **ESP Flow Dynamics:** Rolling temporal window metadata metrics (IAT, Packet sizes, Bursts).
8. **SA Correlation:** Associating IKE SAs with Child ESP SAs and rekey events.
9. **Deterministic Standards Evaluation:** Auditing against declarative YAML rules.
10. **Statistical & ML Anomaly Detection:** XGBoost behavioural classification and SHAP attribution.
11. **Explainable Risk Formulation:** Multi-dimensional score across Crypto, Key Mgmt, Protocol, Anomaly, and Metadata.
12. **Evidence Indexing:** Traceable linking from findings to frame numbers and hex bytes.

---

## 4. Quick Start & Execution

### Prerequisites
- **Python 3.12+** (managed via `uv`)
- **Node.js 18+** & **npm**

### 1. Launching Backend & Frontend Together
Run the Windows batch launcher:
```bat
scripts\run_all.bat
```
Or execute in PowerShell:
```powershell
.\scripts\run_all.ps1
```

### 2. Manual Individual Execution
**Backend:**
```powershell
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation available at: `http://127.0.0.1:8000/docs`

**Frontend:**
```powershell
cd frontend
npm run dev
```
Workstation Console accessible at: `http://localhost:5173`

---

## 5. Running Automated Backend Tests

```powershell
cd backend
uv run pytest
```
All unit tests for Scapy parsing, YAML rule evaluation, explainable risk calculations, and before/after capture comparisons run offline.

---

## 6. Standards Compliance Mapping

| Standard / RFC | Title / Scope | OMEGA Implementation |
| :--- | :--- | :--- |
| **RFC 8247** | Cryptographic Algorithms for IKEv2 | Audits 3DES, DES, NULL, MD5, SHA1 deprecation and verifies approved DH Groups (19, 20, 14). |
| **NIST SP 800-77 Rev. 1** | Guide to IPsec VPNs | Enforces 112/128-bit minimum security strengths and flags excessive rekey intervals (>8h). |
| **RFC 9395** | Deprecation of IKEv1 | Identifies legacy IKEv1 protocol usage and flags Aggressive Mode PSK dictionary vulnerability. |
| **RFC 3948** | UDP Encapsulation of IPsec ESP | Distinguishes 4-byte Non-ESP marker, encapsulated ESP, and NAT keepalives on UDP 4500. |
| **RFC 4303** | IP Encapsulating Security Payload | Analyzes anti-replay sequence continuity and detects sequence gaps or duplicate arrivals. |

---

## 7. Air-Gapped Sovereign Security Guarantee

- **Zero Cloud Dependencies:** No OpenAI, Claude, Gemini, or remote LLM API calls.
- **Zero Telemetry:** No third-party trackers, analytics, or external font CDNs.
- **Local Storage:** Fully self-contained embedded SQLite database (`data/omega.db`).
- **Deterministic Explainability:** Mathematical risk contribution breakdowns without hallucination.
