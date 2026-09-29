# OMEGA Architecture Overview

## System Components

```
┌─────────────────────────────────────────────────────────┐
│                    OPERATOR WORKSTATION                  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │           React 19 Frontend (Vite)              │   │
│  │  10 Pages: Overview | Captures | Tunnels |      │   │
│  │  Findings | Intelligence | Evidence | Compare   │   │
│  │  | Reports | Standards | System                 │   │
│  └──────────────────┬──────────────────────────────┘   │
│                     │  REST API /api/v1                  │
│  ┌──────────────────▼──────────────────────────────┐   │
│  │           FastAPI Backend (Python 3.12)          │   │
│  │                                                  │   │
│  │  ┌────────────┐  ┌─────────────┐  ┌──────────┐ │   │
│  │  │  Parsers   │  │  Engines    │  │  ML      │ │   │
│  │  │  PCAP      │  │  Rules      │  │  XGBoost │ │   │
│  │  │  IKEv1/v2  │  │  Risk       │  │  SHAP    │ │   │
│  │  │  ESP       │  │  Digital    │  │  Feature  │ │   │
│  │  │  NAT-T     │  │  Twin       │  │  Extract  │ │   │
│  │  └────────────┘  └─────────────┘  └──────────┘ │   │
│  │                                                  │   │
│  │  ┌────────────────────────────────────────────┐ │   │
│  │  │          SQLite Database (omega.db)        │ │   │
│  │  │  12 entities: Capture, Tunnel, IKESession  │ │   │
│  │  │  ESPSa, FlowWindow, Finding, Report...    │ │   │
│  │  └────────────────────────────────────────────┘ │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         ZERO external network calls in AIR-GAP mode
```

## 4-Tier Visibility Boundary Model

| Tier | Label | Confidence | Examples |
|------|-------|-----------|---------|
| 1 | OBSERVED | 100% | IKE version, SPIs, DH group, exchange type |
| 2 | DERIVED | 100% | Tunnel duration, rekey count, sequence gaps |
| 3 | INFERRED | 60-95% | ML anomaly classification, behavioral patterns |
| 4 | UNOBSERVABLE | N/A | ESP payload, inner IPs/ports, PSKs, keys |

## 12-Stage Analysis Pipeline

```
PCAP Upload
    │
    ▼
[1] SHA-256 Validation
    │
    ▼
[2] Scapy Packet Parsing (streaming, malformed-tolerant)
    │
    ▼
[3] IKE Classification (UDP 500/4500 header inspection)
    │
    ▼
[4] ESP & NAT-T Parsing (Proto 50, UDP 4500 marker)
    │
    ▼
[5] Session Aggregation (bidirectional tunnel clustering)
    │
    ▼
[6] IKE Feature Extraction (transforms, SPIs, versions)
    │
    ▼
[7] ESP Flow Window Computation (IAT, sizes, bursts)
    │
    ▼
[8] SA Correlation (IKE↔ESP SPI matching, rekeys)
    │
    ▼
[9] Deterministic Rule Evaluation (YAML rules, OBSERVED only)
    │
    ▼
[10] ML Anomaly Detection (XGBoost on flow windows, INFERRED)
    │
    ▼
[11] Explainable Risk Formulation (5-dimension weighted score)
    │
    ▼
[12] Evidence Indexing (frame# → finding → hex offset chain)
    │
    ▼
Database Storage → REST API → Frontend Display
```
