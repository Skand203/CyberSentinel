# CyberSentinel

**Evidence-Driven Suspicious Content Analysis Engine & Triage Platform**

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=flat-square&logo=fastapi)
![Architecture](https://img.shields.io/badge/Stage-Architecture%20%26%20Specification-informational?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Overview

**CyberSentinel** is an open-source, evidence-driven security analysis platform designed to inspect suspicious URLs, email artifacts, and messages, generating clear Indicators of Compromise (IOCs) and interpretable threat reports.

Most threat intelligence tools either output cryptic raw data (hex dumps, raw WHOIS strings, entropy scores) that confuse non-specialists or deliver opaque risk scores (e.g., "Risk: 82/100") without explaining *why* a resource is malicious. 

CyberSentinel bridges this gap by implementing an **evidence-first extraction pipeline** that breaks down suspicious artifacts into transparent, verifiable technical indicators—such as domain age anomalies, lookalike unicode permutations, redirect chain manipulation, DNS reputation, and email authentication failures (SPF/DKIM/DMARC).

> **Project Status:** Architectural Specification & Scaffold Phase. The repository contains the modular component design, threat analysis pipeline specification, and data contract definitions. Core backend services are currently undergoing implementation.

---

## Analysis Pipeline Architecture

```text
 ┌─────────────────────────────────────────────────────────┐
 │ Input Submission (Suspicious URL / Raw Email / Message)  │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Stage 1: Static Normalization & Parsing                 │
 │  - URL canonization & un-shortening                     │
 │  - RFC 5322 Email header & MIME structure parsing       │
 │  - Extract IOCs: Domains, IPs, hashes, reply-to paths    │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Stage 2: Evidence Extraction Engine                     │
 │  ├── Domain & Infrastructure Inspection                 │
 │  │    - WHOIS registration age & registrar reputation   │
 │  │    - DNS resolution (A, AAAA, MX, TXT, NS records)    │
 │  │    - Punycode & Typosquatting distance (Levenshtein) │
 │  ├── Security Protocol Audit                            │
 │  │    - SSL/TLS certificate validity & issuer chain     │
 │  │    - Email auth validation: SPF, DKIM, and DMARC     │
 │  └── Reputation & Threat Feed Lookups                   │
 │       - Threat intelligence feeds & DNSBL checks        │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Stage 3: Evidence Synthesis & Scoring                   │
 │  - Deterministic indicator aggregation                  │
 │  - Risk tier calculation (Benign, Suspicious, Malicious)│
 │  - Plain-English analyst explanation generation         │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │ Output: Structured Evidence Report                      │
 └─────────────────────────────────────────────────────────┘
```

---

## Core Analysis Modules

### 1. URL & Domain Analyzer
- **Redirect Unwinding:** Follows HTTP 3xx redirect chains in a sandboxed client to uncover final destination URLs without executing client-side scripts.
- **Homoglyph & Typosquatting Detection:** Analyzes internationalized domain names (IDNs) and computes Levenshtein edit distances against high-value target brands (e.g., Google, Microsoft, PayPal).
- **Domain Age & Registrar Telemetry:** Inspects domain registration timestamps to identify newly registered domains (NRDs), a prominent indicator of throwaway phishing infrastructure.

### 2. Email Header & Authentication Verifier
- **Authentication Alignment:** Evaluates SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC alignment to detect email spoofing.
- **Routing Hop Analysis:** Inspects `Received` header chains to trace the true origin IP and identify MTA relay manipulation.
- **Header Inconsistency Detection:** Compares `From`, `Reply-To`, and `Return-Path` headers to flag mismatched response vectors.

### 3. Threat Report Synthesizer
- Compiles isolated technical findings into a unified, human-readable report explaining:
  - What indicators were detected.
  - Why those indicators represent risk.
  - Concrete defensive recommendations for the user or SOC analyst.

---

## Repository Structure

```text
CyberSentinel/
├── backend/
│   ├── analyzers/
│   │   ├── url_analyzer.py          # Domain, SSL, and redirect chain parser
│   │   ├── email_analyzer.py        # RFC 5322 header and SPF/DKIM validator
│   │   └── reputation.py            # Threat feed & DNSBL client
│   ├── core/
│   │   ├── config.py                # Environment configuration
│   │   └── pipeline.py              # Pipeline orchestration engine
│   ├── schemas/
│   │   ├── request.py               # Input submission models
│   │   └── report.py                # Evidence report serialization schemas
│   └── main.py                      # FastAPI application entrypoint
├── docs/
│   ├── threat_model.md              # Threat modeling and attack vectors
│   └── architecture.md              # In-depth system design & component contracts
├── frontend/
│   └── (Planned web investigation dashboard)
├── tests/
│   ├── test_url_analyzer.py         # URL parsing and un-shortening tests
│   └── test_email_analyzer.py       # Header validation unit tests
├── .gitignore
├── LICENSE
└── README.md
```

---

## API Specification (Target Contracts)

### Submit Content for Analysis
- **Route:** `POST /api/v1/analyze`
- **Request Body:**
  ```json
  {
    "type": "url",
    "target": "https://secure-login.paypa1-update.com/verify",
    "deep_inspection": true
  }
  ```

- **Response Body (`200 OK`):**
  ```json
  {
    "target": "https://secure-login.paypa1-update.com/verify",
    "risk_level": "MALICIOUS",
    "verdict": "High-confidence credential phishing page impersonating PayPal.",
    "evidence": [
      {
        "category": "Domain Infrastructure",
        "indicator": "Typosquatting Detected",
        "severity": "CRITICAL",
        "description": "Domain contains character substitution ('paypa1' instead of 'paypal')."
      },
      {
        "category": "Domain Infrastructure",
        "indicator": "Newly Registered Domain (NRD)",
        "severity": "HIGH",
        "description": "Domain registered 3 days ago via privacy-protected registrar."
      },
      {
        "category": "Transport Security",
        "indicator": "Free Automated TLS Certificate",
        "severity": "MEDIUM",
        "description": "Issued by Let's Encrypt 48 hours prior to scan."
      }
    ],
    "recommendations": [
      "Block domain on perimeter DNS and proxy firewalls.",
      "Reset credentials for any user who accessed the destination URI."
    ]
  }
  ```

---

## Planned Technical Stack

- **Backend:** Python 3.11+, FastAPI, Pydantic v2
- **Networking & DNS:** `dnspython`, `httpx`, `cryptography`
- **Email Parsing:** Python standard `email` library, `authres` (Authentication-Results parsing)
- **Data Store (Planned):** Redis (caching and rate limiting), PostgreSQL (historical analysis audit logs)

---

## Roadmap

- [x] Architectural design, component interfaces, and schema specifications.
- [ ] Implement URL canonization and recursive redirect un-shortening engine.
- [ ] Implement WHOIS parsing and domain age calculation service.
- [ ] Build RFC 5322 email header parser with SPF/DKIM validation.
- [ ] Expose FastAPI REST endpoints and integrate with lightweight UI.

---

## License

This project is licensed under the [MIT License](LICENSE).
