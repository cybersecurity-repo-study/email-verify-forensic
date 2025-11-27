# Email Forensic Analyzer

A Python tool for investigating spam and phishing emails through header analysis, URL extraction, and threat detection.

## Features

- **Authentication Analysis** — SPF, DKIM, DMARC, and ARC verification
- **Risk Scoring** — 0-100 score with severity levels (CLEAN/LOW/MEDIUM/HIGH)
- **Email Extraction** — Collects all addresses from headers and body
- **URL Analysis** — Detects link shorteners, suspicious TLDs, IP-based URLs, homograph attacks
- **Domain Mismatch Detection** — Compares From/Return-Path/Reply-To
- **Attachment Analysis** — MD5/SHA256 hashes, dangerous extension detection
- **Phishing Keyword Detection** — Urgency/fear tactic patterns
- **Mail Routing Analysis** — Full Received chain with IPv4/IPv6 extraction
- **JSON Export** — SIEM-ready output

## Requirements

Python 3.7+ (no external dependencies)

## Usage

```bash
# Basic analysis with formatted report
python email_verify.py email.eml

# JSON output to stdout
python email_verify.py email.eml --json

# Save JSON report to file
python email_verify.py email.eml --json --output report.json

# Disable colors (for piping/logging)
python email_verify.py email.eml --no-color
```

## Output Example

```
══════════════════════════════════════════════════════════════════════════
  EMAIL FORENSIC ANALYSIS REPORT
══════════════════════════════════════════════════════════════════════════

┌──────────────────────────────────────────────────────────────────────────┐
│  RISK ASSESSMENT                                                         │
└──────────────────────────────────────────────────────────────────────────┘
  Severity: [MEDIUM]  Score: 38/100
  Factors:
    • From/Return-Path domain mismatch
    • 6 high-risk URLs

┌──────────────────────────────────────────────────────────────────────────┐
│  AUTHENTICATION (SPF/DKIM/DMARC)                                         │
└──────────────────────────────────────────────────────────────────────────┘
  SPF:   PASS
  DKIM:  PASS (domain: example.com)
  DMARC: PASS (policy: quarantine)
```

## Risk Score Factors

| Factor | Points |
|--------|--------|
| SPF failure | +20 |
| DKIM failure | +25 |
| DMARC failure | +25 |
| Missing authentication | +15 |
| Domain mismatches | +5-10 |
| High-risk URLs | +5 each (max 20) |
| Dangerous attachments | +30 |
| Phishing keywords | +3 each (max 15) |

## Supported Input

- `.eml` files (standard email format)
- Raw email headers (text files)
- Full email messages with body

## License

MIT

