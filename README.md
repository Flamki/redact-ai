# RedactAI — AI-Powered PII Detection & Redaction

🛡️ **Detect and redact sensitive data instantly.** Built with Microsoft Presidio, FastAPI, and a premium dark-mode dashboard.

## Features
- **50+ PII entity types** detected via NLP + regex + ML
- **Real-time scanning** — paste text, upload files, or use the API
- **Multiple modes** — highlight, redact, mask, or hash sensitive data
- **Full dashboard** — analytics, scan history, file upload, API key management
- **REST API** with auto-generated Swagger docs
- **Zero data stored** — nothing is saved to disk

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Run the server
python server.py
```

Then open http://127.0.0.1:8000

## Docker

```bash
docker build -t redactai .
docker run -p 8000:8000 redactai
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/scan` | Scan text for PII |
| POST | `/api/v1/scan/batch` | Batch scan multiple texts |
| POST | `/api/v1/scan/file` | Upload and scan a file |
| GET | `/api/v1/history` | Get scan history |
| GET | `/api/v1/stats` | Get analytics |
| GET | `/api/v1/supported-entities` | List detectable entity types |

## Tech Stack
- **Backend:** FastAPI + Microsoft Presidio + spaCy
- **Frontend:** Vanilla HTML/CSS/JS (dark-mode glassmorphism)
- **NLP Model:** en_core_web_lg (spaCy)
- **License:** MIT

## Compliance
Supports GDPR, HIPAA, PCI DSS, DPDP Act, CCPA, SOC 2 compliance workflows.
