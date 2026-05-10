---
title: RedactAI
emoji: 🛡️
colorFrom: purple
colorTo: blue
sdk: docker
pinned: false
license: mit
app_port: 7860
---

# RedactAI — AI-Powered PII Detection & Redaction API

Detect and redact sensitive data instantly using Microsoft Presidio + spaCy NLP.

## API Endpoints
- `POST /api/v1/scan` — Scan text for PII
- `POST /api/v1/scan/batch` — Batch scan  
- `POST /api/v1/scan/file` — Upload files
- `GET /api/v1/supported-entities` — List detectable types
- `GET /docs` — Swagger API docs
