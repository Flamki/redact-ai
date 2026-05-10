"""
RedactAI — FastAPI Backend powered by Microsoft Presidio
Production-grade PII detection & redaction API
"""

import os
import json
import time
import uuid
import hashlib
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# ---- Presidio Setup ----
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Initialize engines (loads spaCy model once at startup)
print("[*] Loading NLP model & Presidio engines...")
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
print("[+] Presidio engines ready!")

# ---- FastAPI App ----
app = FastAPI(
    title="RedactAI API",
    description="AI-powered PII detection & redaction API backed by Microsoft Presidio",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- In-Memory Storage (use DB in production) ----
scan_history = []
api_keys = {
    "rda_live_sk_demo123": {"name": "Demo Key", "created": datetime.now().isoformat(), "active": True}
}

# ---- Entity color/icon mapping for frontend ----
ENTITY_META = {
    "PERSON": {"icon": "👤", "color": "#f472b6", "cssClass": "name", "label": "Person Name"},
    "EMAIL_ADDRESS": {"icon": "📧", "color": "#74c0fc", "cssClass": "email", "label": "Email"},
    "PHONE_NUMBER": {"icon": "📱", "color": "#51cf66", "cssClass": "phone", "label": "Phone"},
    "CREDIT_CARD": {"icon": "💳", "color": "#ffd43b", "cssClass": "credit-card", "label": "Credit Card"},
    "US_SSN": {"icon": "🆔", "color": "#ff6b6b", "cssClass": "gov-id", "label": "SSN"},
    "US_PASSPORT": {"icon": "🆔", "color": "#ff6b6b", "cssClass": "gov-id", "label": "Passport"},
    "US_DRIVER_LICENSE": {"icon": "🆔", "color": "#ff6b6b", "cssClass": "gov-id", "label": "Driver License"},
    "IP_ADDRESS": {"icon": "🌐", "color": "#22d3ee", "cssClass": "ip", "label": "IP Address"},
    "DATE_TIME": {"icon": "📅", "color": "#a29bfe", "cssClass": "date", "label": "Date/Time"},
    "LOCATION": {"icon": "📍", "color": "#fdcb6e", "cssClass": "location", "label": "Location"},
    "NRP": {"icon": "🏛️", "color": "#dfe6e9", "cssClass": "other", "label": "Nationality/Religion"},
    "MEDICAL_LICENSE": {"icon": "🏥", "color": "#e17055", "cssClass": "other", "label": "Medical License"},
    "URL": {"icon": "🔗", "color": "#74c0fc", "cssClass": "other", "label": "URL"},
    "IBAN_CODE": {"icon": "🏦", "color": "#ffd43b", "cssClass": "credit-card", "label": "IBAN"},
    "CRYPTO": {"icon": "₿", "color": "#f9ca24", "cssClass": "other", "label": "Crypto Wallet"},
    "UK_NHS": {"icon": "🏥", "color": "#e17055", "cssClass": "gov-id", "label": "UK NHS Number"},
    "IN_AADHAAR": {"icon": "🆔", "color": "#ff6b6b", "cssClass": "gov-id", "label": "Aadhaar"},
    "IN_PAN": {"icon": "🆔", "color": "#ff6b6b", "cssClass": "gov-id", "label": "PAN Card"},
}

# ---- Request/Response Models ----
class ScanRequest(BaseModel):
    text: str
    mode: str = "highlight"  # "highlight" or "redact"
    language: str = "en"
    entities: Optional[list] = None  # specific entities to detect, or None for all
    score_threshold: float = 0.35

class ScanResponse(BaseModel):
    original: str
    redacted: str
    entities: list
    entity_summary: dict
    count: int
    processing_ms: float

class BatchScanRequest(BaseModel):
    texts: list[str]
    mode: str = "redact"
    language: str = "en"

# ---- API Endpoints ----

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "engine": "presidio", "version": "1.0.0"}


@app.post("/api/v1/scan", response_model=ScanResponse)
def scan_text(req: ScanRequest):
    """Scan text for PII and return detected entities + redacted text"""
    start = time.time()
    
    # Analyze with Presidio
    results = analyzer.analyze(
        text=req.text,
        language=req.language,
        entities=req.entities,
        score_threshold=req.score_threshold,
    )
    
    # Build entity list with metadata
    entities = []
    for r in sorted(results, key=lambda x: x.start):
        meta = ENTITY_META.get(r.entity_type, {"icon": "❓", "color": "#dfe6e9", "cssClass": "other", "label": r.entity_type})
        entities.append({
            "type": r.entity_type,
            "label": meta["label"],
            "text": req.text[r.start:r.end],
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 3),
            "icon": meta["icon"],
            "color": meta["color"],
            "cssClass": meta["cssClass"],
        })
    
    # Anonymize/redact
    anonymized = anonymizer.anonymize(
        text=req.text,
        analyzer_results=results,
        operators={
            "DEFAULT": OperatorConfig("replace", {"new_value": "[REDACTED]"}),
            "PERSON": OperatorConfig("replace", {"new_value": "[NAME]"}),
            "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "[EMAIL]"}),
            "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "[PHONE]"}),
            "CREDIT_CARD": OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"}),
            "US_SSN": OperatorConfig("replace", {"new_value": "[SSN]"}),
            "IP_ADDRESS": OperatorConfig("replace", {"new_value": "[IP_ADDRESS]"}),
            "DATE_TIME": OperatorConfig("replace", {"new_value": "[DATE]"}),
            "LOCATION": OperatorConfig("replace", {"new_value": "[LOCATION]"}),
            "URL": OperatorConfig("replace", {"new_value": "[URL]"}),
            "IN_AADHAAR": OperatorConfig("replace", {"new_value": "[AADHAAR]"}),
            "IN_PAN": OperatorConfig("replace", {"new_value": "[PAN]"}),
        }
    )
    
    # Build entity summary
    summary = {}
    for e in entities:
        t = e["label"]
        if t not in summary:
            summary[t] = {"count": 0, "icon": e["icon"], "cssClass": e["cssClass"]}
        summary[t]["count"] += 1
    
    elapsed_ms = round((time.time() - start) * 1000, 2)
    
    # Store in history
    scan_history.append({
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().isoformat(),
        "source": "Text Input",
        "entity_count": len(entities),
        "types": list(summary.keys()),
        "processing_ms": elapsed_ms,
        "preview": req.text[:80] + ("..." if len(req.text) > 80 else ""),
    })
    
    return ScanResponse(
        original=req.text,
        redacted=anonymized.text,
        entities=entities,
        entity_summary=summary,
        count=len(entities),
        processing_ms=elapsed_ms,
    )


@app.post("/api/v1/scan/batch")
def scan_batch(req: BatchScanRequest):
    """Scan multiple texts at once"""
    results = []
    total_start = time.time()
    
    for text in req.texts:
        analysis = analyzer.analyze(text=text, language=req.language)
        anonymized = anonymizer.anonymize(text=text, analyzer_results=analysis)
        
        entities = []
        for r in analysis:
            meta = ENTITY_META.get(r.entity_type, {"icon": "❓", "label": r.entity_type})
            entities.append({
                "type": r.entity_type,
                "label": meta["label"],
                "text": text[r.start:r.end],
                "score": round(r.score, 3),
            })
        
        results.append({
            "original": text,
            "redacted": anonymized.text,
            "entity_count": len(entities),
            "entities": entities,
        })
    
    return {
        "results": results,
        "total_texts": len(req.texts),
        "total_entities": sum(r["entity_count"] for r in results),
        "processing_ms": round((time.time() - total_start) * 1000, 2),
    }


@app.post("/api/v1/scan/file")
async def scan_file(file: UploadFile = File(...)):
    """Upload and scan a file for PII"""
    if not file.filename:
        raise HTTPException(400, "No file provided")
    
    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("txt", "csv", "json"):
        raise HTTPException(400, f"Unsupported file type: .{ext}. Use .txt, .csv, or .json")
    
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    
    start = time.time()
    
    # For CSV/JSON, scan each cell/value
    if ext == "csv":
        import csv
        import io
        reader = csv.reader(io.StringIO(text))
        all_text = " ".join(" ".join(row) for row in reader)
    elif ext == "json":
        try:
            data = json.loads(text)
            all_text = json.dumps(data) if isinstance(data, (dict, list)) else text
        except json.JSONDecodeError:
            all_text = text
    else:
        all_text = text
    
    # Analyze
    results = analyzer.analyze(text=all_text, language="en")
    anonymized = anonymizer.anonymize(text=all_text, analyzer_results=results)
    
    entities = []
    for r in sorted(results, key=lambda x: x.start):
        meta = ENTITY_META.get(r.entity_type, {"icon": "❓", "label": r.entity_type})
        entities.append({
            "type": r.entity_type,
            "label": meta["label"],
            "text": all_text[r.start:r.end],
            "score": round(r.score, 3),
        })
    
    elapsed_ms = round((time.time() - start) * 1000, 2)
    
    # Store in history
    scan_history.append({
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().isoformat(),
        "source": f"File: {file.filename}",
        "entity_count": len(entities),
        "types": list(set(e["label"] for e in entities)),
        "processing_ms": elapsed_ms,
        "preview": all_text[:80] + "...",
    })
    
    return {
        "filename": file.filename,
        "file_size": len(content),
        "redacted_text": anonymized.text,
        "entities": entities,
        "entity_count": len(entities),
        "processing_ms": elapsed_ms,
    }


@app.get("/api/v1/history")
def get_history(page: int = 1, per_page: int = 10):
    """Get scan history with pagination"""
    total = len(scan_history)
    start = (page - 1) * per_page
    items = list(reversed(scan_history))[start:start + per_page]
    return {
        "items": items,
        "total": total,
        "page": page,
        "pages": max(1, (total + per_page - 1) // per_page),
    }


@app.get("/api/v1/stats")
def get_stats():
    """Get overview statistics"""
    total_scans = len(scan_history)
    total_entities = sum(h["entity_count"] for h in scan_history)
    avg_ms = round(sum(h["processing_ms"] for h in scan_history) / max(1, total_scans), 2)
    
    # Type breakdown
    type_counts = {}
    for h in scan_history:
        for t in h.get("types", []):
            type_counts[t] = type_counts.get(t, 0) + 1
    
    return {
        "total_scans": total_scans,
        "total_entities": total_entities,
        "avg_response_ms": avg_ms,
        "entity_type_breakdown": type_counts,
    }


@app.get("/api/v1/supported-entities")
def get_supported_entities():
    """List all PII entity types the engine can detect"""
    supported = analyzer.get_supported_entities()
    entities = []
    for entity_type in sorted(supported):
        meta = ENTITY_META.get(entity_type, {"icon": "❓", "color": "#dfe6e9", "label": entity_type})
        entities.append({
            "type": entity_type,
            "label": meta["label"],
            "icon": meta["icon"],
            "color": meta["color"],
        })
    return {"entities": entities, "count": len(entities)}


# ---- Serve Frontend Static Files ----
# Serve static files from the current directory
app.mount("/static", StaticFiles(directory="."), name="static")

@app.get("/")
def serve_index():
    return FileResponse("index.html")

@app.get("/dashboard")
@app.get("/dashboard.html")
def serve_dashboard():
    return FileResponse("dashboard.html")

# Catch-all for CSS/JS files
@app.get("/{filename}")
def serve_file(filename: str):
    filepath = os.path.join(".", filename)
    if os.path.isfile(filepath):
        return FileResponse(filepath)
    raise HTTPException(404, "Not found")


if __name__ == "__main__":
    import uvicorn
    print("\n[*] RedactAI API Server starting...")
    print("[>] Dashboard: http://127.0.0.1:8000/dashboard")
    print("[>] API Docs:  http://127.0.0.1:8000/docs")
    print("[>] Landing:   http://127.0.0.1:8000/\n")
    uvicorn.run(app, host="127.0.0.1", port=8000)
