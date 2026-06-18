from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware

from .cleanup import (
    UPLOAD_RETENTION_SECONDS,
    ensure_upload_dir,
    purge_stale_uploads,
    schedule_file_deletion,
)
from .parser import analyze_pcap


BASE_DIR = Path(__file__).resolve().parents[1]
UPLOAD_DIR = BASE_DIR / "tmp_uploads"
ALLOWED_SUFFIXES = {".pcap", ".pcapng"}


app = FastAPI(
    title="FortiGate IPsec PCAP Analyzer",
    version="0.1.0",
    description="Upload pcap/pcapng files and receive FortiGate-focused IKE/ESP diagnostics.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event() -> None:
    ensure_upload_dir(UPLOAD_DIR)
    purge_stale_uploads(UPLOAD_DIR, retention_seconds=UPLOAD_RETENTION_SECONDS)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze_capture(
    file: UploadFile = File(...),
    anonymize: bool = Form(False),
    psk: str | None = Form(None),
) -> dict:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail="Only .pcap or .pcapng files are supported")

    ensure_upload_dir(UPLOAD_DIR)
    file_id = uuid.uuid4().hex
    stored_path = UPLOAD_DIR / f"{file_id}{suffix}"

    try:
        content = await file.read()
        await run_in_threadpool(stored_path.write_bytes, content)

        report = await run_in_threadpool(
            analyze_pcap,
            str(stored_path),
            anonymize,
            psk,
        )

        report["upload"] = {
            "retention_seconds": UPLOAD_RETENTION_SECONDS,
            "auto_delete_scheduled": True,
        }
        return report
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc
    finally:
        schedule_file_deletion(stored_path, delay_seconds=UPLOAD_RETENTION_SECONDS)
        await file.close()
