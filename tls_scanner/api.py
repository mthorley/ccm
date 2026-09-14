from __future__ import annotations

import os
import logging

from fastapi import FastAPI, HTTPException
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from fastapi.responses import Response

from .config import load_config
from .main import run_scan


logger = logging.getLogger(__name__)
app = FastAPI(title="TLS Scanner", version="0.1.0")


def _config():
    endpoints_path = os.getenv("TLS_SCANNER_ENDPOINTS_CONFIG", "/etc/tls-checker/endpoints/endpoints.yaml")
    policies_path = os.getenv("TLS_SCANNER_POLICIES_CONFIG", "/etc/tls-checker/policies/policies.yaml")
    return load_config(endpoints_path, policies_path)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/scan")
def scan() -> dict:
    try:
        outcome, results, duration_seconds = run_scan(_config())
    except Exception as exc:
        logger.exception("Immediate TLS scan failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"outcome": outcome, "duration_seconds": duration_seconds, "results": results}