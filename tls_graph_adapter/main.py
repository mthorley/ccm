from __future__ import annotations

import gzip
import logging

from fastapi import FastAPI, HTTPException, Request

from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

from .graph import graph_from_environment


logger = logging.getLogger(__name__)
app = FastAPI(title="TLS Graph Adapter", version="0.1.0")
graph = None


def _value(attribute: object) -> object:
    if attribute.HasField("string_value"):
        return attribute.string_value
    if attribute.HasField("bool_value"):
        return attribute.bool_value
    if attribute.HasField("int_value"):
        return attribute.int_value
    if attribute.HasField("double_value"):
        return attribute.double_value
    return ""


def _attributes(items: object) -> dict[str, object]:
    return {item.key: _value(item.value) for item in items}


def run_from_span(span: object) -> dict[str, object] | None:
    """Summarise a ``tls.scan`` span: identity, outcome, and execution time."""
    attributes = _attributes(span.attributes)
    scan_id = attributes.get("tls.scan.id")
    if not scan_id:
        return None
    started_ms = span.start_time_unix_nano // 1_000_000
    finished_ms = span.end_time_unix_nano // 1_000_000
    duration_seconds = attributes.get("tls.scan.duration_seconds")
    if not isinstance(duration_seconds, (int, float)):
        duration_seconds = (span.end_time_unix_nano - span.start_time_unix_nano) / 1_000_000_000
    return {
        "scan_id": str(scan_id),
        "scanner": str(attributes.get("tls.scanner.name", "")),
        "outcome": str(attributes.get("tls.scan.outcome", "")),
        "endpoint_count": int(attributes.get("tls.endpoint.count") or 0),
        "duration_seconds": round(float(duration_seconds), 3),
        "started_at_ms": started_ms,
        "finished_at_ms": finished_ms,
    }


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


def decode_otlp_body(body: bytes, content_encoding: str | None) -> bytes:
    encodings = {item.strip().lower() for item in (content_encoding or "").split(",")}
    return gzip.decompress(body) if "gzip" in encodings else body


@app.post("/v1/traces")
async def traces(request: Request) -> dict[str, bool]:
    global graph
    if graph is None:
        try:
            graph = graph_from_environment()
        except Exception as exc:
            logger.exception("Unable to connect to Neo4j")
            raise HTTPException(status_code=503, detail="Neo4j is not configured") from exc
    try:
        body = await request.body()
        body = decode_otlp_body(body, request.headers.get("content-encoding"))
        payload = ExportTraceServiceRequest.FromString(body)
        for resource in payload.resource_spans:
            for scope in resource.scope_spans:
                for span in scope.spans:
                    scan_started_at_ms = span.start_time_unix_nano // 1_000_000 or None
                    for event in span.events:
                        if event.name == "tls.endpoint.result":
                            graph.write_event(_attributes(event.attributes), scan_started_at_ms)
                    run = run_from_span(span)
                    if run:
                        graph.write_run(run)
        return {"accepted": True}
    except Exception as exc:
        logger.exception("Failed to process OTLP trace payload")
        raise HTTPException(status_code=500, detail=str(exc)) from exc