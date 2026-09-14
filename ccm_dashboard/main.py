from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse


app = FastAPI(title="TLS Dashboard", version="0.1.0")
app.add_middleware(GZipMiddleware, minimum_size=1000)  # the SP 800-53 tree is ~400 KB raw; ~40 KB gzipped
driver = None


DASHBOARD_FILE = Path(__file__).with_name("dashboard.html")
ASSETS = {
    "/dashboard.css": (Path(__file__).with_name("dashboard.css"), "text/css"),
    "/sunburst.js": (Path(__file__).with_name("sunburst.js"), "text/javascript"),
    "/sunburst-zoom.js": (Path(__file__).with_name("sunburst-zoom.js"), "text/javascript"),
}
# Content hash of the static assets; appended as ?v= so browsers never pair a new page with a cached old stylesheet.
ASSET_VERSION = hashlib.sha256(b"".join(path.read_bytes() for path, _ in ASSETS.values())).hexdigest()[:12]
ASSET_CACHE_CONTROL = "public, max-age=31536000, immutable"  # safe: the URL changes whenever the content does
FRAMEWORK_CACHE_SECONDS = int(os.getenv("DASHBOARD_FRAMEWORK_CACHE_SECONDS", "600"))


class _TtlCache:
    """Small in-process cache for the framework tree queries, which only change when the catalog is re-ingested."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str, ttl: float, compute: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._lock:
            hit = self._entries.get(key)
            if hit and now - hit[0] < ttl:
                return hit[1]
        value = compute()
        with self._lock:
            self._entries[key] = (now, value)
        return value

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


framework_cache = _TtlCache()


def graph_driver():
    global driver
    if driver is None:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(os.environ["NEO4J_URI"], auth=(os.getenv("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
    return driver


def _value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "to_native"):  # neo4j temporal types -> ISO 8601
        return value.to_native().isoformat()
    return str(value)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.on_event("startup")
def warm_caches() -> None:
    """Open the Neo4j connection and prime the framework caches in the background, so the first
    visitor after a pod restart doesn't pay the cold-start cost (which on a small pod can exceed the gateway timeout)."""
    def warm() -> None:
        for query, key in ((CSF_TREE_QUERY, "csf"), (SP800_53_TREE_QUERY, "sp800-53")):
            try:
                _framework_rows(query, key, refresh=False)
            except Exception:  # noqa: BLE001 - warming is best-effort; requests will retry on demand
                return
    if os.getenv("NEO4J_URI"):
        threading.Thread(target=warm, name="warm-framework-caches", daemon=True).start()


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)  # kept for existing links
def dashboard() -> HTMLResponse:
    html = DASHBOARD_FILE.read_text(encoding="utf-8")
    for route in ASSETS:
        html = html.replace(f'"{route}"', f'"{route}?v={ASSET_VERSION}"')
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})  # always revalidate the page itself


def _asset(route: str) -> FileResponse:
    path, media_type = ASSETS[route]
    return FileResponse(path, media_type=media_type, headers={"Cache-Control": ASSET_CACHE_CONTROL})


@app.get("/dashboard.css")
def dashboard_css() -> FileResponse:
    return _asset("/dashboard.css")


@app.get("/sunburst.js")
def sunburst_js() -> FileResponse:
    return _asset("/sunburst.js")


@app.get("/sunburst-zoom.js")
def sunburst_zoom_js() -> FileResponse:
    return _asset("/sunburst-zoom.js")


CSF_TREE_QUERY = """
MATCH (v:FrameworkVersion {framework: 'nist-csf'})-[:CONTAINS]->(f:CsfFunction)-[:CONTAINS]->(c:CsfCategory)-[:CONTAINS]->(s:CsfSubcategory)
WITH v, f, c, s ORDER BY f.order, c.order, s.order
OPTIONAL MATCH (s)-[:REFERENCES]->(base:Control)
OPTIONAL MATCH (base)-[:CONTAINS*0..1]->(ctl:Control)<-[:SUPPORTS]-(p:Policy)
WITH v, f, c, s, collect(DISTINCT base.id) AS controls, collect(DISTINCT {id: p.id, name: p.name, control: ctl.id}) AS policies
RETURN v.version AS version, f.id AS function_id, f.title AS function_title, f.description AS function_description,
       c.id AS category_id, c.title AS category_title, c.description AS category_description,
       s.id AS subcategory_id, s.statement AS statement, controls,
       [x IN policies WHERE x.id IS NOT NULL] AS policies
"""

# Current state per endpoint: the adapter stamps lastPolicyId with the policy that produced lastOutcome.
CSF_EVIDENCE_QUERY = """
MATCH (e:Endpoint)
RETURN e.fqdn AS endpoint, e.lastOutcome AS outcome, e.lastPolicyId AS policy_id, e.lastCheckedAt AS checked_at
ORDER BY e.fqdn
"""

OUTCOME_RANK = {"fail": 3, "warn": 2, "pass": 1}


def _policy_status(policy_id: str, endpoints: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Worst current outcome among endpoints whose outcome was produced by this policy; pass if none were."""
    hits = [row for row in endpoints if row["policy_id"] == policy_id and row["outcome"] in OUTCOME_RANK]
    if not endpoints:
        return "unknown", []
    if not hits:
        return "pass", []
    return max((row["outcome"] for row in hits), key=OUTCOME_RANK.__getitem__), hits


def build_csf_tree(rows: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble function -> category -> subcategory with a status per subcategory from current endpoint state."""
    functions: dict[str, dict[str, Any]] = {}
    for row in rows:
        function = functions.setdefault(row["function_id"], {
            "id": row["function_id"], "title": row["function_title"], "description": row["function_description"], "categories": {},
        })
        category = function["categories"].setdefault(row["category_id"], {
            "id": row["category_id"], "title": row["category_title"], "description": row["category_description"], "subcategories": [],
        })
        policies = []
        status = "unmapped"
        for policy in {p["id"]: p for p in row["policies"]}.values():
            policy_status, hits = _policy_status(policy["id"], endpoints)
            policies.append({**policy, "status": policy_status, "endpoints": hits})
            if OUTCOME_RANK.get(policy_status, 0) > OUTCOME_RANK.get(status, 0):
                status = policy_status
        if policies and status == "unmapped":
            status = "unknown"
        category["subcategories"].append({
            "id": row["subcategory_id"], "statement": row["statement"], "controls": sorted(row["controls"]),
            "policies": sorted(policies, key=lambda p: p["id"]), "status": status,
        })
    tree = [{**f, "categories": list(f["categories"].values())} for f in functions.values()]
    subcategories = [s for f in tree for c in f["categories"] for s in c["subcategories"]]
    return {
        "version": rows[0]["version"] if rows else None,
        "functions": tree,
        "endpoints": endpoints,
        "summary": {
            "subcategories": len(subcategories),
            **{status: sum(1 for s in subcategories if s["status"] == status) for status in ("pass", "warn", "fail", "unknown", "unmapped")},
        },
    }


SP800_53_TREE_QUERY = """
MATCH (v:FrameworkVersion {framework: 'nist-sp-800-53'})-[:CONTAINS]->(f:ControlFamily)-[:CONTAINS]->(c:Control)
WHERE coalesce(c.status, '') <> 'withdrawn'
OPTIONAL MATCH (c)-[:CONTAINS]->(e:Control) WHERE coalesce(e.status, '') <> 'withdrawn'
OPTIONAL MATCH (c)<-[:SUPPORTS]-(p:Policy)
OPTIONAL MATCH (c)<-[:REFERENCES]-(s:CsfSubcategory)
WITH v, f, c, e, collect(DISTINCT {id: p.id, name: p.name, control: c.id}) AS policies, collect(DISTINCT s.id) AS csf
ORDER BY f.order, c.order, e.order
OPTIONAL MATCH (e)<-[:SUPPORTS]-(ep:Policy)
WITH v, f, c, policies, csf, e, collect(DISTINCT {id: ep.id, name: ep.name, control: e.id}) AS enhancement_policies
WITH v, f, c, policies, csf,
     collect(CASE WHEN e IS NULL THEN NULL ELSE {id: e.id, title: e.title, statement: e.statement,
             policies: [x IN enhancement_policies WHERE x.id IS NOT NULL]} END) AS enhancements
RETURN v.version AS version, f.id AS family_id, f.title AS family_title,
       c.id AS control_id, c.title AS control_title, c.statement AS statement, c.implementationLevel AS implementation_level,
       [x IN policies WHERE x.id IS NOT NULL] AS policies, csf, [x IN enhancements WHERE x IS NOT NULL] AS enhancements
"""


def _with_status(policies: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    """Attach a status to each policy and return the worst; 'unmapped' when there are no policies."""
    status = "unmapped"
    out = []
    for policy in {p["id"]: p for p in policies}.values():
        policy_status, hits = _policy_status(policy["id"], endpoints)
        out.append({**policy, "status": policy_status, "endpoints": hits})
        if OUTCOME_RANK.get(policy_status, 0) > OUTCOME_RANK.get(status, 0):
            status = policy_status
    if out and status == "unmapped":
        status = "unknown"
    return sorted(out, key=lambda p: p["id"]), status


def _worst(statuses: list[str]) -> str:
    ranked = [s for s in statuses if s in OUTCOME_RANK]
    if ranked:
        return max(ranked, key=OUTCOME_RANK.__getitem__)
    return "unknown" if "unknown" in statuses else "unmapped"


def _summary(nodes: list[dict[str, Any]], key: str) -> dict[str, int]:
    return {key: len(nodes), **{status: sum(1 for n in nodes if n["status"] == status) for status in ("pass", "warn", "fail", "unknown", "unmapped")}}


def build_sp800_53_tree(rows: list[dict[str, Any]], endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble family -> control (-> enhancement) with a status per node; a control's status rolls up its enhancements."""
    families: dict[str, dict[str, Any]] = {}
    for row in rows:
        family = families.setdefault(row["family_id"], {"id": row["family_id"], "title": row["family_title"], "controls": []})
        enhancements = []
        for enhancement in row["enhancements"]:
            policies, status = _with_status(enhancement["policies"], endpoints)
            enhancements.append({**enhancement, "policies": policies, "status": status})
        policies, own_status = _with_status(row["policies"], endpoints)
        status = _worst([own_status] + [e["status"] for e in enhancements])
        family["controls"].append({
            "id": row["control_id"], "title": row["control_title"], "statement": row["statement"],
            "implementation_level": row["implementation_level"], "csf": sorted(row["csf"]),
            "policies": policies, "enhancements": enhancements, "status": status,
            "evidenced": bool(policies) or any(e["policies"] for e in enhancements),
        })
    tree = list(families.values())
    controls = [c for f in tree for c in f["controls"]]
    return {
        "version": rows[0]["version"] if rows else None,
        "families": tree,
        "endpoints": endpoints,
        "summary": {**_summary(controls, "controls"), "enhancements": sum(len(c["enhancements"]) for c in controls)},
    }


def _framework_rows(query: str, cache_key: str, refresh: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Cached catalog rows (they change only on ingest) plus the always-fresh endpoint state."""
    def fetch_rows() -> list[dict[str, Any]]:
        with graph_driver().session(database=os.getenv("NEO4J_DATABASE", "neo4j")) as session:
            return [{key: _value(value) if not isinstance(value, list) else value for key, value in record.items()} for record in session.run(query)]

    try:
        if refresh:
            framework_cache.clear()
        rows = framework_cache.get(cache_key, FRAMEWORK_CACHE_SECONDS, fetch_rows)
        with graph_driver().session(database=os.getenv("NEO4J_DATABASE", "neo4j")) as session:
            endpoints = [{key: _value(value) for key, value in record.items()} for record in session.run(CSF_EVIDENCE_QUERY)]
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Neo4j query failed") from exc
    return rows, endpoints


@app.get("/api/sp800-53")
def sp800_53(refresh: bool = False) -> dict[str, Any]:
    """NIST SP 800-53 families -> controls -> enhancements with TLS policy evidence per control."""
    rows, endpoints = _framework_rows(SP800_53_TREE_QUERY, "sp800-53", refresh)
    return build_sp800_53_tree(rows, endpoints)


@app.get("/api/csf")
def csf(refresh: bool = False) -> dict[str, Any]:
    """NIST CSF 2.0 tree with per-subcategory coverage derived from Policy -> Control <- REFERENCES."""
    rows, endpoints = _framework_rows(CSF_TREE_QUERY, "csf", refresh)
    return build_csf_tree(rows, endpoints)


RESULTS_QUERY = """
// One row per endpoint: its current state, attributed to the scan run that produced it.
MATCH (endpoint:Endpoint)
WHERE ($outcome = '' OR endpoint.lastOutcome = $outcome)
OPTIONAL MATCH (run:ScanRun {id: endpoint.lastScanId})
OPTIONAL MATCH (endpoint)-[:EVALUATED_BY {scanId: endpoint.lastScanId}]->(policy:Policy)
OPTIONAL MATCH (endpoint)-[:PRESENTED]->(certificate:Certificate)
// an endpoint can have presented several certificates over time (rotation, CDN edges); show the latest-expiring one
WITH endpoint, run, policy, certificate ORDER BY certificate.expiresAt DESC
WITH endpoint, run, policy, collect(certificate)[0] AS certificate
WHERE ($scanner = '' OR run.scanner = $scanner)
RETURN run.id AS scan_id, run.scanner AS scanner, endpoint.fqdn AS endpoint,
       endpoint.lastOutcome AS outcome, endpoint.tlsVersion AS tls_version, endpoint.cipher AS cipher,
       endpoint.lastCheckedAt AS checked_at, endpoint.lastCheckDurationSeconds AS duration_seconds,
       run.startedAt AS scan_started_at, run.durationSeconds AS scan_duration_seconds,
       coalesce(endpoint.lastPolicyId, policy.id) AS policy_id,
       certificate.subject AS certificate_subject, certificate.issuer AS certificate_issuer,
       certificate.expiresAt AS certificate_expires_at
ORDER BY endpoint.fqdn LIMIT $limit
"""

SCANS_QUERY = """
MATCH (run:ScanRun)
OPTIONAL MATCH (run)-[:CHECKED]->(endpoint:Endpoint)
WITH run, count(endpoint) AS endpoints
RETURN run.id AS scan_id, run.scanner AS scanner, coalesce(run.outcome, run.lastOutcome) AS outcome,
       run.startedAt AS started_at, run.finishedAt AS finished_at, run.durationSeconds AS duration_seconds, endpoints
ORDER BY run.startedAt IS NULL, run.startedAt DESC LIMIT $limit
"""


def _rows(session: Any, query: str, **params: Any) -> list[dict[str, Any]]:
    return [{key: _value(value) for key, value in record.items()} for record in session.run(query, **params)]


@app.get("/api/results")
def results(scanner: str = "", outcome: str = "", limit: int = 500) -> dict[str, list[dict[str, Any]]]:
    """Current state of every endpoint (one row each), with the scan run that produced it."""
    try:
        with graph_driver().session(database=os.getenv("NEO4J_DATABASE", "neo4j")) as session:
            return {"results": _rows(session, RESULTS_QUERY, scanner=scanner, outcome=outcome, limit=max(1, min(limit, 5000)))}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Neo4j query failed") from exc


@app.get("/api/scans")
def scans(limit: int = 50) -> dict[str, list[dict[str, Any]]]:
    """Scan run history, newest first; runs recorded before timestamps were stored sort last."""
    try:
        with graph_driver().session(database=os.getenv("NEO4J_DATABASE", "neo4j")) as session:
            return {"scans": _rows(session, SCANS_QUERY, limit=max(1, min(limit, 500)))}
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Neo4j query failed") from exc
