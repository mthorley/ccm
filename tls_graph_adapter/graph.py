from __future__ import annotations

import hashlib
import os
from typing import Any


def _text(attributes: dict[str, Any], key: str, default: str = "") -> str:
    value = attributes.get(key, default)
    return str(value) if value is not None else default


def _number(attributes: dict[str, Any], key: str) -> float | None:
    value = attributes.get(key)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


class Neo4jGraph:
    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j") -> None:
        from neo4j import GraphDatabase

        self.database = database
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self.driver.close()


    def write_event(self, attributes: dict[str, Any], scan_started_at_ms: int | None = None) -> None:
        scan_id = _text(attributes, "tls.scan.id")
        endpoint = _text(attributes, "tls.endpoint")
        if not scan_id or not endpoint:
            return
        scanner = _text(attributes, "tls.scanner.name")
        outcome = _text(attributes, "tls.outcome")
        policy_id = _text(attributes, "tls.policy.id")
        subject = _text(attributes, "tls.certificate.subject")
        issuer = _text(attributes, "tls.certificate.issuer")
        expires_at = _text(attributes, "tls.certificate.expires_at")
        certificate_id = hashlib.sha256(f"{endpoint}|{subject}|{issuer}|{expires_at}".encode()).hexdigest()
        with self.driver.session(database=self.database) as session:
            session.execute_write(
                self._write_event,
                scan_id,
                endpoint,
                scanner,
                outcome,
                policy_id,
                certificate_id,
                subject,
                issuer,
                expires_at,
                _text(attributes, "tls.version"),
                _text(attributes, "tls.cipher"),
                _number(attributes, "tls.check.duration_seconds"),
                scan_started_at_ms,
            )

    def write_run(self, run: dict[str, Any]) -> None:
        with self.driver.session(database=self.database) as session:
            session.execute_write(self._write_run, run)

    @staticmethod
    def _write_run(tx: Any, run: dict[str, Any]) -> None:
        tx.run(
            """
            MERGE (scan:ScanRun {id: $scan_id})
            SET scan.scanner = $scanner, scan.outcome = $outcome, scan.endpointCount = $endpoint_count,
                scan.durationSeconds = $duration_seconds,
                scan.startedAt = datetime({epochMillis: $started_at_ms}),
                scan.finishedAt = datetime({epochMillis: $finished_at_ms})
            """,
            **run,
        )

    @staticmethod
    def _write_event(
        tx: Any,
        scan_id: str,
        endpoint: str,
        scanner: str,
        outcome: str,
        policy_id: str,
        certificate_id: str,
        subject: str,
        issuer: str,
        expires_at: str,
        tls_version: str,
        cipher: str,
        duration_seconds: float | None,
        scan_started_at_ms: int | None,
    ) -> None:
        tx.run(
            """
            MERGE (run:ScanRun {id: $scan_id})
            SET run.scanner = $scanner, run.lastOutcome = $outcome
            MERGE (endpoint:Endpoint {fqdn: $endpoint})
            MERGE (run)-[checked:CHECKED]->(endpoint)
            SET checked.durationSeconds = $duration_seconds,
                checked.scanStartedAt = CASE WHEN $scan_started_at_ms IS NULL THEN datetime()
                                             ELSE datetime({epochMillis: $scan_started_at_ms}) END
            SET endpoint.lastOutcome = $outcome, endpoint.tlsVersion = $tls_version,
                endpoint.cipher = $cipher, endpoint.lastCheckedAt = checked.scanStartedAt,
                endpoint.lastCheckDurationSeconds = $duration_seconds,
                endpoint.lastScanId = $scan_id, endpoint.lastPolicyId = $policy_id
            MERGE (certificate:Certificate {id: $certificate_id})
            SET certificate.subject = $subject, certificate.issuer = $issuer,
                certificate.expiresAt = $expires_at
            MERGE (endpoint)-[:PRESENTED]->(certificate)
            """,
            scan_id=scan_id,
            scanner=scanner,
            outcome=outcome,
            endpoint=endpoint,
            policy_id=policy_id,
            tls_version=tls_version,
            cipher=cipher,
            duration_seconds=duration_seconds,
            scan_started_at_ms=scan_started_at_ms,
            certificate_id=certificate_id,
            subject=subject,
            issuer=issuer,
            expires_at=expires_at,
        )
        if policy_id:
            tx.run(
                """
                MATCH (endpoint:Endpoint {fqdn: $endpoint})
                MERGE (policy:Policy {id: $policy_id})
                MERGE (endpoint)-[evaluation:EVALUATED_BY {scanId: $scan_id}]->(policy)
                SET evaluation.outcome = $outcome
                MERGE (policy)-[:PRODUCED {scanId: $scan_id}]->(:Outcome {name: $outcome})
                """,
                endpoint=endpoint,
                policy_id=policy_id,
                scan_id=scan_id,
                outcome=outcome,
            )


def graph_from_environment() -> Neo4jGraph:
    uri = os.environ["NEO4J_URI"]
    return Neo4jGraph(
        uri,
        os.getenv("NEO4J_USER", "neo4j"),
        os.environ["NEO4J_PASSWORD"],
        os.getenv("NEO4J_DATABASE", "neo4j"),
    )