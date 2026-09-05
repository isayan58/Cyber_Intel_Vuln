"""MITRE ATT&CK STIX 2.1 (design doc D10/D11).

Stored relationally first, exactly as the design doc's scope-reduction advice
says — Neo4j is deferred until the core workflow is stable. ``attack_object``
plus ``attack_relationship`` is enough to answer tactic -> technique ->
mitigation questions with recursive SQL.

CVE -> technique links are *derived*, never asserted by the feed: ATT&CK does
not publish them. ``build_cwe_bridge`` produces candidate mappings with an
explicit basis and confidence so the critic can downgrade weak ones.
"""

from __future__ import annotations

import json
from typing import Any

from vulnintel.ingest.base import IngestResult, Pipeline, utcnow
from vulnintel.ingest.http import FeedClient
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
)

DEFAULT_DOMAINS = ("enterprise-attack",)

_OBJECT_TYPES = {
    "attack-pattern",
    "course-of-action",
    "intrusion-set",
    "malware",
    "tool",
    "x-mitre-tactic",
    "x-mitre-data-source",
}

# Coarse CWE -> technique bridge. Deliberately small and conservative: each
# entry is a defensible relationship, and everything it produces is written
# with confidence < 1.0 and a stated basis so it can be challenged.
CWE_TECHNIQUE_BRIDGE: dict[str, list[tuple[str, float, str]]] = {
    "CWE-89": [("T1190", 0.7, "SQL injection is a public-facing app exploit")],
    "CWE-79": [("T1189", 0.6, "XSS commonly delivered via drive-by compromise")],
    "CWE-78": [("T1190", 0.7, "OS command injection in exposed services")],
    "CWE-77": [("T1190", 0.65, "Command injection in exposed services")],
    "CWE-94": [("T1190", 0.7, "Code injection in public-facing applications")],
    "CWE-502": [("T1190", 0.7, "Deserialization RCE in exposed services")],
    "CWE-22": [("T1190", 0.6, "Path traversal against public-facing apps")],
    "CWE-287": [("T1078", 0.7, "Authentication bypass yields valid accounts")],
    "CWE-798": [("T1078", 0.8, "Hard-coded credentials are valid accounts")],
    "CWE-306": [("T1078", 0.65, "Missing authentication for critical function")],
    "CWE-269": [("T1068", 0.75, "Improper privilege management")],
    "CWE-250": [("T1068", 0.7, "Execution with unnecessary privileges")],
    "CWE-416": [("T1068", 0.6, "Use-after-free commonly used for privilege escalation")],
    "CWE-787": [("T1203", 0.65, "Out-of-bounds write drives client execution")],
    "CWE-120": [("T1203", 0.6, "Buffer overflow drives client execution")],
    "CWE-611": [("T1190", 0.6, "XXE against public-facing applications")],
    "CWE-918": [("T1190", 0.6, "SSRF against public-facing applications")],
}


class AttackPipeline(Pipeline):
    source = "attack"

    def fetch(self, *, domains: tuple[str, ...] = DEFAULT_DOMAINS, **kwargs: Any) -> IngestResult:
        run_id = self.start_run(notes={"domains": list(domains)})
        total = 0
        partition = self.today_partition("release")

        try:
            with FeedClient() as client:
                for domain in domains:
                    url = ATTACK_URL.format(domain=domain)
                    payload = client.get_bytes(url)
                    bundle = json.loads(payload)
                    objects = bundle.get("objects", [])
                    self.bronze.write(
                        self.source,
                        partition,
                        f"{domain}.json",
                        payload,
                        source_url=url,
                        record_count=len(objects),
                        run_id=run_id,
                        extra={"domain": domain, "spec_version": bundle.get("spec_version")},
                    )
                    total += len(objects)
                    log.info("ATT&CK: %s — %d STIX objects", domain, len(objects))
        except Exception as exc:
            self.finish_run(run_id, status="failed", error=str(exc))
            raise

        self.finish_run(run_id, rows_in=total)
        return IngestResult(self.source, run_id, partition, rows_in=total)

    def transform(self, partition: str | None = None, **kwargs: Any) -> IngestResult:
        partition = self.resolve_partition(partition)
        bundles = self.bronze.files_in(self.source, partition, suffix=".json.gz")
        bundles += self.bronze.files_in(self.source, partition, suffix=".json")
        if not bundles:
            raise FileNotFoundError(f"No ATT&CK bundles in bronze partition {partition}")

        run_id = self.start_run(notes={"partition": partition})
        retrieved = utcnow()

        objects: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        for path in sorted(set(bundles)):
            bundle = json.loads(self.bronze.read(self.source, partition, path.name))
            domain = path.name.replace(".json.gz", "").replace(".json", "")
            release = _release_of(bundle)

            for obj in bundle.get("objects", []):
                obj_type = obj.get("type")
                if obj_type == "relationship":
                    relationships.append(
                        {
                            "source_ref": obj.get("source_ref"),
                            "relationship_type": obj.get("relationship_type"),
                            "target_ref": obj.get("target_ref"),
                            "description": obj.get("description"),
                            "attack_release": release,
                        }
                    )
                elif obj_type in _OBJECT_TYPES:
                    objects.append(
                        {
                            "stix_id": obj.get("id"),
                            "attack_id": _attack_id(obj),
                            "object_type": obj_type,
                            "name": obj.get("name"),
                            "description": obj.get("description"),
                            "domain": domain,
                            "tactics": ",".join(
                                phase.get("phase_name", "")
                                for phase in obj.get("kill_chain_phases", []) or []
                                if phase.get("kill_chain_name") == "mitre-attack"
                            ),
                            "platforms": ",".join(obj.get("x_mitre_platforms", []) or []),
                            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                            "revoked": bool(obj.get("revoked", False)),
                            "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                            "attack_release": release,
                            "source_run_id": run_id,
                            "retrieved_at": retrieved,
                        }
                    )

        written = self.db.upsert("attack_object", objects, key_columns=("stix_id",))
        self.db.upsert(
            "attack_relationship",
            _dedupe(relationships, ("source_ref", "relationship_type", "target_ref")),
            key_columns=("source_ref", "relationship_type", "target_ref"),
        )

        self.finish_run(run_id, rows_in=len(objects), rows_out=written)
        log.info("ATT&CK: %d objects, %d relationships", len(objects), len(relationships))
        return IngestResult(self.source, run_id, partition, rows_in=len(objects), rows_out=written)

    # -- derived mappings -----------------------------------------------------

    def build_cwe_bridge(self) -> int:
        """Derive CVE -> technique candidates from CWE, with stated confidence.

        This is intentionally the only automated mapping path. Anything else
        would be the agent inventing relationships, which §7.4 of the design
        explicitly forbids.
        """
        known_techniques = {
            row["attack_id"]
            for row in self.db.query(
                "SELECT attack_id FROM attack_object "
                "WHERE object_type = 'attack-pattern' AND attack_id IS NOT NULL"
            )
        }
        if not known_techniques:
            log.warning("No ATT&CK techniques loaded; skipping CWE bridge")
            return 0

        rows: list[dict[str, Any]] = []
        for cwe_id, targets in CWE_TECHNIQUE_BRIDGE.items():
            cves = self.db.query("SELECT DISTINCT cve_id FROM cve_cwe WHERE cwe_id = ?", [cwe_id])
            for record in cves:
                for attack_id, confidence, evidence in targets:
                    if attack_id not in known_techniques:
                        continue
                    rows.append(
                        {
                            "cve_id": record["cve_id"],
                            "attack_id": attack_id,
                            "confidence": confidence,
                            "basis": "cwe-bridge",
                            "evidence": f"{cwe_id}: {evidence}",
                        }
                    )

        written = self.db.upsert(
            "attack_mapping",
            _dedupe(rows, ("cve_id", "attack_id", "basis")),
            key_columns=("cve_id", "attack_id", "basis"),
        )
        log.info("ATT&CK: derived %d CWE-bridge mappings", written)
        return written


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _release_of(bundle: dict[str, Any]) -> str | None:
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            return obj.get("x_mitre_version")
    return bundle.get("spec_version")


def _dedupe(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(row.get(k) for k in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out
