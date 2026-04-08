"""
Entity Graph Persistence — write IOCs as entity nodes and infer edges.
Called from store.py after investigation completes.

RULES:
- Every query includes tenant_id
- All operations wrapped in try/except — NEVER crash the pipeline
- No LLM calls — all logic is deterministic
- Uses same psycopg2 pattern as store.py
"""
import hashlib
import json
from datetime import datetime


# Map IOC types from pipeline to entity_type CHECK constraint values
IOC_TYPE_MAP = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "hash_md5": "file_hash",
    "hash_sha1": "file_hash",
    "hash_sha256": "file_hash",
    "hash": "file_hash",
    "md5": "file_hash",
    "sha1": "file_hash",
    "sha256": "file_hash",
    "username": "user",
    "email": "email",
    "cve": "process",  # map CVEs to process as closest fit
    "process_name": "process",
    "process": "process",
    "device": "device",
    "user": "user",
}

# Valid entity_type values per CHECK constraint
VALID_ENTITY_TYPES = {"ip", "domain", "file_hash", "url", "user", "device", "process", "email"}


def persist_entities(conn, tenant_id: str, investigation_id: str,
                     iocs: list, risk_score: int = 0) -> dict:
    """
    UPSERT IOCs as entity nodes.
    Returns: {value: entity_uuid} mapping for edge creation.
    """
    entity_map = {}
    if not iocs or not tenant_id:
        return entity_map

    for ioc in iocs:
        try:
            if isinstance(ioc, dict):
                raw_type = ioc.get("type", ioc.get("ioc_type", ""))
                value = ioc.get("value", "")
                confidence = float(ioc.get("confidence", 0.5) if ioc.get("confidence") not in (None, "high", "medium", "low") else
                                   0.9 if ioc.get("confidence") == "high" else
                                   0.7 if ioc.get("confidence") == "medium" else 0.5)
            else:
                continue

            if not value or not raw_type:
                continue

            entity_type = IOC_TYPE_MAP.get(raw_type.lower(), raw_type.lower())
            if entity_type not in VALID_ENTITY_TYPES:
                continue

            # Compute entity_hash for dedup
            entity_hash = hashlib.sha256(f"{entity_type}:{value}".encode()).hexdigest()

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO entities (entity_hash, entity_type, value, tenant_id,
                        threat_score, observation_count, confidence, source_investigation_id, metadata)
                    VALUES (%s, %s, %s, %s, %s, 1, %s, %s, %s)
                    ON CONFLICT (entity_hash, tenant_id) DO UPDATE SET
                        last_seen = now(),
                        observation_count = entities.observation_count + 1,
                        threat_score = GREATEST(entities.threat_score, EXCLUDED.threat_score),
                        confidence = GREATEST(entities.confidence, EXCLUDED.confidence)
                    RETURNING id
                """, (
                    entity_hash, entity_type, value, tenant_id,
                    min(risk_score, 100), confidence,
                    investigation_id,
                    json.dumps({"ioc_type": raw_type}),
                ))
                row = cur.fetchone()
                if row:
                    entity_map[value] = str(row[0])
        except Exception as e:
            print(f"Entity persist failed for {ioc} (non-fatal): {e}")

    return entity_map


def persist_edges(conn, tenant_id: str, investigation_id: str,
                  relationships: list, entity_map: dict) -> int:
    """
    UPSERT edges between entities.
    Returns: count of edges written.
    """
    count = 0
    if not relationships or not entity_map:
        return count

    for rel in relationships:
        try:
            source_value = rel.get("source_value", "")
            target_value = rel.get("target_value", "")
            edge_type = rel.get("edge_type", "associated_with")

            source_id = entity_map.get(source_value)
            target_id = entity_map.get(target_value)
            if not source_id or not target_id or source_id == target_id:
                continue

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO entity_edges (source_entity_id, target_entity_id, edge_type,
                        investigation_id, tenant_id, confidence, metadata)
                    VALUES (%s, %s, %s, %s, %s, 0.8, %s)
                    ON CONFLICT DO NOTHING
                """, (
                    source_id, target_id, edge_type,
                    investigation_id, tenant_id,
                    json.dumps({"investigation_id": investigation_id}),
                ))
                count += 1
        except Exception as e:
            print(f"Edge persist failed (non-fatal): {e}")

    return count


def persist_cross_tenant(conn, iocs: list, risk_score: int, verdict: str) -> int:
    """
    UPSERT cross-tenant entity sightings (privacy-preserving).
    No tenant_id — shared across all tenants.
    """
    count = 0
    if not iocs:
        return count

    is_malicious = verdict in ("true_positive", "suspicious")

    for ioc in iocs:
        try:
            if not isinstance(ioc, dict):
                continue
            raw_type = ioc.get("type", ioc.get("ioc_type", ""))
            value = ioc.get("value", "")
            if not value or not raw_type:
                continue

            entity_type = IOC_TYPE_MAP.get(raw_type.lower(), raw_type.lower())
            entity_hash = hashlib.sha256(f"{entity_type}:{value}".encode()).hexdigest()

            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO cross_tenant_entities (entity_hash, entity_type,
                        avg_risk_score, malicious_count, benign_count)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (entity_hash) DO UPDATE SET
                        sighting_count = cross_tenant_entities.sighting_count + 1,
                        last_seen = now(),
                        avg_risk_score = (COALESCE(cross_tenant_entities.avg_risk_score, 0) *
                            cross_tenant_entities.sighting_count + %s) /
                            (cross_tenant_entities.sighting_count + 1),
                        malicious_count = cross_tenant_entities.malicious_count + %s,
                        benign_count = cross_tenant_entities.benign_count + %s,
                        updated_at = now()
                """, (
                    entity_hash, entity_type,
                    float(risk_score), 1 if is_malicious else 0, 0 if is_malicious else 1,
                    float(risk_score),
                    1 if is_malicious else 0,
                    0 if is_malicious else 1,
                ))
                count += 1
        except Exception as e:
            print(f"Cross-tenant persist failed (non-fatal): {e}")

    return count


# Valid edge_type values per CHECK constraint
VALID_EDGE_TYPES = {
    "communicates_with", "resolved_to", "logged_into", "executed",
    "downloaded", "contains", "parent_of", "accessed",
    "sent_to", "received_from", "associated_with",
}


def infer_relationships(iocs: list, siem_event: dict) -> list:
    """
    Infer entity relationships from SIEM event context.
    Deterministic — no LLM.
    """
    relationships = []
    if not siem_event or not isinstance(siem_event, dict):
        return relationships

    source_ip = siem_event.get("source_ip", "")
    dest_ip = siem_event.get("destination_ip", siem_event.get("dest_ip", ""))
    username = siem_event.get("username", "")
    hostname = siem_event.get("hostname", "")

    # Collect all IOC values for matching
    ioc_values = set()
    for ioc in (iocs or []):
        if isinstance(ioc, dict):
            ioc_values.add(ioc.get("value", ""))

    # source_ip -> dest_ip = communicates_with
    if source_ip and dest_ip and source_ip in ioc_values:
        relationships.append({
            "source_value": source_ip,
            "target_value": dest_ip,
            "edge_type": "communicates_with",
        })

    # source_ip -> username = logged_into (via username)
    if source_ip and username and source_ip in ioc_values and username in ioc_values:
        relationships.append({
            "source_value": source_ip,
            "target_value": username,
            "edge_type": "logged_into",
        })

    # source_ip -> hostname = communicates_with
    if source_ip and hostname and source_ip in ioc_values and hostname in ioc_values:
        relationships.append({
            "source_value": source_ip,
            "target_value": hostname,
            "edge_type": "communicates_with",
        })

    # username -> hostname = logged_into
    if username and hostname and username in ioc_values and hostname in ioc_values:
        relationships.append({
            "source_value": username,
            "target_value": hostname,
            "edge_type": "logged_into",
        })

    return relationships
