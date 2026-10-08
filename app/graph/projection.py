"""Deterministic projection of accepted F01 canonical state into the F03 ontology.

Pipeline (US40852 §7.3): snapshot (F01 contract) -> accepted filter -> eligibility validation
-> predicate-to-ontology mapping -> stable identities -> provenance -> purpose metadata ->
rows for the graph store. The function is pure: the same snapshot always yields the same
node/edge rows and the same graph hash, so a drop-and-rebuild from the same canonical state
is byte-identical (AC10). No wall-clock value, run id or random value enters a node or edge.

VALUE SCHEMAS (provisional, decision D-03): F01 Part 1 registers the predicates but does not
define value shapes for org_unit, manager_or_sponsor and preboarding_dependency_status. The
shapes accepted here are the F03 proposal; anything else is rejected with INVALID_VALUE and
never turned into a node or edge. Unknown values are not graph facts (no fabrication).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..dependency_schema import InvalidDependencyValue, normalize_dependencies
from ..security import sha256
from .ontology import (EDGE_TYPES, GRAPH_PREDICATES, NODE_TYPES, ONTOLOGY_VERSION,
                       PROJECTION_VERSION)

PREDICATE_ORDER = ("offered_role", "org_unit", "manager_or_sponsor", "preboarding_dependency_status")


def canonical(data) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def node_id(tenant: str, node_type: str, key: str) -> str:
    return sha256(f"{tenant}|{node_type}|{key}".encode())


def edge_id(tenant: str, edge_type: str, src: str, dst: str, claim_id: str) -> str:
    return sha256(f"{tenant}|{edge_type}|{src}|{dst}|{claim_id}".encode())


@dataclass(frozen=True)
class NodeRow:
    node_id: str
    tenant_id: str
    node_type: str
    node_key: str
    subject_id: str | None
    properties: dict
    allowed_purposes: list

    def identity(self) -> tuple:
        return (self.node_id, self.tenant_id, self.node_type, self.node_key, self.subject_id,
                canonical(self.properties).decode(), canonical(self.allowed_purposes).decode())


@dataclass(frozen=True)
class EdgeRow:
    edge_id: str
    tenant_id: str
    edge_type: str
    src_node_id: str
    dst_node_id: str
    subject_id: str
    claim_id: str
    event_id: str
    event_type: str
    event_sequence: int
    event_hash: str
    source_system: str
    source_record_id: str
    source_version: int
    evidence_id: str
    evidence_hash: str
    evidence_uri: str
    valid_from: str
    valid_to: str | None
    projection_version: str
    allowed_purposes: list
    properties: dict

    def identity(self) -> tuple:
        return (self.edge_id, self.tenant_id, self.edge_type, self.src_node_id, self.dst_node_id,
                self.subject_id, self.claim_id, self.event_id, self.event_type, self.event_sequence,
                self.event_hash, self.source_system, self.source_record_id, self.source_version,
                self.evidence_id, self.evidence_hash, self.evidence_uri, self.valid_from, self.valid_to,
                self.projection_version, canonical(self.allowed_purposes).decode(),
                canonical(self.properties).decode())


@dataclass
class Rejection:
    subject_id: str | None
    predicate: str | None
    claim_id: str | None
    reason_code: str
    detail: str | None = None


@dataclass
class ProjectionResult:
    tenant_id: str
    as_of: str
    canonical_fingerprint: str
    canonical_event_count: int
    nodes: dict[str, NodeRow] = field(default_factory=dict)
    edges: dict[str, EdgeRow] = field(default_factory=dict)
    rejections: list[Rejection] = field(default_factory=list)

    def graph_hash(self) -> str:
        nodes = sorted(n.identity() for n in self.nodes.values())
        edges = sorted(e.identity() for e in self.edges.values())
        return sha256(canonical({"ontology": ONTOLOGY_VERSION, "projection": PROJECTION_VERSION,
                                 "nodes": nodes, "edges": edges}))


class ProjectionError(ValueError):
    def __init__(self, code: str, detail: str | None = None):
        super().__init__(code)
        self.code, self.detail = code, detail


# ----- value shape normalisation (provisional schemas, D-03) -----

def _ref(value, key: str) -> tuple[str, str | None]:
    """Accept a non-empty reference string or an object with `key` (+ optional label)."""
    if isinstance(value, str) and value.strip():
        return value.strip(), None
    if isinstance(value, dict) and isinstance(value.get(key), str) and value[key].strip():
        label = value.get("label")
        if label is not None and not isinstance(label, str):
            raise ProjectionError("INVALID_VALUE", f"{key}: label must be a string")
        return value[key].strip(), label
    raise ProjectionError("INVALID_VALUE", f"expected reference string or object with '{key}'")


def _dependencies(value) -> list[dict]:
    try:
        return normalize_dependencies(value)
    except InvalidDependencyValue as exc:
        raise ProjectionError("INVALID_VALUE", str(exc)) from exc


# ----- projection -----

def project(snapshot: dict) -> ProjectionResult:
    tenant = snapshot["tenant_id"]
    result = ProjectionResult(tenant, snapshot["as_of"], snapshot["canonical_fingerprint"],
                              snapshot["canonical_event_count"])
    for item in snapshot.get("excluded_subjects", []):
        result.rejections.append(Rejection(item["subject_id"], None, None, item["reason"].upper()))

    def put_node(node_type: str, key: str, subject_id: str | None, props: dict) -> str:
        spec = NODE_TYPES[node_type]   # KeyError == unregistered type: rejected by construction
        nid = node_id(tenant, node_type, key)
        row = NodeRow(nid, tenant, node_type, key, subject_id if spec.subject_bound else None,
                      props, sorted(spec.allowed_purposes))
        existing = result.nodes.get(nid)
        if existing is None:
            result.nodes[nid] = row
        elif existing.properties != props:
            # Shared node reached with different display properties: keep the first (sorted
            # subject order makes this deterministic) and record the disagreement.
            result.rejections.append(Rejection(subject_id, None, None, "SHARED_NODE_PROPERTY_CONFLICT",
                                               f"{node_type}:{key}"))
        return nid

    def put_edge(edge_type: str, src: str, dst: str, subject_id: str, claim: dict, props: dict) -> str | None:
        spec = EDGE_TYPES[edge_type]   # KeyError == unregistered type: rejected by construction
        if result.nodes[src].node_type != spec.src or result.nodes[dst].node_type != spec.dst:
            raise ProjectionError("INVALID_EDGE_ENDPOINTS", edge_type)
        eid = edge_id(tenant, edge_type, src, dst, claim["claim_id"])
        if eid in result.edges:
            result.rejections.append(Rejection(subject_id, claim.get("predicate"), claim["claim_id"],
                                               "DUPLICATE_REFERENCE", edge_type))
            return None
        event = claim["event"]
        result.edges[eid] = EdgeRow(
            eid, tenant, edge_type, src, dst, subject_id, claim["claim_id"], event["event_id"],
            event["event_type"], event["event_sequence"], event["record_hash"], claim["source_system"],
            claim["source_record_id"], claim["source_version"], claim["evidence_id"], claim["evidence_hash"],
            claim["evidence_uri"], claim["valid_from"], claim["valid_to"], PROJECTION_VERSION,
            sorted(spec.allowed_purposes), props)
        return eid

    def eligible(subject_id: str, predicate: str, entry: dict | None) -> dict | None:
        """Accepted-canonical-only filter (AC02) and F01 §1.1 authority check."""
        if entry is None or entry.get("state") != "accepted":
            reason = (entry or {}).get("reason", "no_claim")
            for cid in (entry or {}).get("claim_ids") or [None]:
                result.rejections.append(Rejection(subject_id, predicate, cid, reason.upper()))
            return None
        claim = dict(entry, predicate=predicate)
        checks = (
            (claim.get("record_kind") == "canonical_claim", "NOT_CANONICAL_RECORD"),
            (claim.get("claim_class") == "authoritative", "CLAIM_CLASS_NOT_ALLOWED"),
            (claim.get("status") == "current", "NOT_CURRENT"),
            (claim.get("source_system") in GRAPH_PREDICATES[predicate], "SOURCE_NOT_AUTHORITATIVE"),
            (bool(claim.get("event")) and claim["event"].get("event_type") == "ClaimAccepted", "MISSING_ACCEPTED_EVENT"),
            (bool(claim.get("evidence_id")) and bool(claim.get("evidence_hash")), "MISSING_EVIDENCE_REFERENCE"),
            (bool(claim.get("valid_from")), "MISSING_VALIDITY"),
        )
        for ok, code in checks:
            if not ok:
                result.rejections.append(Rejection(subject_id, predicate, claim["claim_id"], code))
                return None
        return claim

    for subject in sorted(snapshot["subjects"], key=lambda s: s["subject_id"]):
        sid = subject["subject_id"]
        # ledger_watermark is canonical state (max accepted event sequence), so it is deterministic
        # and lets the read path flag a projection that is older than the subject's ledger.
        person = put_node("Person", sid, sid, {"subject_id": sid, "ledger_watermark": subject.get("ledger_watermark", 0)})
        accepted = {p: eligible(sid, p, subject["claims"].get(p)) for p in PREDICATE_ORDER}
        role_node = unit_node = None
        for predicate in PREDICATE_ORDER:
            claim = accepted[predicate]
            if claim is None:
                continue
            try:
                value = claim["value"]
                if predicate == "offered_role":
                    ref, label = _ref(value, "role_ref")
                    role_node = put_node("Role", ref, None, {"role_ref": ref, **({"label": label} if label else {})})
                    put_edge("OFFERED_ROLE", person, role_node, sid, claim, {})
                elif predicate == "org_unit":
                    ref, label = _ref(value, "unit_ref")
                    unit_node = put_node("OrgUnit", ref, None, {"unit_ref": ref, **({"label": label} if label else {})})
                    put_edge("IN_UNIT", person, unit_node, sid, claim, {})
                elif predicate == "manager_or_sponsor":
                    ref, label = _ref(value, "contact_ref")
                    relationship = value.get("relationship", "manager_or_sponsor") if isinstance(value, dict) else "manager_or_sponsor"
                    if relationship not in {"manager", "sponsor", "manager_or_sponsor"}:
                        raise ProjectionError("INVALID_VALUE", "relationship must be manager|sponsor")
                    contact = put_node("Contact", ref, None, {"contact_ref": ref, **({"label": label} if label else {})})
                    put_edge("HAS_CONTACT", person, contact, sid, claim, {"relationship": relationship})
                elif predicate == "preboarding_dependency_status":
                    for dep in _dependencies(value):
                        task = put_node("Task", dep["task_ref"], None,
                                        {"task_ref": dep["task_ref"], **({"label": dep["label"]} if dep["label"] else {})})
                        put_edge("HAS_DEPENDENCY", person, task, sid, claim, {"status": dep["status"]})
                        if dep["status"] == "blocked":
                            blocker = put_node("Task", dep["blocked_by"], None,
                                               {"task_ref": dep["blocked_by"],
                                                **({"label": dep["blocked_by_label"]} if dep["blocked_by_label"] else {})})
                            put_edge("BLOCKED_BY", task, blocker, sid, claim,
                                     {"reason_code": dep["reason_code"],
                                      **({"reason": dep["reason"]} if dep["reason"] else {})})
                # Evidence relationship for every accepted claim that contributed (AC03 / "evidence relationships").
                evidence = put_node("Evidence", f"{sid}:{claim['evidence_id']}", sid,
                                    {"evidence_id": claim["evidence_id"], "evidence_hash": claim["evidence_hash"],
                                     "evidence_uri": claim["evidence_uri"], "source_system": claim["source_system"]})
                put_edge("EVIDENCED_BY", person, evidence, sid, claim, {"predicate": predicate})
            except ProjectionError as exc:
                result.rejections.append(Rejection(sid, predicate, claim["claim_id"], exc.code, exc.detail))
                _drop_subject_predicate(result, sid, claim["claim_id"])
        # Derived two-hop context edge (F01 §1.1 "F03 ROLE_IN_UNIT"): the org_unit claim is the
        # provenance; the edge is subject-scoped so a shared Role never leaks another unit.
        if role_node and unit_node and accepted["org_unit"]:
            put_edge("ROLE_IN_UNIT", role_node, unit_node, sid, accepted["org_unit"],
                     {"role_claim_id": accepted["offered_role"]["claim_id"]})
    return result


def _drop_subject_predicate(result: ProjectionResult, subject_id: str, claim_id: str) -> None:
    """A claim that failed mapping half-way leaves no partial edges (all-or-nothing per claim)."""
    for eid in [e for e, row in result.edges.items() if row.subject_id == subject_id and row.claim_id == claim_id]:
        del result.edges[eid]
    referenced = {e.src_node_id for e in result.edges.values()} | {e.dst_node_id for e in result.edges.values()}
    for nid in [n for n, row in result.nodes.items() if row.node_type != "Person" and n not in referenced]:
        del result.nodes[nid]
