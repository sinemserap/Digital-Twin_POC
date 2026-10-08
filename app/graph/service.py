"""F03 Operational Relationship Graph service (US40852 Part 1).

Boundaries:
  * Reads canonical state only through F01ProjectionContract (never the claim tables directly).
  * Writes only the five graph_* tables; the session factory refuses every other table and the
    deployment role (migrations/f03_graph_role.sql) has no canonical write privilege (AC10).
  * Exposes exactly two server-side query templates; there is no query-expression input (AC09).
  * Authorizes the request (purpose x role, tenant, subject binding, restriction, erasure) and
    then every hop and every returned node/edge (tenant, subject, purpose) (AC06-AC08).
  * Audits every request with identifiers and a response digest, never values (AC11).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import event, select, update
from sqlalchemy.orm import sessionmaker

from ..security import Identity, sha256
from ..service import as_utc
from .models import (GRAPH_TABLES, GraphEdge, GraphNode, GraphProjection, GraphQueryAudit,
                     GraphRejection)
from .ontology import (EDGE_TYPES, GRAPH_PREDICATES, NODE_TYPES, ONTOLOGY_VERSION,
                       PROJECTION_VERSION, registry_document)
from .projection import ProjectionResult, canonical, project

GRAPH_ADMIN_ROLE = "graph_administrator"
PROJECTION_ROLE = "projection_service"
PROJECTION_ACCOUNT = "f03-projection"

# Approved query templates (AC08/AC09): id -> (version, purposes that may execute it).
TEMPLATES = {
    "role_context": {"version": "v1", "purposes": frozenset({"candidate_self_view", "preboarding_support"}),
                     "description": "Person -OFFERED_ROLE-> Role -ROLE_IN_UNIT-> OrgUnit, plus HAS_CONTACT and IN_UNIT context"},
    "blocker_explanation": {"version": "v1", "purposes": frozenset({"candidate_self_view", "preboarding_support"}),
                            "description": "Person -HAS_DEPENDENCY-> Task -BLOCKED_BY-> Task with the blocking reason and event"},
}
# Provenance fields withheld from the candidate self-view (v3.1 §22 "protect confidential source
# metadata while preserving meaningful explanation"). Provisional: decision D-06.
RESTRICTED_PROVENANCE = {"candidate_self_view": frozenset({"evidence_uri", "source_record_id"})}


def graph_sessions(engine):
    """Session factory for the graph store that refuses to flush any non-graph table."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    @event.listens_for(factory, "before_flush")
    def deny_canonical_writes(session, flush_context, instances):
        for obj in list(session.new) + list(session.dirty) + list(session.deleted):
            if obj.__tablename__ not in GRAPH_TABLES:
                raise PermissionError(f"F03 graph service may not write table {obj.__tablename__}")
    return factory


class GraphService:
    def __init__(self, engine, f01):
        self.sessions = graph_sessions(engine)
        self.f01 = f01

    # ----- audit -----

    def audit(self, db, identity, subject_id, purpose, template_id, operation, outcome, status,
              request_hash, correlation, response_digest=None, projection_id=None, edge_ids=None):
        db.add(GraphQueryAudit(actor=identity.account_id, tenant_id=identity.tenant_id, subject_id=subject_id,
                               purpose=purpose, template_id=template_id,
                               template_version=TEMPLATES.get(template_id, {}).get("version", "-"),
                               operation=operation, outcome=outcome, http_status=status,
                               request_hash=request_hash, response_digest=response_digest,
                               projection_id=projection_id, edge_ids=edge_ids, correlation_id=correlation))

    def _deny(self, db, identity, subject_id, purpose, template_id, operation, outcome, status, detail,
              request_hash, correlation):
        self.audit(db, identity, subject_id, purpose, template_id, operation, outcome, status, request_hash, correlation)
        db.commit()
        raise HTTPException(status, detail)

    # ----- projection lifecycle -----

    def _projection_identity(self, identity: Identity) -> Identity:
        # Tenant is server-derived from the authenticated administrator; the F01 read runs under the
        # projection service identity and the F01 purpose registered for F03 (preboarding_support).
        return Identity(identity.tenant_id, PROJECTION_ACCOUNT, frozenset({PROJECTION_ROLE}))

    def rebuild(self, identity: Identity, correlation: str, as_of: datetime | None = None) -> dict:
        request_hash = sha256(canonical({"op": "rebuild", "as_of": as_of.isoformat() if as_of else None}))
        with self.sessions() as db:
            if GRAPH_ADMIN_ROLE not in identity.roles:
                self._deny(db, identity, None, "-", "projection_rebuild", "rebuild", "denied", 403,
                           "graph administrator role required", request_hash, correlation)
        as_of = (as_of or datetime.now(timezone.utc)).astimezone(timezone.utc)
        snapshot = self.f01.snapshot(self._projection_identity(identity), tuple(GRAPH_PREDICATES), as_of, correlation)
        result = project(snapshot)
        with self.sessions() as db:
            # Full rebuild: the previous projection is dropped (rows deleted) and replaced atomically.
            previous = list(db.scalars(select(GraphProjection).where(
                GraphProjection.tenant_id == identity.tenant_id, GraphProjection.status == "active")))
            for old in previous:
                db.execute(GraphEdge.__table__.delete().where(GraphEdge.projection_id == old.id))
                db.execute(GraphNode.__table__.delete().where(GraphNode.projection_id == old.id))
                db.execute(GraphRejection.__table__.delete().where(GraphRejection.projection_id == old.id))
                old.status, old.replaced_at = "replaced", datetime.now(timezone.utc)
            projection = self._store(db, identity, correlation, result)
            summary = self._summary(projection)
            self.audit(db, identity, None, "-", "projection_rebuild", "rebuild", "completed", 200, request_hash,
                       correlation, response_digest=sha256(canonical(summary)), projection_id=projection.id)
            db.commit()
            return summary

    def _store(self, db, identity, correlation, result: ProjectionResult) -> GraphProjection:
        projection = GraphProjection(tenant_id=result.tenant_id, projection_version=PROJECTION_VERSION,
                                     ontology_version=ONTOLOGY_VERSION,
                                     as_of=datetime.fromisoformat(result.as_of),
                                     canonical_fingerprint=result.canonical_fingerprint,
                                     canonical_event_count=result.canonical_event_count,
                                     graph_hash=result.graph_hash(), node_count=len(result.nodes),
                                     edge_count=len(result.edges), rejected_count=len(result.rejections),
                                     status="active", actor=identity.account_id, correlation_id=correlation)
        db.add(projection); db.flush()
        for row in sorted(result.nodes.values(), key=lambda n: n.node_id):
            db.add(GraphNode(projection_id=projection.id, **row.__dict__))
        for row in sorted(result.edges.values(), key=lambda e: e.edge_id):
            db.add(GraphEdge(projection_id=projection.id, **row.__dict__))
        for rej in result.rejections:
            db.add(GraphRejection(projection_id=projection.id, tenant_id=result.tenant_id, subject_id=rej.subject_id,
                                  predicate=rej.predicate, claim_id=rej.claim_id, reason_code=rej.reason_code,
                                  detail=rej.detail))
        db.flush()
        return projection

    @staticmethod
    def _summary(p: GraphProjection) -> dict:
        return {"projection_id": p.id, "tenant_id": p.tenant_id, "status": p.status,
                "projection_version": p.projection_version, "ontology_version": p.ontology_version,
                "as_of": as_utc(p.as_of).isoformat(), "canonical_fingerprint": p.canonical_fingerprint,
                "canonical_event_count": p.canonical_event_count, "graph_hash": p.graph_hash,
                "node_count": p.node_count, "edge_count": p.edge_count, "rejected_count": p.rejected_count}

    def _active(self, db, tenant_id) -> GraphProjection | None:
        return db.scalar(select(GraphProjection).where(GraphProjection.tenant_id == tenant_id,
                                                       GraphProjection.status == "active"))

    def current(self, identity: Identity, correlation: str) -> dict:
        with self.sessions() as db:
            if GRAPH_ADMIN_ROLE not in identity.roles:
                self._deny(db, identity, None, "-", "projection_status", "status", "denied", 403,
                           "graph administrator role required", sha256(b"status"), correlation)
            active = self._active(db, identity.tenant_id)
            if not active:
                return {"tenant_id": identity.tenant_id, "status": "none"}
            summary = self._summary(active)
            rejections = list(db.scalars(select(GraphRejection).where(GraphRejection.projection_id == active.id)))
            summary["rejections"] = [{"subject_id": r.subject_id, "predicate": r.predicate, "claim_id": r.claim_id,
                                      "reason_code": r.reason_code, "detail": r.detail} for r in rejections]
            summary["node_types"] = sorted({n for n in db.scalars(select(GraphNode.node_type).where(GraphNode.projection_id == active.id))})
            summary["edge_types"] = sorted({e for e in db.scalars(select(GraphEdge.edge_type).where(GraphEdge.projection_id == active.id))})
            return summary

    def verify(self, identity: Identity, correlation: str) -> dict:
        """Deterministic-rebuild check (AC10): re-project the current canonical state at the active
        projection's as_of (dry run, nothing written) and compare every node/edge row and the hash."""
        request_hash = sha256(b"verify")
        with self.sessions() as db:
            if GRAPH_ADMIN_ROLE not in identity.roles:
                self._deny(db, identity, None, "-", "projection_verify", "verify", "denied", 403,
                           "graph administrator role required", request_hash, correlation)
            active = self._active(db, identity.tenant_id)
            if not active:
                raise HTTPException(404, "no active projection")
            stored_nodes = sorted(_node_identity(n) for n in db.scalars(select(GraphNode).where(GraphNode.projection_id == active.id)))
            stored_edges = sorted(_edge_identity(e) for e in db.scalars(select(GraphEdge).where(GraphEdge.projection_id == active.id)))
            as_of, stored_hash, stored_fp, pid = active.as_of, active.graph_hash, active.canonical_fingerprint, active.id
        snapshot = self.f01.snapshot(self._projection_identity(identity), tuple(GRAPH_PREDICATES), as_of, correlation)
        fresh = project(snapshot)
        fresh_nodes = sorted(n.identity() for n in fresh.nodes.values())
        fresh_edges = sorted(e.identity() for e in fresh.edges.values())
        report = {"projection_id": pid, "canonical_state_unchanged": fresh.canonical_fingerprint == stored_fp,
                  "stored_graph_hash": stored_hash, "recomputed_graph_hash": fresh.graph_hash(),
                  "nodes_identical": fresh_nodes == stored_nodes, "edges_identical": fresh_edges == stored_edges,
                  "identical": fresh.graph_hash() == stored_hash and fresh_nodes == stored_nodes and fresh_edges == stored_edges}
        with self.sessions() as db:
            self.audit(db, identity, None, "-", "projection_verify", "verify", "completed", 200, request_hash,
                       correlation, response_digest=sha256(canonical(report)), projection_id=pid)
            db.commit()
        return report

    # ----- authorized template execution -----

    def _authorize_request(self, db, identity, subject_id, purpose, template_id, request_hash, correlation):
        """Request-level authorization: template registered, purpose registered/allowed for the
        caller's role (F01 registry; a client cannot upgrade its purpose), template permitted for
        the purpose, subject in tenant, candidate bound, not restricted, not erased."""
        template = TEMPLATES.get(template_id)
        if not template:
            self._deny(db, identity, subject_id, purpose, template_id, "template_query", "unknown_template", 404,
                       "query template is not registered", request_hash, correlation)
        if not self.f01.purpose_permitted(identity, purpose, "read"):
            self._deny(db, identity, subject_id, purpose, template_id, "template_query", "purpose_denied", 403,
                       "purpose is not authorized for this identity and endpoint", request_hash, correlation)
        if purpose not in template["purposes"]:
            self._deny(db, identity, subject_id, purpose, template_id, "template_query", "template_not_for_purpose", 403,
                       "query template is not permitted for this purpose", request_hash, correlation)
        state, subject = self.f01.subject_access_state(db, identity, subject_id)
        if state == "not_found":
            self._deny(db, identity, subject_id, purpose, template_id, "template_query", "denied", 404,
                       "subject not found", request_hash, correlation)
        if state == "restricted":
            self._deny(db, identity, subject_id, purpose, template_id, "template_query", "restricted", 403,
                       "subject is restricted", request_hash, correlation)
        if state == "erased":
            self._deny(db, identity, subject_id, purpose, template_id, "template_query", "erased", 410,
                       "subject payload has been erased", request_hash, correlation)
        return subject

    def _hop(self, db, projection_id, identity, subject_id, purpose, edge_type, from_node_id, denied):
        """One authorized traversal step. Every edge must belong to the caller's tenant AND to the
        requested subject AND permit the purpose; both endpoint nodes must permit the purpose.
        Edges that fail are counted as denied hops and never returned."""
        rows = list(db.scalars(select(GraphEdge).where(
            GraphEdge.projection_id == projection_id, GraphEdge.tenant_id == identity.tenant_id,
            GraphEdge.subject_id == subject_id, GraphEdge.edge_type == edge_type,
            GraphEdge.src_node_id == from_node_id).order_by(GraphEdge.edge_id)))
        out = []
        for edge in rows:
            if purpose not in edge.allowed_purposes:
                denied.append({"edge_type": edge_type, "reason": "purpose"}); continue
            src = db.get(GraphNode, (projection_id, edge.src_node_id))
            dst = db.get(GraphNode, (projection_id, edge.dst_node_id))
            if not src or not dst or src.tenant_id != identity.tenant_id or dst.tenant_id != identity.tenant_id:
                denied.append({"edge_type": edge_type, "reason": "tenant"}); continue
            if purpose not in src.allowed_purposes or purpose not in dst.allowed_purposes:
                denied.append({"edge_type": edge_type, "reason": "node_purpose"}); continue
            for node in (src, dst):
                if node.subject_id is not None and node.subject_id != subject_id:
                    denied.append({"edge_type": edge_type, "reason": "subject"}); break
            else:
                out.append((edge, src, dst))
        return out

    def _node_view(self, node: GraphNode, purpose) -> dict:
        hidden = RESTRICTED_PROVENANCE.get(purpose, frozenset())
        return {"node_id": node.node_id, "type": node.node_type,
                "properties": {k: v for k, v in node.properties.items() if k not in hidden}}

    def _edge_view(self, edge: GraphEdge, purpose, evidence: GraphNode | None) -> dict:
        hidden = RESTRICTED_PROVENANCE.get(purpose, frozenset())
        provenance = {"claim_id": edge.claim_id, "event_id": edge.event_id, "event_type": edge.event_type,
                      "event_sequence": edge.event_sequence, "event_hash": edge.event_hash,
                      "source_system": edge.source_system, "source_record_id": edge.source_record_id,
                      "source_version": edge.source_version, "valid_from": edge.valid_from, "valid_to": edge.valid_to,
                      "projection_version": edge.projection_version,
                      "evidence": {"evidence_id": edge.evidence_id, "evidence_hash": edge.evidence_hash,
                                   "evidence_uri": edge.evidence_uri,
                                   "evidence_node_id": evidence.node_id if evidence else None}}
        provenance = {k: v for k, v in provenance.items() if k not in hidden}
        provenance["evidence"] = {k: v for k, v in provenance["evidence"].items() if k not in hidden}
        return {"edge_id": edge.edge_id, "type": edge.edge_type, "properties": edge.properties, "provenance": provenance}

    def _evidence_node(self, db, projection_id, subject_id, evidence_id) -> GraphNode | None:
        return db.scalar(select(GraphNode).where(GraphNode.projection_id == projection_id,
                                                 GraphNode.node_type == "Evidence",
                                                 GraphNode.subject_id == subject_id,
                                                 GraphNode.node_key == f"{subject_id}:{evidence_id}"))

    def _exclusions(self, db, projection_id, subject_id, predicates) -> list[dict]:
        rows = db.scalars(select(GraphRejection).where(GraphRejection.projection_id == projection_id,
                                                      GraphRejection.subject_id == subject_id,
                                                      GraphRejection.predicate.in_(predicates)))
        return [{"predicate": r.predicate, "reason": r.reason_code.lower()} for r in rows]

    def run_template(self, identity: Identity, template_id: str, subject_id: str, purpose: str, correlation: str) -> dict:
        request_hash = sha256(canonical({"template": template_id, "subject_id": subject_id, "purpose": purpose}))
        with self.sessions() as db:
            self._authorize_request(db, identity, subject_id, purpose, template_id, request_hash, correlation)
            active = self._active(db, identity.tenant_id)
            if not active:
                self._deny(db, identity, subject_id, purpose, template_id, "template_query", "no_projection", 409,
                           "no graph projection exists for this tenant", request_hash, correlation)
            person = db.scalar(select(GraphNode).where(GraphNode.projection_id == active.id,
                                                       GraphNode.node_type == "Person",
                                                       GraphNode.subject_id == subject_id,
                                                       GraphNode.tenant_id == identity.tenant_id))
            denied, hops_used = [], []
            body = {"template": template_id, "template_version": TEMPLATES[template_id]["version"],
                    "projection_id": active.id, "projection_version": active.projection_version,
                    "ontology_version": active.ontology_version, "subject_id": subject_id, "purpose": purpose,
                    "stale": False}
            if person is None:
                body.update({"result": "no_graph_state", "paths": [],
                             "exclusions": self._exclusions(db, active.id, subject_id, list(GRAPH_PREDICATES))})
            else:
                watermark = self.f01.ledger_watermark(db, subject_id)
                body["stale"] = watermark > int(person.properties.get("ledger_watermark", 0))
                if template_id == "role_context":
                    self._role_context(db, active.id, identity, subject_id, purpose, person, body, denied, hops_used)
                else:
                    self._blocker_explanation(db, active.id, identity, subject_id, purpose, person, body, denied, hops_used)
            body["denied_hops"] = len(denied)
            digest = sha256(canonical(body))
            body["audit"] = {"correlation_id": correlation, "response_digest": digest}
            self.audit(db, identity, subject_id, purpose, template_id, "template_query", "allowed", 200, request_hash,
                       correlation, response_digest=digest, projection_id=active.id, edge_ids=sorted(hops_used))
            db.commit()
            return body

    # Template A — Role context: Person -OFFERED_ROLE-> Role -ROLE_IN_UNIT-> OrgUnit (two hops),
    # plus the person's IN_UNIT and HAS_CONTACT context edges and the Evidence node of every hop.
    def _role_context(self, db, pid, identity, subject_id, purpose, person, body, denied, hops_used):
        paths = []
        for role_edge, _, role in self._hop(db, pid, identity, subject_id, purpose, "OFFERED_ROLE", person.node_id, denied):
            hops = [self._hop_view(db, pid, subject_id, purpose, role_edge, person, role)]
            hops_used.append(role_edge.edge_id)
            for unit_edge, _, unit in self._hop(db, pid, identity, subject_id, purpose, "ROLE_IN_UNIT", role.node_id, denied):
                hops.append(self._hop_view(db, pid, subject_id, purpose, unit_edge, role, unit)); hops_used.append(unit_edge.edge_id)
            paths.append({"hops": hops, "hop_count": len(hops)})
        context = []
        for edge_type in ("IN_UNIT", "HAS_CONTACT"):
            for edge, _, target in self._hop(db, pid, identity, subject_id, purpose, edge_type, person.node_id, denied):
                context.append(self._hop_view(db, pid, subject_id, purpose, edge, person, target)); hops_used.append(edge.edge_id)
        longest = max((p["hop_count"] for p in paths), default=0)
        body.update({"result": "complete" if longest >= 2 else ("partial" if paths or context else "no_context"),
                     "person": self._node_view(person, purpose), "paths": paths, "context": context,
                     "exclusions": self._exclusions(db, pid, subject_id, ["offered_role", "org_unit", "manager_or_sponsor"]),
                     "explanation": _explain_role_context(paths, context)})

    # Template B — Blocker explanation: Person -HAS_DEPENDENCY-> Task(blocked) -BLOCKED_BY-> Task(dependency).
    def _blocker_explanation(self, db, pid, identity, subject_id, purpose, person, body, denied, hops_used):
        blockers, dependencies = [], []
        for dep_edge, _, task in self._hop(db, pid, identity, subject_id, purpose, "HAS_DEPENDENCY", person.node_id, denied):
            hops_used.append(dep_edge.edge_id)
            first = self._hop_view(db, pid, subject_id, purpose, dep_edge, person, task)
            dependencies.append(first)
            for blk_edge, _, blocker in self._hop(db, pid, identity, subject_id, purpose, "BLOCKED_BY", task.node_id, denied):
                hops_used.append(blk_edge.edge_id)
                second = self._hop_view(db, pid, subject_id, purpose, blk_edge, task, blocker)
                blocking_event = self._blocking_event(db, identity, subject_id, blk_edge, task, blocker)
                blockers.append({"hops": [first, second], "hop_count": 2,
                                 "blocked_task": self._node_view(task, purpose),
                                 "blocking_dependency": self._node_view(blocker, purpose),
                                 "reason_code": blk_edge.properties.get("reason_code"),
                                 "reason": blk_edge.properties.get("reason"),
                                 "blocking_event": blocking_event})
        body.update({"result": "blocked" if blockers else ("no_blocker" if dependencies else "no_dependency_state"),
                     "person": self._node_view(person, purpose), "paths": blockers, "dependencies": dependencies,
                     "exclusions": self._exclusions(db, pid, subject_id, ["preboarding_dependency_status"]),
                     "explanation": _explain_blockers(blockers, dependencies)})

    def _blocking_event(self, db, identity, subject_id, edge, task, blocker) -> dict | None:
        """AC05: the PreboardingDependencyBlocked ledger event that corresponds to this blocked edge.
        It is read from the F01 ledger (read-only) by claim id; absent if F01 did not emit one."""
        from ..models import EventLedger
        rows = db.scalars(select(EventLedger).where(EventLedger.claim_id == edge.claim_id,
                                                    EventLedger.subject_id == subject_id,
                                                    EventLedger.tenant_id == identity.tenant_id,
                                                    EventLedger.event_type == "PreboardingDependencyBlocked")
                          .order_by(EventLedger.sequence))
        for row in rows:
            meta = row.metadata_json or {}
            if meta.get("task_ref") == task.node_key and meta.get("blocked_by_ref") == blocker.node_key:
                return {"event_id": row.id, "event_type": row.event_type, "event_sequence": row.sequence,
                        "record_hash": row.record_hash, "reason_code": meta.get("reason_code")}
        return None

    def _hop_view(self, db, pid, subject_id, purpose, edge, src, dst) -> dict:
        evidence = self._evidence_node(db, pid, subject_id, edge.evidence_id)
        return {"from": self._node_view(src, purpose), "edge": self._edge_view(edge, purpose, evidence),
                "to": self._node_view(dst, purpose),
                "evidence_node": self._node_view(evidence, purpose) if evidence else None}

    @staticmethod
    def ontology() -> dict:
        return registry_document()

    @staticmethod
    def templates() -> dict:
        return {"templates": [{"id": k, "version": v["version"], "purposes": sorted(v["purposes"]),
                               "description": v["description"],
                               "path": f"/graph/v1/subjects/{{subject_id}}/{k.replace('_', '-')}"} for k, v in TEMPLATES.items()],
                "client_query_expressions": "not accepted (AC09)"}


def _node_identity(n: GraphNode) -> tuple:
    return (n.node_id, n.tenant_id, n.node_type, n.node_key, n.subject_id,
            canonical(n.properties).decode(), canonical(n.allowed_purposes).decode())


def _edge_identity(e: GraphEdge) -> tuple:
    return (e.edge_id, e.tenant_id, e.edge_type, e.src_node_id, e.dst_node_id, e.subject_id, e.claim_id,
            e.event_id, e.event_type, e.event_sequence, e.event_hash, e.source_system, e.source_record_id,
            e.source_version, e.evidence_id, e.evidence_hash, e.evidence_uri, e.valid_from, e.valid_to,
            e.projection_version, canonical(e.allowed_purposes).decode(), canonical(e.properties).decode())


def _explain_role_context(paths, context) -> list[str]:
    lines = []
    for path in paths:
        for hop in path["hops"]:
            p = hop["edge"]["provenance"]
            lines.append(f"{hop['from']['type']} -{hop['edge']['type']}-> {hop['to']['type']}"
                         f"({_label(hop['to'])}): accepted claim {p['claim_id']} from {p['source_system']} "
                         f"(event {p['event_type']} #{p['event_sequence']}, evidence {p['evidence']['evidence_id']}).")
    for hop in context:
        p = hop["edge"]["provenance"]
        lines.append(f"{hop['from']['type']} -{hop['edge']['type']}-> {hop['to']['type']}({_label(hop['to'])}): "
                     f"accepted claim {p['claim_id']} from {p['source_system']} (event {p['event_type']} #{p['event_sequence']}).")
    return lines or ["No accepted role or organisational context is projected for this person."]


def _explain_blockers(blockers, dependencies) -> list[str]:
    if not dependencies:
        return ["No accepted preboarding dependency state is projected for this person."]
    if not blockers:
        return ["Dependencies are projected but none is blocked."]
    out = []
    for b in blockers:
        ev = b["blocking_event"]
        out.append(f"Task {_label(b['blocked_task'])} is blocked by {_label(b['blocking_dependency'])}: "
                   f"{b['reason_code']}" + (f" — {b['reason']}" if b["reason"] else "") +
                   (f" (event {ev['event_type']} #{ev['event_sequence']})." if ev else " (no PreboardingDependencyBlocked event in ledger)."))
    return out


def _label(node_view) -> str:
    props = node_view["properties"]
    return props.get("label") or next((v for k, v in props.items() if k.endswith("_ref")), node_view["node_id"][:8])
