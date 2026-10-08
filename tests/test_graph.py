"""F03 Operational Relationship Graph — Part 1 (US40852) acceptance tests G01–G40, mapped to AC01–AC11.

Shared by the SQLite regression run and the migrated PostgreSQL run (--postgres-url). Synthetic
data only. Candidate A (tenant-a) has role R / unit U1 / manager M / one blocked dependency;
candidate B (tenant-a) shares role R and manager M, has unit U2 and an open dependency;
candidate C (tenant-b) has role R and unit U1 (same references, foreign tenant); candidate D
(tenant-a) comes in through the real F08 JSONL import and therefore has offered_role only.
"""
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from app.graph.models import GraphEdge, GraphNode, GraphProjection, GraphQueryAudit, GraphRejection
from app.graph.ontology import EDGE_TYPES, NODE_TYPES, PROJECTION_VERSION, assert_registry_invariants
from app.graph.projection import ProjectionError, project
from app.main import create_app
from app.models import AuditLog, Claim, EventLedger, Subject
from app.security import sha256
from app.service import canonical
from test_acceptance import env, headers, import_subject
from test_import import file, record, upload

ADMIN = dict(account="graph-admin", roles="graph_administrator")
SUPPORT = dict(account="support-1", roles="support")


def mutation(predicate, value, source="HR", idem=None, version=1, record_id="rec-1", valid_from="2026-01-01T00:00:00Z",
             valid_to=None, claim_class="authoritative", record_kind="canonical_claim"):
    idem = idem or f"{predicate}-{source}-{version}-{record_id}"
    evidence = f"synthetic {source} {predicate} {record_id} v{version} {json.dumps(value, sort_keys=True)}".encode()
    return {"idempotency_key": idem, "predicate": predicate, "value": value, "claim_class": claim_class,
            "record_kind": record_kind,
            "source": {"system": source, "record_id": record_id, "authority": "authoritative", "version": version},
            "evidence": {"evidence_id": "ev-" + hashlib.sha256(idem.encode()).hexdigest()[:30],   # claim.evidence_id is varchar(36)
                         "hash": hashlib.sha256(evidence).hexdigest(),
                         "content_base64": base64.b64encode(evidence).decode()},
            "purpose_id": "source_sync", "valid_from": valid_from, "valid_to": valid_to,
            "observed_at": "2026-01-01T00:00:00Z", "retention_rule": "preboarding_context", "confidence_band": "confirmed"}


def claim(client, sid, body, tenant="tenant-a"):
    body = {**body, "idempotency_key": f"{sid}:{body['idempotency_key']}"}   # receipts are tenant-scoped
    response = client.post(f"/subjects/{sid}/claims", headers=headers(tenant=tenant), json=body)
    assert response.status_code == 201, response.text
    return response.json()


BLOCKED = {"dependencies": [{"task_ref": "TASK-LAPTOP", "label": "Laptop", "status": "blocked",
                             "blocked_by": {"task_ref": "REQ-ACCOUNT", "label": "AD account"},
                             "reason_code": "DEP_NOT_RESOLVED", "reason": "waiting on account creation"},
                            {"task_ref": "TASK-BADGE", "status": "open"}]}
OPEN = {"dependencies": [{"task_ref": "TASK-LAPTOP", "label": "Laptop", "status": "open"}]}


def seed(client):
    a = import_subject(client, "p-a", "candidate-a").json()["subject_id"]
    b = import_subject(client, "p-b", "candidate-b").json()["subject_id"]
    c = import_subject(client, "p-c", "candidate-c", tenant="tenant-b").json()["subject_id"]
    claim(client, a, mutation("offered_role", "synthetic-engineer", "ATS"))
    claim(client, a, mutation("org_unit", {"unit_ref": "DWP-RND", "label": "DWP R&D"}))
    claim(client, a, mutation("manager_or_sponsor", {"contact_ref": "mgr-007", "relationship": "manager"}))
    claim(client, a, mutation("preboarding_dependency_status", BLOCKED, "ITSM"))
    claim(client, b, mutation("offered_role", "synthetic-engineer", "ATS"))
    claim(client, b, mutation("org_unit", {"unit_ref": "CLOUD-OPS", "label": "Cloud Ops"}))
    claim(client, b, mutation("manager_or_sponsor", {"contact_ref": "mgr-007", "relationship": "manager"}))
    claim(client, b, mutation("preboarding_dependency_status", OPEN, "ITSM"))
    claim(client, c, mutation("offered_role", "synthetic-engineer", "ATS"), tenant="tenant-b")
    claim(client, c, mutation("org_unit", {"unit_ref": "DWP-RND", "label": "DWP R&D"}), tenant="tenant-b")
    return a, b, c


def rebuild(client, tenant="tenant-a", as_of=None, **identity):
    identity = identity or ADMIN
    body = {"as_of": as_of} if as_of else None
    return client.post("/graph/v1/projections/rebuild", json=body, headers=headers(tenant=tenant, **identity))


def role_context(client, sid, purpose="candidate_self_view", tenant="tenant-a", **identity):
    identity = identity or dict(account="candidate-a", roles="candidate")
    return client.get(f"/graph/v1/subjects/{sid}/role-context", params={"purpose": purpose},
                      headers=headers(tenant=tenant, **identity))


def blockers(client, sid, purpose="candidate_self_view", tenant="tenant-a", **identity):
    identity = identity or dict(account="candidate-a", roles="candidate")
    return client.get(f"/graph/v1/subjects/{sid}/blocker-explanation", params={"purpose": purpose},
                      headers=headers(tenant=tenant, **identity))


def graph_rows(app, tenant="tenant-a"):
    with app.state.graph.sessions() as db:
        active = db.scalar(select(GraphProjection).where(GraphProjection.tenant_id == tenant,
                                                         GraphProjection.status == "active"))
        nodes = sorted((n.node_id, n.node_type, n.node_key, n.subject_id, canonical(n.properties), canonical(n.allowed_purposes))
                       for n in db.scalars(select(GraphNode).where(GraphNode.projection_id == active.id)))
        edges = sorted((e.edge_id, e.edge_type, e.src_node_id, e.dst_node_id, e.subject_id, e.claim_id, e.event_id,
                        e.event_type, e.event_sequence, e.event_hash, e.source_system, e.source_record_id,
                        e.source_version, e.evidence_id, e.evidence_hash, e.evidence_uri, e.valid_from, e.valid_to,
                        e.projection_version, canonical(e.allowed_purposes), canonical(e.properties))
                       for e in db.scalars(select(GraphEdge).where(GraphEdge.projection_id == active.id)))
        return active.graph_hash, nodes, edges


def all_hops(body):
    return [h for p in body.get("paths", []) for h in p["hops"]] + body.get("context", [])


def text_of(response):
    return json.dumps(response.json(), sort_keys=True)


# ----- AC01 ontology -----

def test_g01_registry_has_exactly_six_node_and_seven_edge_types():
    assert_registry_invariants()
    assert set(NODE_TYPES) == {"Person", "Role", "OrgUnit", "Contact", "Task", "Evidence"}
    assert set(EDGE_TYPES) == {"OFFERED_ROLE", "IN_UNIT", "ROLE_IN_UNIT", "HAS_CONTACT", "HAS_DEPENDENCY",
                               "BLOCKED_BY", "EVIDENCED_BY"}
    # F01 §1.1 "Needed by" names are all present, with their predicates.
    assert EDGE_TYPES["OFFERED_ROLE"].predicate == "offered_role"
    assert EDGE_TYPES["ROLE_IN_UNIT"].predicate == "org_unit"
    assert EDGE_TYPES["HAS_CONTACT"].predicate == "manager_or_sponsor"
    assert EDGE_TYPES["HAS_DEPENDENCY"].predicate == EDGE_TYPES["BLOCKED_BY"].predicate == "preboarding_dependency_status"


def test_g02_projection_uses_only_registered_types_and_rejects_others(env):
    client, app = env
    seed(client)
    assert rebuild(client).status_code == 200
    with app.state.graph.sessions() as db:
        assert {n for n in db.scalars(select(GraphNode.node_type))} <= set(NODE_TYPES)
        assert {e for e in db.scalars(select(GraphEdge.edge_type))} <= set(EDGE_TYPES)
        assert {n for n in db.scalars(select(GraphNode.node_type))} == set(NODE_TYPES)   # all six populated
        assert {e for e in db.scalars(select(GraphEdge.edge_type))} == set(EDGE_TYPES)   # all seven populated
    # Unregistered types cannot be introduced through the registry mappings.
    with pytest.raises(KeyError):
        NODE_TYPES["Skill"]
    with pytest.raises(KeyError):
        EDGE_TYPES["HAS_SKILL"]
    ontology = client.get("/graph/v1/ontology", headers=headers(**SUPPORT)).json()
    assert len(ontology["node_types"]) == 6 and len(ontology["edge_types"]) == 7
    assert ontology["status"] == "proposed-pending-design-authority"
    assert "has_skill" not in json.dumps(ontology) and "Knowledge" not in json.dumps(ontology)


# ----- AC02 canonical source only -----

def test_g03_model_outputs_and_non_canonical_records_never_enter_the_graph(env):
    client, app = env
    a, _, _ = seed(client)
    for change in ({"record_kind": "model_output", "claim_class": "inference"},
                   {"record_kind": "quarantined_hypothesis", "claim_class": "hypothesis"},
                   {"claim_class": "prediction"}, {"claim_class": "self_declared"}):
        body = mutation("org_unit", {"unit_ref": "LEAKED"}, idem="bad-" + json.dumps(change, sort_keys=True))
        body.update(change)
        assert client.post(f"/subjects/{a}/claims", headers=headers(), json=body).status_code == 422
    rebuild(client)
    with app.state.graph.sessions() as db:
        assert "LEAKED" not in json.dumps([n.properties for n in db.scalars(select(GraphNode))])


def test_g04_contested_superseded_historical_and_expired_records_are_excluded(env):
    client, app = env
    a, b, _ = seed(client)
    # Supersede A's org_unit (v2); the superseded v1 must disappear from the graph.
    claim(client, a, mutation("org_unit", {"unit_ref": "DWP-RND-2"}, version=2))
    # Contest B's org_unit by a second source with a different value: no org_unit edge for B at all.
    claim(client, b, mutation("org_unit", {"unit_ref": "OTHER"}, source="directory", record_id="dir-1"))
    # Late lower version for A's manager: historical, current state unchanged.
    claim(client, a, mutation("manager_or_sponsor", {"contact_ref": "mgr-OLD"}, version=0, record_id="rec-0"))
    # Expired role for B's valid_to in the past is excluded when projected as of now.
    claim(client, b, mutation("offered_role", "expired-role", "ATS", version=2, valid_to="2026-02-01T00:00:00Z"))
    assert rebuild(client).status_code == 200
    with app.state.graph.sessions() as db:
        active = db.scalar(select(GraphProjection).where(GraphProjection.status == "active"))
        units = {e.dst_node_id for e in db.scalars(select(GraphEdge).where(GraphEdge.edge_type == "IN_UNIT"))}
        keys = {db.get(GraphNode, (active.id, u)).node_key for u in units}
        assert keys == {"DWP-RND-2"}                       # superseded DWP-RND gone, contested B excluded
        contacts = {db.get(GraphNode, (active.id, e.dst_node_id)).node_key
                    for e in db.scalars(select(GraphEdge).where(GraphEdge.edge_type == "HAS_CONTACT"))}
        assert contacts == {"mgr-007"}                      # historical mgr-OLD never projected
        rejected = {(r.subject_id, r.predicate, r.reason_code) for r in db.scalars(select(GraphRejection))}
        assert (b, "org_unit", "CONTESTED") in rejected and (b, "offered_role", "EXPIRED") in rejected
        assert not db.scalar(select(GraphEdge).where(GraphEdge.edge_type == "OFFERED_ROLE", GraphEdge.subject_id == b))
        assert "expired-role" not in json.dumps([n.properties for n in db.scalars(select(GraphNode))])


def test_g05_claim_from_non_authoritative_source_and_invalid_value_shapes_are_rejected(env):
    client, app = env
    a, _, _ = seed(client)
    # org_unit asserted by the ATS source: F01 Part 1 does not enforce source authority at write,
    # the F03 eligibility validation must (F01 §1.1: org_unit authority = HR/directory).
    d = import_subject(client, "p-d", "candidate-d").json()["subject_id"]
    claim(client, d, mutation("org_unit", {"unit_ref": "ATS-UNIT"}, source="ATS"))
    claim(client, d, mutation("preboarding_dependency_status", {"dependencies": [{"task_ref": "X", "status": "blocked"}]}, "ITSM"))
    claim(client, d, mutation("manager_or_sponsor", 42))
    rebuild(client)
    with app.state.graph.sessions() as db:
        rejected = {(r.predicate, r.reason_code) for r in db.scalars(select(GraphRejection).where(GraphRejection.subject_id == d))}
        assert ("org_unit", "SOURCE_NOT_AUTHORITATIVE") in rejected
        assert ("preboarding_dependency_status", "INVALID_VALUE") in rejected
        assert ("manager_or_sponsor", "INVALID_VALUE") in rejected
        assert "ATS-UNIT" not in json.dumps([n.properties for n in db.scalars(select(GraphNode))])
        assert not db.scalar(select(GraphEdge).where(GraphEdge.subject_id == d))   # no partial edges


def test_g06_unknown_values_produce_no_fabricated_nodes(env):
    client, app = env
    d = import_subject(client, "p-d", "candidate-d").json()["subject_id"]
    rebuild(client)
    with app.state.graph.sessions() as db:
        assert db.scalar(select(func.count()).select_from(GraphEdge)) == 0
        assert [n.node_type for n in db.scalars(select(GraphNode))] == ["Person"]
    body = role_context(client, d, account="candidate-d", roles="candidate").json()
    assert body["result"] == "no_context" and body["paths"] == [] and body["context"] == []
    assert {x["predicate"]: x["reason"] for x in body["exclusions"]} == {
        "offered_role": "no_claim", "org_unit": "no_claim", "manager_or_sponsor": "no_claim"}


# ----- AC03 provenance on every edge -----

def test_g07_every_edge_carries_claim_event_source_validity_and_projection_version(env):
    client, app = env
    seed(client); rebuild(client)
    with app.state.graph.sessions() as db:
        edges = list(db.scalars(select(GraphEdge)))
        assert edges
        for e in edges:
            assert e.claim_id and e.event_id and e.event_type == "ClaimAccepted" and e.event_sequence > 0
            assert e.source_system and e.valid_from and e.projection_version == PROJECTION_VERSION
            assert e.evidence_id and len(e.evidence_hash) == 64
    with app.state.sessions() as db:   # every referenced claim and event exists and is accepted/current
        for e in edges:
            c = db.get(Claim, e.claim_id)
            assert c and c.status == "current" and c.record_kind == "canonical_claim"
            ev = db.get(EventLedger, e.event_id)
            assert ev and ev.event_type == "ClaimAccepted" and ev.record_hash == e.event_hash


def test_g08_projection_refuses_claims_without_accepted_event_or_evidence():
    base = {"tenant_id": "t", "as_of": "2026-01-01T00:00:00+00:00", "canonical_fingerprint": "f", "canonical_event_count": 1}
    good = {"state": "accepted", "value": "r", "claim_id": "c1", "claim_class": "authoritative", "record_kind": "canonical_claim",
            "status": "current", "source_system": "ATS", "source_record_id": "r", "source_version": 1,
            "evidence_id": "e", "evidence_hash": "h", "evidence_uri": "u", "valid_from": "2026-01-01T00:00:00+00:00",
            "valid_to": None, "event": {"event_id": "ev", "event_type": "ClaimAccepted", "event_sequence": 2, "record_hash": "x"},
            "related_events": []}
    for broken, code in (({"event": None}, "MISSING_ACCEPTED_EVENT"), ({"evidence_id": ""}, "MISSING_EVIDENCE_REFERENCE"),
                         ({"status": "historical"}, "NOT_CURRENT"), ({"record_kind": "model_output"}, "NOT_CANONICAL_RECORD")):
        snapshot = {**base, "subjects": [{"subject_id": "s", "claims": {"offered_role": {**good, **broken}}}]}
        result = project(snapshot)
        assert not result.edges and [r.reason_code for r in result.rejections if r.predicate == "offered_role"] == [code]


# ----- AC04 role context -----

def test_g09_role_context_is_a_real_two_hop_traversal_with_evidence_on_every_edge(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    response = role_context(client, a)
    assert response.status_code == 200
    body = response.json()
    assert body["result"] == "complete" and body["paths"][0]["hop_count"] == 2
    hops = body["paths"][0]["hops"]
    assert [h["edge"]["type"] for h in hops] == ["OFFERED_ROLE", "ROLE_IN_UNIT"]
    assert [(h["from"]["type"], h["to"]["type"]) for h in hops] == [("Person", "Role"), ("Role", "OrgUnit")]
    assert hops[0]["to"]["node_id"] == hops[1]["from"]["node_id"]          # connected path
    assert hops[1]["to"]["properties"]["unit_ref"] == "DWP-RND"
    for h in all_hops(body):
        p = h["edge"]["provenance"]
        assert p["claim_id"] and p["event_id"] and p["event_type"] == "ClaimAccepted"
        assert p["evidence"]["evidence_id"] and p["evidence"]["evidence_hash"] and h["evidence_node"]["type"] == "Evidence"
    assert {h["edge"]["type"] for h in body["context"]} == {"IN_UNIT", "HAS_CONTACT"}
    assert body["stale"] is False and body["denied_hops"] == 0 and body["audit"]["response_digest"]


def test_g10_role_context_is_partial_without_org_unit_and_explains_why(env):
    client, app = env
    upload(client, file([record(source_person_ref="synthetic-f08")]))     # real F08 pipeline: offered_role only
    with app.state.sessions() as db:
        sid = db.scalar(select(Subject.id).where(Subject.tenant_id == "tenant-a"))
    rebuild(client)
    body = role_context(client, sid, purpose="preboarding_support", **SUPPORT).json()
    assert body["result"] == "partial" and body["paths"][0]["hop_count"] == 1
    assert body["paths"][0]["hops"][0]["edge"]["provenance"]["source_system"] == "ATS"
    assert body["paths"][0]["hops"][0]["to"]["properties"]["role_ref"] == "synthetic-engineer"
    assert {x["predicate"] for x in body["exclusions"]} == {"org_unit", "manager_or_sponsor"}


# ----- AC05 blocker explanation -----

def test_g11_blocker_explanation_returns_path_reason_and_dependency_blocked_event(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    body = blockers(client, a).json()
    assert body["result"] == "blocked" and len(body["paths"]) == 1
    path = body["paths"][0]
    assert [h["edge"]["type"] for h in path["hops"]] == ["HAS_DEPENDENCY", "BLOCKED_BY"]
    assert path["blocked_task"]["properties"]["task_ref"] == "TASK-LAPTOP"
    assert path["blocking_dependency"]["properties"]["task_ref"] == "REQ-ACCOUNT"
    assert path["reason_code"] == "DEP_NOT_RESOLVED" and "account" in path["reason"]
    event = path["blocking_event"]
    assert event and event["event_type"] == "PreboardingDependencyBlocked"
    with app.state.sessions() as db:
        row = db.get(EventLedger, event["event_id"])
        assert row.event_type == "PreboardingDependencyBlocked" and row.claim_id == path["hops"][1]["edge"]["provenance"]["claim_id"]
        assert row.metadata_json["task_ref"] == "TASK-LAPTOP" and row.metadata_json["blocked_by_ref"] == "REQ-ACCOUNT"
        assert app.state.service.verify_ledger(db, a)
    assert len(body["dependencies"]) == 2            # the open TASK-BADGE is listed, not a blocker
    assert "PreboardingDependencyBlocked" in body["explanation"][0]


def test_g12_no_blocker_is_manufactured_from_open_dependencies_or_missing_state(env):
    client, app = env
    a, b, _ = seed(client); rebuild(client)
    body = blockers(client, b, account="candidate-b", roles="candidate").json()
    assert body["result"] == "no_blocker" and body["paths"] == [] and len(body["dependencies"]) == 1
    # Resolving A's blocker with a higher version removes the BLOCKED_BY edge after a rebuild.
    claim(client, a, mutation("preboarding_dependency_status",
                              {"dependencies": [{"task_ref": "TASK-LAPTOP", "status": "resolved"}]}, "ITSM", version=2))
    rebuild(client)
    assert blockers(client, a).json()["result"] == "no_blocker"
    d = import_subject(client, "p-d", "candidate-d").json()["subject_id"]
    rebuild(client)
    assert blockers(client, d, account="candidate-d", roles="candidate").json()["result"] == "no_dependency_state"


# ----- AC06 subject authorization -----

def test_g13_candidate_cannot_obtain_another_candidates_nodes_or_edges(env):
    client, app = env
    a, b, _ = seed(client); rebuild(client)
    denied = role_context(client, b)       # candidate-a asks for candidate-b's subject id
    assert denied.status_code == 404 and b not in denied.text and "CLOUD-OPS" not in denied.text
    assert blockers(client, b).status_code == 404
    # Own query of candidate-a never returns anything that belongs to B, even via shared Role R / Contact M.
    body = role_context(client, a).json()
    dump = json.dumps(body)
    assert b not in dump and "CLOUD-OPS" not in dump and "candidate-b" not in dump
    for h in all_hops(body):
        assert h["edge"]["provenance"]["claim_id"]
        with app.state.sessions() as db:
            assert db.get(Claim, h["edge"]["provenance"]["claim_id"]).subject_id == a


def test_g14_shared_role_and_contact_do_not_leak_across_candidates(env):
    client, app = env
    a, b, _ = seed(client); rebuild(client)
    a_body, b_body = role_context(client, a).json(), role_context(client, b, account="candidate-b", roles="candidate").json()
    role_a = a_body["paths"][0]["hops"][0]["to"]["node_id"]
    role_b = b_body["paths"][0]["hops"][0]["to"]["node_id"]
    assert role_a == role_b                                                    # one shared Role node
    assert a_body["paths"][0]["hops"][1]["to"]["properties"]["unit_ref"] == "DWP-RND"
    assert b_body["paths"][0]["hops"][1]["to"]["properties"]["unit_ref"] == "CLOUD-OPS"
    assert len(a_body["paths"][0]["hops"]) == 2 and len(b_body["paths"][0]["hops"]) == 2   # exactly one unit each
    with app.state.graph.sessions() as db:   # the store holds both ROLE_IN_UNIT edges from the shared Role
        assert db.scalar(select(func.count()).select_from(GraphEdge).where(
            GraphEdge.edge_type == "ROLE_IN_UNIT", GraphEdge.src_node_id == role_a)) == 2


def test_g15_candidate_without_account_binding_gets_no_graph(env):
    client, app = env
    upload(client, file([record(source_person_ref="synthetic-f08")]))
    with app.state.sessions() as db:
        sid = db.scalar(select(Subject.id))
    rebuild(client)
    assert role_context(client, sid, account="anyone", roles="candidate").status_code == 404
    assert role_context(client, sid, purpose="preboarding_support", **SUPPORT).status_code == 200


# ----- AC07 tenant authorization -----

def test_g16_foreign_tenant_requests_are_denied_without_existence_signal(env):
    client, app = env
    a, _, c = seed(client); rebuild(client); rebuild(client, tenant="tenant-b")
    for sid in (a, c):
        foreign = role_context(client, sid, purpose="preboarding_support", tenant="tenant-x", **SUPPORT)
        assert foreign.status_code == 404 and foreign.json() == {"detail": "subject not found"}
    cross = role_context(client, a, purpose="preboarding_support", tenant="tenant-b", **SUPPORT)
    assert cross.status_code == 404 and cross.json() == {"detail": "subject not found"}
    # An unknown subject id in the caller's own tenant is indistinguishable from a foreign one.
    unknown = role_context(client, "00000000-0000-0000-0000-000000000000", purpose="preboarding_support", **SUPPORT)
    assert unknown.status_code == 404 and unknown.json() == cross.json()
    # Shared reference values (role R, unit U1) exist in both tenants as separate nodes.
    a_unit = role_context(client, a).json()["paths"][0]["hops"][1]["to"]["node_id"]
    c_unit = role_context(client, c, tenant="tenant-b", account="candidate-c", roles="candidate").json()["paths"][0]["hops"][1]["to"]["node_id"]
    assert a_unit != c_unit
    admin_b = client.get("/graph/v1/projections/current", headers=headers(tenant="tenant-b", **ADMIN)).json()
    assert admin_b["node_count"] < client.get("/graph/v1/projections/current", headers=headers(**ADMIN)).json()["node_count"]
    assert a not in json.dumps(admin_b)


def test_g17_tenant_rebuild_only_touches_own_tenant(env):
    client, app = env
    a, _, c = seed(client); rebuild(client); rebuild(client, tenant="tenant-b")
    before = graph_rows(app, "tenant-b")
    claim(client, a, mutation("org_unit", {"unit_ref": "NEW"}, version=2)); rebuild(client)
    assert graph_rows(app, "tenant-b") == before


# ----- AC08 purpose authorization -----

@pytest.mark.parametrize("purpose", ["performance_evaluation", "recruitment_evaluation", "workforce_monitoring",
                                     "marketing", "model_training_cross_customer", "audit_reconstruction",
                                     "source_sync", "made_up_purpose"])
def test_g18_prohibited_unregistered_and_non_template_purposes_are_denied(env, purpose):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    for identity in (dict(account="candidate-a", roles="candidate"), SUPPORT, dict(account="aud", roles="auditor")):
        assert role_context(client, a, purpose=purpose, **identity).status_code == 403
        assert blockers(client, a, purpose=purpose, **identity).status_code == 403


def test_g19_client_cannot_upgrade_its_purpose(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    assert role_context(client, a, purpose="preboarding_support", account="candidate-a", roles="candidate").status_code == 403
    assert role_context(client, a, purpose="candidate_self_view", **SUPPORT).status_code == 403
    assert role_context(client, a, purpose="candidate_self_view", account="candidate-a", roles="candidate,support").status_code == 200


def test_g20_edges_and_provenance_not_authorized_for_the_purpose_are_excluded(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    # Restricted provenance: the candidate self-view never receives evidence_uri / source_record_id.
    self_view = json.dumps(role_context(client, a).json())
    assert "evidence_uri" not in self_view and "source_record_id" not in self_view and "localblob://" not in self_view
    support = json.dumps(role_context(client, a, purpose="preboarding_support", **SUPPORT).json())
    assert "evidence_uri" in support and "source_record_id" in support
    # Per-hop purpose exclusion: an edge whose allowed_purposes omit the purpose is dropped at traversal.
    with app.state.graph.sessions() as db:
        edge = db.scalar(select(GraphEdge).where(GraphEdge.edge_type == "ROLE_IN_UNIT", GraphEdge.subject_id == a))
        edge.allowed_purposes = ["preboarding_support"]
        db.commit()
    body = role_context(client, a).json()
    assert body["paths"][0]["hop_count"] == 1 and body["denied_hops"] == 1 and body["result"] == "partial"
    assert role_context(client, a, purpose="preboarding_support", **SUPPORT).json()["paths"][0]["hop_count"] == 2


# ----- AC09 server-side authorization / no arbitrary queries -----

@pytest.mark.parametrize("params", [
    {"purpose": "candidate_self_view", "cypher": "MATCH (n) RETURN n"},
    {"purpose": "candidate_self_view", "depth": "5"},
    {"purpose": "candidate_self_view", "edge_type": "HAS_CONTACT"},
    {"purpose": "candidate_self_view", "filter": "subject_id!=me"},
    {"purpose": "candidate_self_view", "q": "SELECT * FROM graph_edge"},
])
def test_g21_arbitrary_query_parameters_are_rejected(env, params):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    r = client.get(f"/graph/v1/subjects/{a}/role-context", params=params, headers=headers(account="candidate-a", roles="candidate"))
    assert r.status_code == 422 and "unexpected parameter" in r.text


def test_g22_unregistered_templates_bodies_and_query_strings_in_purpose_are_refused(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    h = headers(account="candidate-a", roles="candidate")
    assert client.get(f"/graph/v1/subjects/{a}/shortest-path", params={"purpose": "candidate_self_view"}, headers=h).status_code == 404
    assert client.get(f"/graph/v1/subjects/{a}/all-edges", params={"purpose": "candidate_self_view"}, headers=h).status_code == 404
    r = client.request("GET", f"/graph/v1/subjects/{a}/role-context", params={"purpose": "candidate_self_view"},
                       headers=h, content=b'{"cypher": "MATCH (n) RETURN n"}')
    assert r.status_code == 422
    injected = client.get(f"/graph/v1/subjects/{a}/role-context",
                          params={"purpose": "candidate_self_view' OR 1=1 --"}, headers=h)
    assert injected.status_code == 403
    assert client.get("/graph/v1/templates", headers=h).json()["client_query_expressions"] == "not accepted (AC09)"
    with app.state.graph.sessions() as db:
        outcomes = {(r.template_id, r.outcome) for r in db.scalars(select(GraphQueryAudit))}
        assert ("shortest_path", "unknown_template") in outcomes and ("all_edges", "unknown_template") in outcomes


def test_g23_unauthenticated_requests_are_rejected(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    assert client.get(f"/graph/v1/subjects/{a}/role-context", params={"purpose": "candidate_self_view"}).status_code == 422
    assert client.post("/graph/v1/projections/rebuild").status_code == 422
    assert client.get(f"/graph/v1/subjects/{a}/role-context", params={"purpose": "candidate_self_view"},
                      headers={"X-Tenant-ID": "tenant-a", "X-Account-ID": "x", "X-Roles": ""}).status_code == 401


def test_g24_rebuild_and_status_require_the_graph_administrator_role(env):
    client, app = env
    seed(client)
    for identity in (dict(account="candidate-a", roles="candidate"), SUPPORT, dict(account="da", roles="data_administrator")):
        assert rebuild(client, **identity).status_code == 403
        assert client.get("/graph/v1/projections/current", headers=headers(**identity)).status_code == 403
        assert client.post("/graph/v1/projections/verify", headers=headers(**identity)).status_code == 403
    assert rebuild(client).status_code == 200


# ----- AC10 deterministic rebuild / no canonical write privilege -----

def test_g25_drop_and_rebuild_from_the_same_canonical_state_is_identical(env):
    client, app = env
    seed(client)
    as_of = "2026-10-08T12:00:00Z"
    first = rebuild(client, as_of=as_of).json()
    rows_first = graph_rows(app)
    second = rebuild(client, as_of=as_of).json()
    rows_second = graph_rows(app)
    assert first["projection_id"] != second["projection_id"]           # a genuinely new projection run
    assert first["graph_hash"] == second["graph_hash"] == rows_first[0] == rows_second[0]
    assert rows_first == rows_second                                     # every node/edge/property identical
    assert first["canonical_fingerprint"] == second["canonical_fingerprint"]
    with app.state.graph.sessions() as db:
        statuses = sorted(p.status for p in db.scalars(select(GraphProjection).where(GraphProjection.tenant_id == "tenant-a")))
        assert statuses == ["active", "replaced"]
        assert db.scalar(select(func.count()).select_from(GraphNode).where(GraphNode.projection_id == first["projection_id"])) == 0
    verify = client.post("/graph/v1/projections/verify", headers=headers(**ADMIN)).json()
    assert verify["identical"] and verify["canonical_state_unchanged"]


def test_g26_duplicate_references_and_repeated_imports_do_not_duplicate_graph_elements(env):
    client, app = env
    raw = file([record(source_person_ref="synthetic-f08")])
    upload(client, raw); upload(client, raw); upload(client, file([record(source_person_ref="synthetic-f08")], snapshot_id="snapshot-2"))
    a, _, _ = seed(client)
    claim(client, a, mutation("offered_role", "synthetic-engineer", "ATS"))                 # same mutation replayed
    rebuild(client)
    with app.state.graph.sessions() as db:
        assert db.scalar(select(func.count()).select_from(GraphEdge).where(GraphEdge.edge_type == "OFFERED_ROLE")) == 3
        assert db.scalar(select(func.count()).select_from(GraphNode).where(GraphNode.node_type == "Role")) == 1
        ids = [e.edge_id for e in db.scalars(select(GraphEdge))]
        assert len(ids) == len(set(ids))


def test_g27_canonical_change_changes_the_graph_and_the_verify_endpoint_detects_it(env):
    client, app = env
    a, _, _ = seed(client)
    as_of = "2026-10-08T12:00:00Z"
    before = rebuild(client, as_of=as_of).json()
    claim(client, a, mutation("org_unit", {"unit_ref": "MOVED"}, version=2))
    verify = client.post("/graph/v1/projections/verify", headers=headers(**ADMIN)).json()
    assert verify["canonical_state_unchanged"] is False and verify["identical"] is False
    assert role_context(client, a).json()["stale"] is True            # read-time staleness signal
    after = rebuild(client, as_of=as_of).json()
    assert after["graph_hash"] != before["graph_hash"]
    assert role_context(client, a).json()["stale"] is False


def test_g28_graph_service_cannot_write_canonical_tables_in_process(env):
    client, app = env
    a, _, _ = seed(client)
    with app.state.graph.sessions() as db:
        subject = db.get(Subject, a)
        subject.restricted = True
        with pytest.raises(PermissionError, match="may not write table subject"):
            db.flush()
        db.rollback()
    with app.state.graph.sessions() as db:
        db.add(AuditLog(actor="x", tenant_id="tenant-a", purpose="p", operation="o", outcome="y", correlation_id="c"))
        with pytest.raises(PermissionError):
            db.flush()
        db.rollback()
    with app.state.sessions() as db:
        assert db.get(Subject, a).restricted is False


def test_g29_graph_role_has_no_canonical_write_privilege(postgres_database, tmp_path):
    """AC10 on PostgreSQL: the F03 login role from migrations/f03_graph_role.sql."""
    import secrets, uuid
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ProgrammingError
    from conftest import MIGRATIONS
    url = make_url(postgres_database)
    role, password = "edt_f03_" + uuid.uuid4().hex[:12], secrets.token_urlsafe(16)
    owner = create_engine(postgres_database)
    with owner.begin() as conn:
        try:
            conn.execute(text(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{password}'"))
        except ProgrammingError as exc:
            if getattr(exc.orig, "sqlstate", None) != "42501":
                raise
            pytest.skip("test user lacks CREATEROLE")
        schema = conn.execute(text("SELECT current_schema()")).scalar_one()
        conn.exec_driver_sql((MIGRATIONS / "f03_graph_role.sql").read_text().replace("edt_f03", role).replace("public", schema))
    restricted_url = url.set(username=role, password=password).render_as_string(hide_password=False)
    try:
        app = create_app(postgres_database, str(tmp_path / "evidence"), graph_database_url=restricted_url)
        with TestClient(app) as client:
            assert app.state.graph_engine is not app.state.engine
            a, _, _ = seed(client)
            assert rebuild(client).status_code == 200                       # graph tables writable
            assert role_context(client, a).json()["result"] == "complete"   # read-time gate works on SELECT only
            denied = [
                f"UPDATE subject SET restricted = true WHERE id = '{a}'",
                f"UPDATE claim SET status = 'superseded' WHERE subject_id = '{a}'",
                "SELECT count(*) FROM claim",
                "DELETE FROM event_ledger",
                "INSERT INTO audit_log (id, actor, tenant_id, purpose, operation, outcome, correlation_id, timestamp) "
                "VALUES ('x', 'a', 't', 'p', 'o', 'y', 'c', now())",
                "DELETE FROM mutation_receipt",
                "UPDATE import_run SET status = 'complete'",
            ]
            for statement in denied:
                with app.state.graph_engine.connect() as conn:
                    with pytest.raises(ProgrammingError, match="permission denied"):
                        conn.execute(text(statement))
            with app.state.graph_engine.connect() as conn:
                assert conn.execute(text("SELECT count(*) FROM graph_edge")).scalar_one() > 0
                assert conn.execute(text("SELECT count(*) FROM event_ledger")).scalar_one() > 0   # read-only is allowed
    finally:
        with owner.begin() as conn:
            conn.execute(text(f'REVOKE ALL ON ALL TABLES IN SCHEMA "{schema}" FROM "{role}"'))
            conn.execute(text(f'REVOKE ALL ON SCHEMA "{schema}" FROM "{role}"'))
            conn.execute(text(f'DROP ROLE "{role}"'))
        owner.dispose()


# ----- AC11 deployed, authenticated, auditable service -----

def test_g30_every_request_and_result_is_audited_without_values(env):
    client, app = env
    a, b, _ = seed(client); rebuild(client)
    ok = role_context(client, a).json()
    role_context(client, b)                                                        # denied
    role_context(client, a, purpose="performance_evaluation")                       # purpose denied
    blockers(client, a, purpose="preboarding_support", **SUPPORT)
    with app.state.graph.sessions() as db:
        rows = list(db.scalars(select(GraphQueryAudit).order_by(GraphQueryAudit.timestamp)))
        assert {(r.template_id, r.outcome, r.http_status) for r in rows} >= {
            ("projection_rebuild", "completed", 200), ("role_context", "allowed", 200), ("role_context", "denied", 404),
            ("role_context", "purpose_denied", 403), ("blocker_explanation", "allowed", 200)}
        allowed = next(r for r in rows if r.template_id == "role_context" and r.outcome == "allowed")
        assert allowed.actor == "candidate-a" and allowed.subject_id == a and allowed.purpose == "candidate_self_view"
        assert allowed.response_digest == ok["audit"]["response_digest"] and allowed.correlation_id == "test-request"
        assert set(allowed.edge_ids) == {h["edge"]["edge_id"] for h in all_hops(ok)}
        dump = json.dumps([{"a": r.actor, "e": r.edge_ids, "h": r.request_hash} for r in rows])
        assert "DWP-RND" not in dump and "mgr-007" not in dump and "synthetic-engineer" not in dump
    with app.state.sessions() as db:   # the F01 projection read is audited in F01's log under the F03 identity
        assert db.scalar(select(AuditLog).where(AuditLog.operation == "projection_snapshot", AuditLog.actor == "f03-projection"))


def test_g31_response_digest_matches_the_returned_body(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    body = role_context(client, a).json()
    audit = body.pop("audit")
    assert audit["response_digest"] == sha256(canonical(body))


def test_g32_health_openapi_and_versioned_contract_are_exposed(env):
    client, app = env
    assert client.get("/health").json()["status"] == "ok"
    spec = client.get("/openapi.json").json()
    paths = set(spec["paths"])
    assert {"/graph/v1/subjects/{subject_id}/role-context", "/graph/v1/subjects/{subject_id}/blocker-explanation",
            "/graph/v1/projections/rebuild", "/graph/v1/projections/verify", "/graph/v1/projections/current",
            "/graph/v1/ontology", "/graph/v1/templates"} <= paths


# ----- read-time safety before a rebuild (restriction / erasure) -----

def test_g33_restricted_or_erased_subject_is_not_served_from_a_stale_projection(env):
    client, app = env
    a, _, _ = seed(client); rebuild(client)
    assert role_context(client, a).status_code == 200
    with app.state.sessions() as db:
        db.get(Subject, a).restricted = True; db.commit()
    assert role_context(client, a).status_code == 403 and blockers(client, a).status_code == 403
    with app.state.sessions() as db:
        s = db.get(Subject, a); s.restricted = False; s.wrapped_key, s.key_reference = None, None; db.commit()
    assert role_context(client, a).status_code == 410
    rebuild(client)
    with app.state.graph.sessions() as db:
        assert not db.scalar(select(GraphNode).where(GraphNode.subject_id == a))       # dropped by the full rebuild
        assert db.scalar(select(GraphRejection).where(GraphRejection.subject_id == a, GraphRejection.reason_code == "ERASED"))


def test_g34_future_valid_claims_are_not_projected_until_valid(env):
    client, app = env
    a = import_subject(client, "p-a", "candidate-a").json()["subject_id"]
    claim(client, a, mutation("offered_role", "future-role", "ATS", valid_from="2027-01-01T00:00:00Z"))
    rebuild(client, as_of="2026-10-08T12:00:00Z")
    body = role_context(client, a).json()
    assert body["result"] == "no_context" and body["exclusions"][0] == {"predicate": "offered_role", "reason": "not_yet_valid"}
    rebuild(client, as_of="2027-06-01T00:00:00Z")
    assert role_context(client, a).json()["result"] == "partial"
