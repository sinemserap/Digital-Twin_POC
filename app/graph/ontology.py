"""F03 operational ontology registry (US40852 Part 1, AC01).

STATUS OF THIS REGISTRY — read before changing it.

No six-node / seven-relationship ontology is defined in EDT v3.1 (§4.1 is "Assumptions to
preserve"), in F01 (US40850) or in F08 (US40858). The only F03 relationship names that exist
in an agreed document are the five in F01 Part 1 §1.1 "Needed by":

    OFFERED_ROLE, ROLE_IN_UNIT, HAS_CONTACT, HAS_DEPENDENCY, BLOCKED_BY

Everything below is therefore a registry whose *mechanism* is approved by the story
(exactly six node types, exactly seven relationship types, reject anything else) and whose
*content* is the recommended proposal "ONTOLOGY-B" awaiting Design Authority approval
(see docs/F03_decisions.md, decision D-01). Changing the agreed content is a change to this
file and to ONTOLOGY_VERSION only; the projection, templates and tests are registry-driven.

Rules enforced by the registry:
  * Every node type and edge type is closed: an unregistered type is rejected, never added.
  * Every edge type names exactly one F01 predicate as its canonical source and the F01
    source systems that are authoritative for that predicate (F01 §1.1).
  * Every edge type carries the read purposes allowed for its predicate (F01 §1.1 default
    purposes). F03 applies these at query time (AC08) because the running F01 stores the
    *mutation* purpose in claim.purpose_ids, not the read purposes.
  * Skills / capabilities (UC-03), knowledge items (UC-05) and model outputs are not
    registered and are rejected by construction.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType

ONTOLOGY_ID = "edt-f03-poc-ontology-b"
ONTOLOGY_VERSION = "0.1.0-proposed"   # bump when the registry content is approved or changed
PROJECTION_RULES_VERSION = "f03-projection-1.0.0"
# projection_version stamped on every edge (AC03). It identifies the ontology + mapping rules,
# not the rebuild run, so that a rebuild from the same canonical state is byte-identical (AC10).
PROJECTION_VERSION = f"{ONTOLOGY_ID}@{ONTOLOGY_VERSION}/{PROJECTION_RULES_VERSION}"

READ_PURPOSES = ("preboarding_support", "candidate_self_view")


@dataclass(frozen=True)
class NodeType:
    name: str
    meaning: str
    key_fields: tuple[str, ...]          # fields that form the stable node key (after tenant)
    subject_bound: bool                  # True: one node per subject; False: shared context node
    source: str                          # where the node comes from
    allowed_purposes: tuple[str, ...] = READ_PURPOSES


@dataclass(frozen=True)
class EdgeType:
    name: str
    src: str
    dst: str
    meaning: str
    predicate: str | None                # F01 predicate that is the canonical source
    authoritative_sources: tuple[str, ...]   # F01 §1.1 authoritative source systems for the predicate
    allowed_purposes: tuple[str, ...]    # F01 §1.1 default read purposes for the predicate
    subject_scoped: bool = True          # every Part 1 edge belongs to exactly one subject
    properties: tuple[str, ...] = field(default_factory=tuple)


NODE_TYPES: MappingProxyType[str, NodeType] = MappingProxyType({
    "Person": NodeType("Person", "The preboarding subject (opaque F01 subject_id); no names.",
                       ("subject_id",), True, "F01 subject + subject_binding"),
    "Role": NodeType("Role", "The offered role, by role reference.", ("role_ref",), False,
                     "F01 offered_role (ATS via F08)"),
    "OrgUnit": NodeType("OrgUnit", "Organisational unit, by unit reference.", ("unit_ref",), False,
                        "F01 org_unit (HR/directory)"),
    "Contact": NodeType("Contact", "Accountable manager or sponsor contact; never a twin subject.",
                        ("contact_ref",), False, "F01 manager_or_sponsor (HR/directory)"),
    "Task": NodeType("Task", "A preboarding task or service dependency, by task reference.",
                     ("task_ref",), False, "F01 preboarding_dependency_status (ITSM/service)"),
    "Evidence": NodeType("Evidence", "An F01 evidence object (id + hash) that backs a claim.",
                         ("evidence_id",), True, "F01 claim.evidence_*"),
})

EDGE_TYPES: MappingProxyType[str, EdgeType] = MappingProxyType({
    "OFFERED_ROLE": EdgeType("OFFERED_ROLE", "Person", "Role",
        "The role offered to the person.", "offered_role", ("ATS",), READ_PURPOSES),
    "IN_UNIT": EdgeType("IN_UNIT", "Person", "OrgUnit",
        "The organisational unit the person is assigned to.", "org_unit", ("HR", "directory"), READ_PURPOSES),
    "ROLE_IN_UNIT": EdgeType("ROLE_IN_UNIT", "Role", "OrgUnit",
        "The offered role, as it applies to this person, sits in this unit (subject-scoped).",
        "org_unit", ("HR", "directory"), READ_PURPOSES),
    "HAS_CONTACT": EdgeType("HAS_CONTACT", "Person", "Contact",
        "The person's accountable manager or sponsor.", "manager_or_sponsor", ("HR", "directory"),
        READ_PURPOSES, properties=("relationship",)),
    "HAS_DEPENDENCY": EdgeType("HAS_DEPENDENCY", "Person", "Task",
        "A preboarding task/dependency recorded for the person.", "preboarding_dependency_status",
        ("ITSM", "service"), READ_PURPOSES, properties=("status",)),
    "BLOCKED_BY": EdgeType("BLOCKED_BY", "Task", "Task",
        "The task is blocked by the dependency task, with the blocking reason.",
        "preboarding_dependency_status", ("ITSM", "service"), READ_PURPOSES,
        properties=("reason_code", "reason")),
    "EVIDENCED_BY": EdgeType("EVIDENCED_BY", "Person", "Evidence",
        "The person's accepted claim is backed by this evidence object.", None, (), READ_PURPOSES,
        properties=("predicate",)),
})

# Predicates that may contribute to the graph (F01 §1.1 rows 2, 5, 6, 9) and their authority.
GRAPH_PREDICATES: MappingProxyType[str, tuple[str, ...]] = MappingProxyType({
    "offered_role": ("ATS",),
    "org_unit": ("HR", "directory"),
    "manager_or_sponsor": ("HR", "directory"),
    "preboarding_dependency_status": ("ITSM", "service"),
})

# The remaining seven F01 predicates are deliberately NOT graph sources in Part 1.
NON_GRAPH_PREDICATES = ("offer_status", "start_date", "work_location", "verified_channel",
                        "identity_assurance_state", "preferred_name", "communication_language")


def assert_registry_invariants() -> None:
    assert len(NODE_TYPES) == 6, "AC01: exactly six node types"
    assert len(EDGE_TYPES) == 7, "AC01: exactly seven relationship types"
    for edge in EDGE_TYPES.values():
        assert edge.src in NODE_TYPES and edge.dst in NODE_TYPES, edge.name
        if edge.predicate is not None:
            assert edge.predicate in GRAPH_PREDICATES, edge.name
            assert set(edge.authoritative_sources) == set(GRAPH_PREDICATES[edge.predicate]), edge.name


assert_registry_invariants()


def registry_document() -> dict:
    """Machine-readable registry for GET /graph/v1/ontology and for the technical package."""
    return {
        "ontology_id": ONTOLOGY_ID, "ontology_version": ONTOLOGY_VERSION,
        "projection_version": PROJECTION_VERSION, "status": "proposed-pending-design-authority",
        "node_types": [{"name": n.name, "meaning": n.meaning, "key": list(n.key_fields),
                        "subject_bound": n.subject_bound, "source": n.source,
                        "allowed_purposes": list(n.allowed_purposes)} for n in NODE_TYPES.values()],
        "edge_types": [{"name": e.name, "from": e.src, "to": e.dst, "meaning": e.meaning,
                        "predicate": e.predicate, "authoritative_sources": list(e.authoritative_sources),
                        "allowed_purposes": list(e.allowed_purposes), "subject_scoped": e.subject_scoped,
                        "properties": list(e.properties)} for e in EDGE_TYPES.values()],
        "graph_predicates": {k: list(v) for k, v in GRAPH_PREDICATES.items()},
        "excluded_predicates": list(NON_GRAPH_PREDICATES),
    }
