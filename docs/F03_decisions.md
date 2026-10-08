# F03 Operational Relationship Graph — Part 1 (US40852): decision register

Status legend: **APPROVED** (in an agreed document), **POC-DECISION** (adopted for the PoC, recorded in F08 §3
style), **PROVISIONAL** (implemented so the service runs, awaiting Design Authority / product-owner approval),
**OPEN** (Design Authority decision in v3.1 §31).

| ID | Decision | Status | Position implemented on this branch | Source |
|---|---|---|---|---|
| D-01 | Graph ontology content (6 node / 7 relationship types) | PROVISIONAL | `app/graph/ontology.py` "ONTOLOGY-B": Person, Role, OrgUnit, Contact, Task, Evidence; OFFERED_ROLE, IN_UNIT, ROLE_IN_UNIT, HAS_CONTACT, HAS_DEPENDENCY, BLOCKED_BY, EVIDENCED_BY. Registry-driven; changing content is a config change. | No ontology in v3.1 (§4.1 = assumptions), F01 or F08; five names from F01 §1.1 "Needed by" |
| D-02 | "knowledge relationships" in the story description | OPEN | No F01 predicate / source exists for knowledge items (UC-05). Not projected. | US40852 description vs F01 §1.1 |
| D-03 | Value schemas for org_unit, manager_or_sponsor, preboarding_dependency_status | PROVISIONAL | `app/dependency_schema.py` and `_ref()` in `app/graph/projection.py`; invalid shapes are rejected (INVALID_VALUE), never fabricated | F01 §1.1 registers the predicates without value shapes |
| D-04 | Source of the `PreboardingDependencyBlocked` event required by AC05 | PROVISIONAL | F01-EXT-01 (commit "F01-EXT-01"): F01 derives PreboardingDependencyBlocked/Resolved ledger events from an accepted current `preboarding_dependency_status` claim. Isolated commit, droppable. | v3.1 §18 lists the event only as illustrative; F01 Part 1 emits five event kinds |
| D-05 | Graph technology for Part 1 | POC-DECISION pending DA-10 | Relational property-graph tables in the F01 PostgreSQL (migration 004) behind the GraphStore boundary; Apache AGE deferred to DA-10 | F01 §1.6 [ASSUMPTION — DA-10]; v3.1 §31 DA-10 open |
| D-06 | Provenance fields withheld from candidate_self_view | PROVISIONAL | `evidence_uri`, `source_record_id` hidden for candidate_self_view (`RESTRICTED_PROVENANCE`) | v3.1 §22 "protect confidential source metadata" |
| D-07 | Audit content for AC11 | PROVISIONAL | Identifiers + request hash + response digest + edge ids; no values, no full bodies | v3.1 §19 logging minimisation vs AC11 "requests and responses must be auditable" |
| D-08 | Projection read purpose / identity | PROVISIONAL | F03 reads accepted state under `preboarding_support` with role `projection_service` (added to F01 purpose registry roles) | F01 §1.4 "preboarding_support — Used by Operator, F03" |
| D-09 | Residual plaintext references in graph tables after erasure until the next full rebuild | OPEN (privacy acceptance) | Read-time gate blocks serving immediately (403/410); rows are dropped by the next full rebuild; incremental invalidation is US41278 | US40852 out-of-scope list; v3.1 §22 withdrawal workflow |
| D-10 | ROLE_IN_UNIT semantics | PROVISIONAL | Subject-scoped derived edge (Role→OrgUnit for this person), provenance = org_unit claim; shared Role node never leaks another person's unit | F01 §1.1 "F03 ROLE_IN_UNIT" |
