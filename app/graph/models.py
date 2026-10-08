"""F03 derived graph store (relational property-graph tables, PostgreSQL / SQLite).

These tables are a *derived projection*: they are dropped and rebuilt from F01 and are never
a source of truth. The F03 database role (migrations/f03_graph_role.sql) may write these
tables only; it has no write privilege on any canonical table (AC10).

Technology note: F01 §1.6 records "F03 (Apache AGE) in the same database" as
[ASSUMPTION — DA-10]; DA-10 is open in v3.1 §31. Part 1 therefore stores the projection as
plain PostgreSQL tables behind the GraphStore interface in service.py so that an AGE/openCypher
backend can replace the storage without changing the ontology, provenance or templates.
"""
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from ..database import Base
from ..models import utcnow, uuid_str

GRAPH_TABLES = frozenset({"graph_projection", "graph_node", "graph_edge", "graph_rejection",
                          "graph_query_audit"})


class GraphProjection(Base):
    """One rebuild run per tenant; only the row with status='active' has nodes/edges."""
    __tablename__ = "graph_projection"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    projection_version: Mapped[str] = mapped_column(String(160))
    ontology_version: Mapped[str] = mapped_column(String(64))
    # Validity instant the accepted claims were evaluated against (input of the projection).
    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Fingerprint of the canonical state that was projected (ordered ledger hashes).
    canonical_fingerprint: Mapped[str] = mapped_column(String(64))
    canonical_event_count: Mapped[int] = mapped_column(Integer)
    graph_hash: Mapped[str] = mapped_column(String(64))
    node_count: Mapped[int] = mapped_column(Integer)
    edge_count: Mapped[int] = mapped_column(Integer)
    rejected_count: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), index=True)   # active | replaced | failed
    actor: Mapped[str] = mapped_column(String(128))
    correlation_id: Mapped[str] = mapped_column(String(128))
    built_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    replaced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class GraphNode(Base):
    __tablename__ = "graph_node"
    __table_args__ = (UniqueConstraint("projection_id", "node_id", name="uq_graph_node"),
                      Index("ix_graph_node_lookup", "projection_id", "tenant_id", "node_type"))
    projection_id: Mapped[str] = mapped_column(ForeignKey("graph_projection.id"), primary_key=True)
    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)   # sha256(tenant|type|key)
    tenant_id: Mapped[str] = mapped_column(String(128))
    node_type: Mapped[str] = mapped_column(String(40))
    node_key: Mapped[str] = mapped_column(String(512))
    # Subject that owns the node (Person, Evidence); NULL for shared context nodes.
    subject_id: Mapped[str | None] = mapped_column(String(36), index=True)
    properties: Mapped[dict] = mapped_column(JSON)
    allowed_purposes: Mapped[list] = mapped_column(JSON)


class GraphEdge(Base):
    __tablename__ = "graph_edge"
    __table_args__ = (UniqueConstraint("projection_id", "edge_id", name="uq_graph_edge"),
                      Index("ix_graph_edge_subject", "projection_id", "tenant_id", "subject_id"))
    projection_id: Mapped[str] = mapped_column(ForeignKey("graph_projection.id"), primary_key=True)
    edge_id: Mapped[str] = mapped_column(String(64), primary_key=True)   # sha256(tenant|type|src|dst|claim)
    tenant_id: Mapped[str] = mapped_column(String(128))
    edge_type: Mapped[str] = mapped_column(String(40))
    src_node_id: Mapped[str] = mapped_column(String(64))
    dst_node_id: Mapped[str] = mapped_column(String(64))
    # Every Part 1 edge belongs to exactly one subject: the subject whose accepted claim created it.
    subject_id: Mapped[str] = mapped_column(String(36))
    # Provenance (AC03): the accepted canonical reference that justifies the edge.
    claim_id: Mapped[str] = mapped_column(String(36))
    event_id: Mapped[str] = mapped_column(String(36))
    event_type: Mapped[str] = mapped_column(String(80))
    event_sequence: Mapped[int] = mapped_column(Integer)
    event_hash: Mapped[str] = mapped_column(String(64))
    source_system: Mapped[str] = mapped_column(String(128))
    source_record_id: Mapped[str] = mapped_column(String(256))
    source_version: Mapped[int] = mapped_column(Integer)
    evidence_id: Mapped[str] = mapped_column(String(36))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    evidence_uri: Mapped[str] = mapped_column(String(1024))
    valid_from: Mapped[str] = mapped_column(String(40))     # ISO-8601 UTC text: exact rebuild equality
    valid_to: Mapped[str | None] = mapped_column(String(40))
    projection_version: Mapped[str] = mapped_column(String(160))
    allowed_purposes: Mapped[list] = mapped_column(JSON)
    properties: Mapped[dict] = mapped_column(JSON)


class GraphRejection(Base):
    """Records excluded from the projection: identifiers and reason codes only, never values."""
    __tablename__ = "graph_rejection"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    projection_id: Mapped[str] = mapped_column(ForeignKey("graph_projection.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    subject_id: Mapped[str | None] = mapped_column(String(36))
    predicate: Mapped[str | None] = mapped_column(String(80))
    claim_id: Mapped[str | None] = mapped_column(String(36))
    reason_code: Mapped[str] = mapped_column(String(40))
    detail: Mapped[str | None] = mapped_column(Text)


class GraphQueryAudit(Base):
    """AC11: every template request and its result are auditable without storing values."""
    __tablename__ = "graph_query_audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uuid_str)
    actor: Mapped[str] = mapped_column(String(128))
    tenant_id: Mapped[str] = mapped_column(String(128), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(36), index=True)
    purpose: Mapped[str] = mapped_column(String(80))
    template_id: Mapped[str] = mapped_column(String(80))
    template_version: Mapped[str] = mapped_column(String(20))
    operation: Mapped[str] = mapped_column(String(40))
    outcome: Mapped[str] = mapped_column(String(40))
    http_status: Mapped[int] = mapped_column(Integer)
    request_hash: Mapped[str] = mapped_column(String(64))
    response_digest: Mapped[str | None] = mapped_column(String(64))
    projection_id: Mapped[str | None] = mapped_column(String(36))
    edge_ids: Mapped[list | None] = mapped_column(JSON)
    correlation_id: Mapped[str] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
