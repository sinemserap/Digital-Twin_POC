import uuid
from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import AwareDatetime
from sqlalchemy import select
from .auth import authenticated_identity
from .config import Settings
from .constants import ALLOWED_PURPOSES, AUTHORITATIVE, DENIED_PURPOSES, PREDICATES
from .database import Base, build_engine, build_session_factory
from .evidence import AzureBlobEvidenceStore, LocalEvidenceStore
from .models import Claim, PredicateRegistry, PurposeRegistry
from .schemas import ClaimMutation, SubjectImport
from .security import LocalKeyProtector
from .service import ClaimService, F01ImportContract, F01ProjectionContract
from .importer import ControlledImporter
from .source_registry import default_registry
from .graph.api import build_router as build_graph_router
from .graph.service import GraphService


def create_app(database_url: str | None = None, evidence_dir: str | None = None, key_protector=None,
               source_registry=None, malware_scanner=None, import_database_url: str | None = None,
               graph_database_url: str | None = None):
    settings = Settings()
    engine = build_engine(database_url or settings.database_url)
    # The F08 adapter runs on its own database identity when configured: a role granted
    # only the F08 operational tables (design §1.11). Without it the demo shares the engine.
    import_url = import_database_url or (settings.import_database_url if database_url is None else None)
    import_engine = build_engine(import_url) if import_url else engine
    # The F03 graph service likewise runs on its own identity (migrations/f03_graph_role.sql):
    # read-only on subject/subject_binding/event_ledger, read-write on graph_* only (AC10).
    graph_url = graph_database_url or (settings.graph_database_url if database_url is None else None)
    graph_engine = build_engine(graph_url) if graph_url else engine
    sessions = build_session_factory(engine)
    evidence = (AzureBlobEvidenceStore(settings.azure_blob_connection_string, settings.azure_blob_container)
                if settings.azure_blob_connection_string and evidence_dir is None
                else LocalEvidenceStore(evidence_dir or settings.evidence_dir))
    service = ClaimService(sessions, evidence, key_protector or LocalKeyProtector())

    @asynccontextmanager
    async def lifespan(app):
        Base.metadata.create_all(engine)
        with sessions() as db:
            for predicate in PREDICATES:
                if not db.get(PredicateRegistry, predicate):
                    db.add(PredicateRegistry(predicate=predicate,
                        required_claim_class="authoritative" if predicate in AUTHORITATIVE else "self_declared"))
            for purpose, (operation, roles) in ALLOWED_PURPOSES.items():
                if not db.get(PurposeRegistry, purpose):
                    db.add(PurposeRegistry(purpose=purpose, operation=operation,
                        required_role=",".join(sorted(roles)), allowed=True))
            for purpose in DENIED_PURPOSES:
                if not db.get(PurposeRegistry, purpose):
                    db.add(PurposeRegistry(purpose=purpose, operation="none", required_role="none", allowed=False))
            db.commit()
        yield
        engine.dispose()
        if import_engine is not engine:
            import_engine.dispose()
        if graph_engine is not engine:
            graph_engine.dispose()

    app = FastAPI(title="Claim and Evidence Service", version="0.1.0", lifespan=lifespan)
    app.state.engine, app.state.sessions, app.state.service = engine, sessions, service

    def correlation(x_correlation_id: str | None = Header(None)):
        return x_correlation_id or str(uuid.uuid4())

    # The adapter receives only the F01 import contract, never the service or its sessions.
    importer = ControlledImporter(import_engine, F01ImportContract(service), source_registry or default_registry(),
                                  malware_scanner)
    app.state.importer, app.state.import_engine = importer, import_engine
    # F03 receives only the read-only F01 projection contract, never the service or its sessions.
    graph = GraphService(graph_engine, F01ProjectionContract(service))
    app.state.graph, app.state.graph_engine = graph, graph_engine
    app.include_router(build_graph_router(graph))

    @app.post('/imports/{source_system_id}')
    async def import_file(source_system_id: str, request: Request, identity=Depends(authenticated_identity),
                          request_id=Depends(correlation)):
        importer.authorize(identity)
        if request.headers.get('content-type', '').split(';')[0] != 'application/x-ndjson':
            raise HTTPException(415, 'JSONL_REQUIRED')
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > importer.MAX_BYTES:
                raise HTTPException(413, 'FILE_SIZE_INVALID')
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(importer.import_file, identity, source_system_id, bytes(raw), request_id)

    @app.get('/imports/{source_system_id}/freshness')
    def source_freshness(source_system_id: str, identity=Depends(authenticated_identity)):
        return importer.freshness(identity, source_system_id)

    @app.get("/health")
    def health(): return {"status": "ok", "service": "Claim and Evidence Service"}

    @app.post("/subjects", status_code=201)
    def import_subject(body: SubjectImport, identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        return service.import_subject(identity, body, request_id)

    @app.post("/subjects/{subject_id}/claims", status_code=201)
    def mutate(subject_id: str, body: ClaimMutation, identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        return service.mutate(identity, subject_id, body, request_id)

    @app.get("/subjects/{subject_id}/twin")
    def twin(subject_id: str, purpose: str = Query(...), identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        return service.twin(identity, subject_id, purpose, request_id)

    @app.get("/subjects/{subject_id}/twin/history")
    def historical_twin(subject_id: str, valid_at: AwareDatetime = Query(...),
                        system_at: AwareDatetime = Query(...), purpose: str = Query(...),
                        identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        return service.historical_twin(identity, subject_id, purpose, valid_at, system_at, request_id)

    @app.get("/subjects/{subject_id}/evidence/{evidence_id}")
    def read_evidence(subject_id: str, evidence_id: str, purpose: str = Query(...),
                      identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        with sessions() as db:
            service.authorize(db, identity, purpose, "read", subject_id, request_id)
            subject = service._subject(db, identity, subject_id, purpose, "read", request_id)
            claim = db.scalar(select(Claim).where(Claim.subject_id == subject_id, Claim.evidence_id == evidence_id))
            if not claim:
                service.audit(db, identity, subject_id, purpose, "evidence_read", "not_found", request_id)
                db.commit(); raise HTTPException(404, "evidence not found")
            key = service.keys.unwrap(subject.id, subject.wrapped_key, subject.key_reference)
            try:
                content = service.evidence.read_verified(claim.evidence_uri, claim.evidence_id, claim.evidence_hash, key)
            except ValueError:
                service.audit(db, identity, subject_id, purpose, "evidence_read", "integrity_failure", request_id)
                db.commit(); raise HTTPException(409, "evidence integrity verification failed")
            service.audit(db, identity, subject_id, purpose, "evidence_read", "allowed", request_id)
            db.commit()
            return Response(content, media_type="application/octet-stream")

    return app


app = create_app()

