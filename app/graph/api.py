"""F03 HTTP contract (OpenAPI via FastAPI): versioned, template-only, no query expressions.

GET  /graph/v1/ontology                                   registry (any authenticated identity)
GET  /graph/v1/templates                                  approved templates
GET  /graph/v1/subjects/{subject_id}/role-context         Template A  ?purpose=
GET  /graph/v1/subjects/{subject_id}/blocker-explanation  Template B  ?purpose=
POST /graph/v1/projections/rebuild                        full deterministic rebuild (graph_administrator)
POST /graph/v1/projections/verify                         dry-run rebuild comparison (graph_administrator)
GET  /graph/v1/projections/current                        active projection summary (graph_administrator)

Only `purpose` (and, for rebuild, an optional `as_of`) are accepted as parameters. Any other
query parameter, and any request body on the template endpoints, is rejected with 422 so that
no traversal parameter, filter or query fragment can be supplied by a client (AC09).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import AwareDatetime, BaseModel, ConfigDict

from ..auth import authenticated_identity

def correlation(x_correlation_id: str | None = Header(None)):
    return x_correlation_id or str(uuid.uuid4())


class RebuildRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    as_of: AwareDatetime | None = None


def _only(request: Request, allowed: set[str]):
    extra = set(request.query_params.keys()) - allowed
    if extra:
        raise HTTPException(422, f"unexpected parameter(s): {sorted(extra)}; only {sorted(allowed)} are accepted")


async def _no_body(request: Request):
    if request.headers.get("content-length") not in (None, "0"):
        raise HTTPException(422, "request body is not accepted on query templates")


def build_router(graph):
    # A fresh router per application instance: routes close over this app's GraphService.
    router = APIRouter(prefix="/graph/v1", tags=["F03 operational relationship graph"])

    @router.get("/ontology")
    def ontology(identity=Depends(authenticated_identity)):
        return graph.ontology()

    @router.get("/templates")
    def templates(identity=Depends(authenticated_identity)):
        return graph.templates()

    @router.get("/subjects/{subject_id}/role-context")
    async def role_context(subject_id: str, request: Request, purpose: str = Query(..., min_length=1, max_length=80),
                           identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        _only(request, {"purpose"}); await _no_body(request)
        return graph.run_template(identity, "role_context", subject_id, purpose, request_id)

    @router.get("/subjects/{subject_id}/blocker-explanation")
    async def blocker_explanation(subject_id: str, request: Request, purpose: str = Query(..., min_length=1, max_length=80),
                                  identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        _only(request, {"purpose"}); await _no_body(request)
        return graph.run_template(identity, "blocker_explanation", subject_id, purpose, request_id)

    @router.get("/subjects/{subject_id}/{template_id}")
    def unknown_template(subject_id: str, template_id: str, request: Request,
                         identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        # Anything that is not one of the two approved templates is refused and audited.
        return graph.run_template(identity, template_id.replace("-", "_"), subject_id,
                                  request.query_params.get("purpose", "-"), request_id)

    @router.post("/projections/rebuild")
    def rebuild(body: RebuildRequest | None = None, identity=Depends(authenticated_identity),
                request_id=Depends(correlation)):
        return graph.rebuild(identity, request_id, body.as_of if body else None)

    @router.post("/projections/verify")
    def verify(identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        return graph.verify(identity, request_id)

    @router.get("/projections/current")
    def current(identity=Depends(authenticated_identity), request_id=Depends(correlation)):
        return graph.current(identity, request_id)

    return router
