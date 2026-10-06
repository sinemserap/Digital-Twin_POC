from fastapi import Header, HTTPException
from .security import Identity


def authenticated_identity(
    x_tenant_id: str = Header(...), x_account_id: str = Header(...), x_roles: str = Header(...)
) -> Identity:
    """Mock auth boundary. Replace this dependency with Entra JWT validation in deployment."""
    roles = frozenset(x.strip() for x in x_roles.split(",") if x.strip())
    if not roles:
        raise HTTPException(401, "authenticated role required")
    return Identity(x_tenant_id, x_account_id, roles)

