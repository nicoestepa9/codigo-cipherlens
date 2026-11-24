"""Politica de escritura por rol, aplicada antes de resolver cada endpoint."""

from __future__ import annotations

import re
from dataclasses import dataclass

from fastapi import HTTPException

WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
USER_ROLES = frozenset({"viewer", "user", "lead", "admin", "operator"})
OPERATIONAL_ROLES = frozenset({"user", "lead", "admin"})
ADMIN_ROLES = frozenset({"admin"})
AGENT_ROLES = frozenset({"agent"})
OPERATOR_ROLES = frozenset({"operator"})

ROLE_ALIASES = {"analyst": "lead"}

OPERATOR_ALLOWED_PREFIXES = (
    "/api/auth",
    "/api/organizations",
    "/api/users/me",
)
OPERATOR_ALLOWED_PATHS = frozenset({"/", "/health", "/docs", "/redoc", "/openapi.json"})


def operator_path_allowed(path: str) -> bool:
    """Rutas disponibles para un operador de plataforma (sin scope tenant)."""
    if path in OPERATOR_ALLOWED_PATHS:
        return True
    return any(
        path == prefix or path.startswith(f"{prefix}/")
        for prefix in OPERATOR_ALLOWED_PREFIXES
    )


def canonical_role(role: str | None) -> str:
    value = (role or "").strip().lower()
    return ROLE_ALIASES.get(value, value)


@dataclass(frozen=True)
class WritePolicy:
    name: str
    methods: frozenset[str]
    pattern: re.Pattern[str]
    roles: frozenset[str]
    public: bool = False

    def matches(self, method: str, path: str) -> bool:
        return method.upper() in self.methods and self.pattern.fullmatch(path) is not None


def _policy(
    name: str,
    methods: str | set[str],
    pattern: str,
    roles: set[str] | frozenset[str],
    *,
    public: bool = False,
) -> WritePolicy:
    return WritePolicy(
        name=name,
        methods=frozenset({methods} if isinstance(methods, str) else methods),
        pattern=re.compile(pattern),
        roles=frozenset(roles),
        public=public,
    )


WRITE_POLICIES: tuple[WritePolicy, ...] = (
    _policy("auth", "POST", r"/api/auth/(?:login|refresh|logout|bootstrap)", set(), public=True),
    _policy(
        "users-self",
        {"PATCH", "DELETE"},
        r"/api/users/me",
        USER_ROLES,
    ),
    _policy(
        "users-self-password",
        "POST",
        r"/api/users/me/password",
        USER_ROLES,
    ),
    _policy(
        "agent-ingest",
        "POST",
        r"/api/agent/(?:heartbeat|tasks/claim|tasks/[^/]+/status|ingest/scan|ingest/discovery)",
        AGENT_ROLES,
    ),
    _policy("users-admin", {"POST"}, r"/api/users", ADMIN_ROLES),
    _policy("users-admin", {"PATCH", "DELETE"}, r"/api/users/[^/]+", ADMIN_ROLES),
    _policy("teams-admin", {"POST"}, r"/api/teams", ADMIN_ROLES),
    _policy("teams-admin", {"PATCH", "DELETE"}, r"/api/teams/[^/]+", ADMIN_ROLES),
    _policy(
        "teams-lead-members",
        {"POST", "DELETE"},
        r"/api/teams/[^/]+/members(?:/[^/]+)?",
        OPERATIONAL_ROLES - {"user"},
    ),
    _policy("settings-admin", {"PUT", "GET"}, r"/api/settings/.*", ADMIN_ROLES),
    _policy("cves-admin", "POST", r"/api/cves/refresh", ADMIN_ROLES),
    _policy("api-keys-admin", {"POST", "DELETE"}, r"/api/api-keys(?:/[^/]+)?", ADMIN_ROLES),
    _policy(
        "agents-admin",
        {"POST", "PATCH", "DELETE"},
        r"/api/agents(?:/[^/]+)?(?:/rotate-key)?",
        ADMIN_ROLES,
    ),
    _policy(
        "agent-tasks-lead",
        "DELETE",
        r"/api/agent-tasks/[^/]+",
        OPERATIONAL_ROLES - {"user"},
    ),
    _policy(
        "services-owner-admin",
        "PATCH",
        r"/api/services/[^/]+/owner",
        ADMIN_ROLES,
    ),
    _policy("scans-operational", "POST", r"/api/scans", OPERATIONAL_ROLES),
    _policy("crypto-ml-operational", "POST", r"/api/crypto-ml/analyze", OPERATIONAL_ROLES),
    _policy(
        "discovery-operational",
        {"POST", "DELETE"},
        r"/api/discovery(?:/[^/]+)?",
        OPERATIONAL_ROLES,
    ),
    _policy(
        "recurring-scans-operational",
        {"POST", "PATCH", "DELETE"},
        r"/api/recurring-scans(?:/[^/]+)?(?:/run-now)?",
        OPERATIONAL_ROLES,
    ),
    _policy(
        "alerts-operational",
        "PUT",
        r"/api/alerts/[^/]+/status",
        OPERATIONAL_ROLES,
    ),
    _policy(
        "issues-operational",
        {"PATCH", "POST"},
        r"/api/issues(?:/[^/]+)?(?:/comment|/assign)?",
        OPERATIONAL_ROLES,
    ),
    _policy(
        "organizations-operator",
        {"POST", "PUT", "PATCH", "DELETE"},
        r"/api/organizations(?:/[^/]+)?(?:/.*)?",
        OPERATOR_ROLES,
    ),
    _policy(
        "assets-operational",
        {"POST", "GET", "DELETE"},
        r"/api/assets(?:/[^/]+)?",
        OPERATIONAL_ROLES,
    ),
)


def resolve_write_policy(method: str, path: str) -> WritePolicy | None:
    for policy in WRITE_POLICIES:
        if policy.matches(method, path):
            return policy
    return None


def route_path(path: str) -> str:
    """Normaliza parametros de ruta de FastAPI para compararlos con la politica."""
    return re.sub(r"\{[^}]+\}", "route-param", path)


def authorize_write(role: str | None, method: str, path: str) -> None:
    if method.upper() not in WRITE_METHODS:
        return
    policy = resolve_write_policy(method, path)
    if policy is None:
        raise HTTPException(status_code=403, detail="Write operation not allowed")
    if policy.public:
        return
    if canonical_role(role) not in policy.roles:
        raise HTTPException(status_code=403, detail="Insufficient role")
