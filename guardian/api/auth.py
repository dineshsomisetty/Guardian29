"""API authentication + role-based authorization. Owner: Dev3/Dev1.

Two modes:

* **token mode** (production): `GUARDIAN_API_TOKENS="alice:<token>:approver,ci-bot:<token>:operator,..."`.
  Every request needs `Authorization: Bearer <token>` (the SSE route also accepts `?access_token=`, because
  the browser's EventSource cannot send headers). Tokens are compared in constant time against SHA-256
  digests; the raw tokens are not kept in memory after start-up and never logged.
* **local dev mode** (no tokens configured): anonymous, full access, and the server refuses to bind to
  anything but loopback (see `serve_api`), so only this machine can reach it.

Roles are ordered: viewer < operator < approver.
  viewer    read runs, findings, evidence, plans, the live trace, reports
  operator  + start runs
  approver  + decide at the human gate (approve / reject / accept risk)

The approver's *authenticated* name is what `approvals.jsonl` records as `decided_by` (G5, G7.1): a request
body cannot claim to be someone else.

Who uses it: guardian/api/app.py builds one `TokenStore` per app and calls `principal_for` in the app-wide viewer
dependency and again, with a higher role, inside the start-run and decision routes; `serve_api` calls `check_bind`.
Inputs: the GUARDIAN_API_TOKENS environment variable and each request's Authorization header (or query string
for SSE). Outputs: a `Principal` (name, role) or an HTTP 401/403.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from fastapi import HTTPException, Request

ROLES = ("viewer", "operator", "approver")  # lowest to highest privilege; a role includes all the ones before it
ENV = "GUARDIAN_API_TOKENS"


@dataclass(frozen=True)
class Principal:
    """An authenticated (or local-dev) caller. `authenticated` is False only for the anonymous local developer."""

    name: str
    role: str
    authenticated: bool

    def can(self, role: str) -> bool:
        """True if this principal's role is at least `role` (approver can do everything an operator can)."""
        return ROLES.index(self.role) >= ROLES.index(role)


# Used when no tokens are configured: full rights, but the server then only listens on loopback (see check_bind).
LOCAL_DEV = Principal(name="local-dev", role="approver", authenticated=False)


def _digest(token: str) -> bytes:
    """SHA-256 of a token: only digests are stored, so a memory dump does not reveal usable tokens."""
    return hashlib.sha256(token.encode("utf-8")).digest()


class TokenStore:
    """The configured API tokens, keyed by digest. An empty store means local dev mode (no authentication)."""

    def __init__(self, spec: str | None):
        """Parse `name:token:role,name:token:role,...`; raises ValueError on a malformed entry (fail at start-up
        rather than silently running with fewer users or weaker rules than the operator intended)."""
        self._by_digest: dict[bytes, Principal] = {}
        for raw in (spec or "").split(","):
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split(":")
            if len(parts) != 3:
                raise ValueError(f"{ENV}: entries are name:token:role (got {len(parts)} fields)")
            name, token, role = (p.strip() for p in parts)
            if role not in ROLES:
                raise ValueError(f"{ENV}: role for {name!r} must be one of {ROLES}")
            if len(token) < 16:
                raise ValueError(f"{ENV}: token for {name!r} is shorter than 16 characters")
            if not name.replace("-", "").replace("_", "").replace(".", "").isalnum():
                raise ValueError(f"{ENV}: name {name!r} may only use letters, digits, - _ .")
            self._by_digest[_digest(token)] = Principal(name=name, role=role, authenticated=True)

    @classmethod
    def from_env(cls) -> TokenStore:
        """Build the store from GUARDIAN_API_TOKENS (unset = empty = local dev mode)."""
        return cls(os.environ.get(ENV))

    @property
    def enabled(self) -> bool:
        """True in token mode (at least one token configured)."""
        return bool(self._by_digest)

    def lookup(self, token: str) -> Principal | None:
        """The principal owning `token`, or None. Compares against every entry so timing does not leak a match."""
        want = _digest(token)
        found = None
        for d, p in self._by_digest.items():  # constant time per entry; no early exit on match
            if hmac.compare_digest(d, want):
                found = p
        return found


def _token_from(request: Request, allow_query: bool) -> str | None:
    """Extract the bearer token from the Authorization header; the query string only if `allow_query` (SSE).
    Query tokens end up in URLs and logs, so they are accepted on that one route only."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    if allow_query:
        return request.query_params.get("access_token") or None
    return None


def principal_for(request: Request, store: TokenStore, role: str, *, allow_query: bool = False) -> Principal:
    """The caller, or 401/403. In local dev mode everyone is the local developer (loopback-only server)."""
    if not store.enabled:
        return LOCAL_DEV
    token = _token_from(request, allow_query)
    if not token:
        raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})
    p = store.lookup(token)
    if p is None:
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    if not p.can(role):
        raise HTTPException(403, f"role {p.role!r} cannot do this (needs {role})")
    return p


# Hosts that only this machine can reach; anything else counts as "exposed to the network".
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def check_bind(host: str, store: TokenStore) -> None:
    """Refuse to expose an unauthenticated API beyond this machine."""
    if host not in LOOPBACK and not store.enabled:
        raise SystemExit(f"refusing to bind {host} without authentication: set {ENV} (name:token:role,...)")
