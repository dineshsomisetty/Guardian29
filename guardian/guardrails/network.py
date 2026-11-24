"""G3.5 network allowlist: guardian code only talks to a fixed set of hosts. Owner: Dev1.

`check_url` is called before every outbound HTTP request made from guardian code (registry metadata, GitHub
ref lookups, the configured LLM endpoint). A host outside the allowlist raises `NetworkBlocked` and writes a
`guardrail` event (data.rule = "G3.5"). Only https is accepted (http only for the configured LLM host, e.g. a local model server).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from guardian.core.audit import AuditLog

if TYPE_CHECKING:
    from guardian.core.config import Settings
    from guardian.tools.registry import ToolContext

# GUARDIAN_PLAN.md §14
ALLOWED_HOSTS = frozenset({
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "api.osv.dev",
    "api.first.org",
    "www.cisa.gov",
    "api.deps.dev",
    "github.com",
    "api.github.com",
})


class NetworkBlocked(Exception):
    pass


def allowed_hosts(settings: Settings | None = None, extra_hosts: Iterable[str] = ()) -> set[str]:
    hosts = set(ALLOWED_HOSTS)
    if settings is not None:
        if settings.llm_base_url:
            host = urlsplit(settings.llm_base_url).hostname
            if host:
                hosts.add(host.lower())
        if settings.llm_provider == "anthropic":
            hosts.add("api.anthropic.com")
    hosts.update(h.lower() for h in extra_hosts if h)
    return hosts


def check_url(url: str, *, settings: Settings | None = None, extra_hosts: Iterable[str] = (),
              ctx: ToolContext | None = None, audit: AuditLog | None = None, agent: str = "guardrail") -> str:
    """Return `url` if its host is allowlisted, else emit a G3.5 guardrail event and raise NetworkBlocked."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if settings is None and ctx is not None:
        settings = ctx.settings
    reason = None
    llm_hosts = {h.lower() for h in extra_hosts if h}
    if settings is not None and settings.llm_base_url:
        llm_hosts.add((urlsplit(settings.llm_base_url).hostname or "").lower())
    if parts.scheme not in {"https", "http"} or (parts.scheme == "http" and host not in llm_hosts):
        # plain http only for the configured LLM endpoint (a local model server)
        reason = f"scheme {parts.scheme or '(none)'!r} is not https"
    elif parts.username or parts.password:
        reason = "credentials in URL"
    elif host not in allowed_hosts(settings, extra_hosts):
        reason = f"host {host or '(none)'!r} is not in the network allowlist"
    if reason is None:
        return url
    if audit is None and ctx is not None:
        audit = AuditLog(ctx.run_dir, ctx.run_id, echo=False)
    if audit is not None:
        audit.emit("guardrail", "guardrail", f"G3.5 blocked request to {host or url[:80]}: {reason}",
                   data={"rule": "G3.5", "host": host, "agent": agent, "reason": reason})
    raise NetworkBlocked(f"G3.5: {reason}")
