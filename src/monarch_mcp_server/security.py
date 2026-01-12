"""Security hardening helpers for the Monarch Money MCP server.

Key goals:
- Ensure TLS certificate verification is enabled for outbound HTTPS requests.
  In particular, gql's AIOHTTPTransport historically defaults to ssl=False and
  emits a warning. We enforce ssl=True unless the caller explicitly sets ssl.
"""

from __future__ import annotations

import inspect
import logging
from functools import wraps

logger = logging.getLogger(__name__)


def enforce_gql_aiohttp_tls_verification() -> None:
    """Default gql's AIOHTTPTransport `ssl` parameter to True when unspecified."""

    try:
        from gql.transport.aiohttp import AIOHTTPTransport  # type: ignore
    except Exception as e:
        logger.warning(
            "Could not import gql AIOHTTPTransport; TLS enforcement skipped: %s", e
        )
        return

    orig_init = AIOHTTPTransport.__init__

    # Avoid double-patching.
    if getattr(orig_init, "_monarch_tls_patched", False):
        return

    try:
        sig = inspect.signature(orig_init)
    except Exception:
        sig = None

    if sig is not None and "ssl" not in sig.parameters:
        logger.warning("gql AIOHTTPTransport has no `ssl` parameter; TLS enforcement skipped.")
        return

    @wraps(orig_init)
    def patched_init(self, *args, **kwargs):
        if "ssl" not in kwargs:
            kwargs["ssl"] = True
        return orig_init(self, *args, **kwargs)

    setattr(patched_init, "_monarch_tls_patched", True)
    AIOHTTPTransport.__init__ = patched_init  # type: ignore[assignment]

    logger.info(
        "✅ Enforced TLS certificate verification for gql AIOHTTPTransport by default"
    )
