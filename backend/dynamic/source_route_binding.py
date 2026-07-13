"""Server-only capabilities for source-to-route dynamic verification bindings.

JSON transports can carry an auditable ``source_route_binding`` description, but
that description is not an authorization capability.  The capability lives on a
private ``dict`` subclass instance created only while handling server-side route
evidence or an explicitly audited loopback override.  JSON decoding always
creates a plain ``dict`` and therefore cannot forge this capability.
"""
from __future__ import annotations

import copy
import json
from typing import Any


class _ServerBoundSurface(dict):
    """Structured surface carrying an in-process-only capability attribute."""

    __slots__ = ("_capability", "_snapshot")

    def __init__(self, value: dict[str, Any], snapshot: str) -> None:
        super().__init__(value)
        self._capability = _SURFACE_CAPABILITY
        self._snapshot = snapshot


_SURFACE_CAPABILITY = object()


def bind_server_surface(surface: dict[str, Any], binding: dict[str, Any]) -> dict:
    """Mint an immutable-in-practice server capability for one safe route surface.

    A capability is valid only while the exact route, method and parameter
    inventory minted by the server remains unchanged.  This makes a JSON copy,
    a persisted claim, and an in-memory post-bind mutation equally unable to
    authorize an HTTP request.
    """
    value = copy.deepcopy(surface) if isinstance(surface, dict) else {}
    if not isinstance(binding, dict) or not _is_safe_surface(value):
        return value
    value["source_route_binding"] = copy.deepcopy(binding)
    snapshot = _canonical_surface(value)
    if snapshot is None:
        return value
    return _ServerBoundSurface(value, snapshot)


def is_server_bound_surface(surface: object) -> bool:
    """True only for an unchanged capability minted in this server process."""
    return bool(
        isinstance(surface, _ServerBoundSurface)
        and getattr(surface, "_capability", None) is _SURFACE_CAPABILITY
        and _canonical_surface(surface) == getattr(surface, "_snapshot", None)
    )


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_PARAMETER_LOCATIONS = {"query", "form", "json", "multipart", "path", "header", "cookie"}


def _is_safe_surface(surface: dict[str, Any]) -> bool:
    path = surface.get("path")
    raw_path = surface.get("raw_path", path)
    if not _is_relative_route(path) or not _is_relative_route(raw_path):
        return False
    methods = surface.get("methods")
    if not isinstance(methods, list) or not methods:
        return False
    if any(str(method).upper() not in _HTTP_METHODS for method in methods):
        return False
    params = surface.get("params", [])
    if not isinstance(params, list):
        return False
    return all(
        isinstance(parameter, dict)
        and isinstance(parameter.get("name"), str)
        and parameter["name"].strip()
        and str(parameter.get("location") or "query").lower() in _PARAMETER_LOCATIONS
        for parameter in params
    )


def _is_relative_route(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and value.startswith("/")
        and not value.startswith("//")
        and "://" not in value
        and "?" not in value
        and "#" not in value
    )


def _canonical_surface(surface: object) -> str | None:
    try:
        return json.dumps(surface, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False)
    except (TypeError, ValueError):
        return None
