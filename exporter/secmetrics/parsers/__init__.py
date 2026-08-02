from __future__ import annotations

from typing import Any, Callable

from ..models import Finding
from . import trivy

PARSERS: dict[str, Callable[[dict[str, Any], str], list[Finding]]] = {
    "trivy": trivy.parse,
}

__all__ = ["PARSERS"]
