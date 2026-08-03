from __future__ import annotations

from typing import Any, Callable

from ..models import Finding
from . import gitleaks, semgrep, trivy

# Satu-satunya tempat yang perlu disentuh saat menambah scanner baru.
PARSERS: dict[str, Callable[[Any, str], list[Finding]]] = {
    "trivy": trivy.parse,
    "semgrep": semgrep.parse,
    "gitleaks": gitleaks.parse,
}

__all__ = ["PARSERS"]
