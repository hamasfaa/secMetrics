from __future__ import annotations

from typing import Any, Callable

from ..models import ComplianceCheck, Finding
from . import docker_bench, gitleaks, semgrep, trivy

PARSERS: dict[str, Callable[[Any, str], list[Finding]]] = {
    "trivy": trivy.parse,
    "semgrep": semgrep.parse,
    "gitleaks": gitleaks.parse,
}

COMPLIANCE_PARSERS: dict[str, Callable[[Any, str], list[ComplianceCheck]]] = {
    "docker-bench": docker_bench.parse,
}

ALL_TOOLS = sorted({**PARSERS, **COMPLIANCE_PARSERS})

__all__ = ["PARSERS", "COMPLIANCE_PARSERS", "ALL_TOOLS"]
