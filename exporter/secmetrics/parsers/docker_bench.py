from __future__ import annotations

from typing import Any

from ..models import ComplianceCheck

BENCHMARK = "cis-docker"

_KNOWN_STATUSES = ("pass", "warn", "info", "note")


def _normalize_status(raw: str | None) -> str:
    value = (raw or "").strip().lower()
    return value if value in _KNOWN_STATUSES else "info"


def parse(data: Any, project: str) -> list[ComplianceCheck]:
    checks: list[ComplianceCheck] = []

    for section in data.get("tests") or []:
        section_label = f"{section.get('id', '?')} - {section.get('desc', 'Unknown')}"

        for result in section.get("results") or []:
            checks.append(
                ComplianceCheck(
                    tool="docker-bench",
                    project=project,
                    benchmark=BENCHMARK,
                    check_id=str(result.get("id", "?")),
                    title=(result.get("desc") or "").strip()[:120],
                    status=_normalize_status(result.get("result")),
                    section=section_label,
                )
            )

    return checks
