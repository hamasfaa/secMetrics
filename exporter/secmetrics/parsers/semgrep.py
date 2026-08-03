from __future__ import annotations

from typing import Any

from ..models import Finding, normalize_severity, relative_path


def _short_rule_id(check_id: str) -> str:
    return check_id.rsplit(".", 1)[-1] if check_id else "unknown-rule"


def parse(data: Any, project: str) -> list[Finding]:
    findings: list[Finding] = []

    for result in data.get("results") or []:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = relative_path(result.get("path", ""))
        line = (result.get("start") or {}).get("line", 0)

        cwe = metadata.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]

        findings.append(
            Finding(
                tool="semgrep",
                project=project,
                severity=normalize_severity(extra.get("severity")),
                identifier=_short_rule_id(result.get("check_id", "")),
                title=(extra.get("message") or "").strip()[:120],
                target_type="code",
                package=path,
                installed_version=f"L{line}" if line else "",
                fixed_version="",
                extra={
                    "check_id": result.get("check_id", ""),
                    "cwe": cwe[0] if cwe else "",
                    "confidence": str(metadata.get("confidence", "")),
                },
            )
        )

    return findings
