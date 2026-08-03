from __future__ import annotations

from typing import Any

from ..models import Finding, relative_path

_RULE_SEVERITY = {
    "aws-access-token": "critical",
    "aws-secret-key": "critical",
    "private-key": "critical",
    "gcp-service-account": "critical",
    "azure-storage-account-key": "critical",
    "github-pat": "critical",
    "github-fine-grained-pat": "critical",
    "stripe-access-token": "critical",
    "jwt": "medium",
    "generic-api-key": "medium",
}
_DEFAULT_SEVERITY = "high"


def parse(data: Any, project: str) -> list[Finding]:
    if not data:
        return []

    findings: list[Finding] = []

    for leak in data:
        rule_id = leak.get("RuleID", "unknown-rule")
        line = leak.get("StartLine", 0)

        findings.append(
            Finding(
                tool="gitleaks",
                project=project,
                severity=_RULE_SEVERITY.get(rule_id, _DEFAULT_SEVERITY),
                identifier=rule_id,
                title=(leak.get("Description") or "").strip()[:120],
                target_type="secret",
                package=relative_path(leak.get("File", "")),
                installed_version=f"L{line}" if line else "",
                fixed_version="",
                extra={
                    "fingerprint": str(leak.get("Fingerprint", "")),
                    "entropy": f"{leak.get('Entropy', 0):.2f}",
                },
            )
        )

    return findings
