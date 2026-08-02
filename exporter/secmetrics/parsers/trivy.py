from __future__ import annotations

from typing import Any

from ..models import Finding, normalize_severity

_CLASS_TO_TARGET_TYPE = {
    "os-pkgs": "os",
    "lang-pkgs": "library",
    "config": "config",
    "secret": "secret",
    "license": "license",
}


def parse(data: dict[str, Any], project: str) -> list[Finding]:
    findings: list[Finding] = []

    for result in data.get("Results") or []:
        target_type = _CLASS_TO_TARGET_TYPE.get(result.get("Class", ""), "unknown")
        target = result.get("Target", "")

        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    tool="trivy",
                    project=project,
                    severity=normalize_severity(vuln.get("Severity")),
                    identifier=vuln.get("VulnerabilityID", "UNKNOWN"),
                    title=(vuln.get("Title") or vuln.get("Description") or "")[:120],
                    target_type=target_type,
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", "") or "",
                    extra={"target": target},
                )
            )

    return findings
