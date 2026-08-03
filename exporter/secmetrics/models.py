from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")

SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 100,
    "high": 10,
    "medium": 3,
    "low": 1,
    "unknown": 1,
}


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return "unknown"

    value = raw.strip().lower()

    aliases = {
        "error": "high",        # Semgrep ERROR
        "warning": "medium",    # Semgrep WARNING
        "info": "low",          # Semgrep INFO
        "note": "low",          # SARIF note
        "none": "unknown",
        "negligible": "low",
        "moderate": "medium",
        "important": "high",
    }
    value = aliases.get(value, value)

    return value if value in SEVERITIES else "unknown"


def relative_path(path: str) -> str:
    for prefix in ("/src/", "/app/", "./"):
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path.lstrip("/")


@dataclass(frozen=True)
class Finding:
    tool: str                     # "trivy" | "semgrep" | "gitleaks"
    project: str
    severity: str
    identifier: str
    title: str = ""

    target_type: str = "unknown"  # "os" | "library" | "code" | "secret"
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""

    extra: dict[str, str] = field(default_factory=dict)

    @property
    def is_fixable(self) -> bool:
        return bool(self.fixed_version.strip())
