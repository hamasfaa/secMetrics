from __future__ import annotations

import time
from collections import Counter

from prometheus_client import CollectorRegistry, Gauge

from .models import SEVERITIES, SEVERITY_WEIGHTS, Finding

NAMESPACE = "secmetrics"

DEFAULT_DETAIL_LIMIT = 50

_DEFAULT_TARGET_TYPES = {
    "trivy": ("os", "library"),
    "semgrep": ("code",),
    "gitleaks": ("secret",),
}


def build_registry(
    findings: list[Finding],
    project: str,
    tool: str,
    detail_limit: int = DEFAULT_DETAIL_LIMIT,
    scan_success: bool = True,
) -> CollectorRegistry:
    registry = CollectorRegistry()

    vulns = Gauge(
        f"{NAMESPACE}_vulnerabilities",
        "Jumlah kerentanan yang ditemukan pada scan terakhir.",
        ["project", "tool", "severity", "target_type"],
        registry=registry,
    )

    fixable = Gauge(
        f"{NAMESPACE}_vulnerabilities_fixable",
        "Jumlah kerentanan yang sudah tersedia versi perbaikannya (dapat "
        "langsung ditindaklanjuti).",
        ["project", "tool", "severity"],
        registry=registry,
    )

    by_sev_target: Counter[tuple[str, str]] = Counter()
    by_sev_fixable: Counter[str] = Counter()

    for f in findings:
        by_sev_target[(f.severity, f.target_type)] += 1
        if f.is_fixable:
            by_sev_fixable[f.severity] += 1

    seen_target_types = {t for _, t in by_sev_target} or set(
        _DEFAULT_TARGET_TYPES.get(tool, ("unknown",))
    )
    for severity in SEVERITIES:
        for target_type in seen_target_types:
            vulns.labels(project, tool, severity, target_type).set(
                by_sev_target.get((severity, target_type), 0)
            )
        fixable.labels(project, tool, severity).set(by_sev_fixable.get(severity, 0))

    risk = Gauge(
        f"{NAMESPACE}_risk_score",
        "Skor risiko berbobot (critical=100, high=10, medium=3, low/unknown=1).",
        ["project", "tool"],
        registry=registry,
    )
    risk.labels(project, tool).set(
        sum(SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    )

    weight = Gauge(
        f"{NAMESPACE}_severity_weight",
        "Bobot numerik tiap severity, untuk keperluan pengurutan dan skoring "
        "di dalam query PromQL.",
        ["project", "tool", "severity"],
        registry=registry,
    )
    for severity in SEVERITIES:
        weight.labels(project, tool, severity).set(SEVERITY_WEIGHTS[severity])

    Gauge(
        f"{NAMESPACE}_scan_timestamp_seconds",
        "Unix timestamp saat scan terakhir selesai.",
        ["project", "tool"],
        registry=registry,
    ).labels(project, tool).set(time.time())

    Gauge(
        f"{NAMESPACE}_scan_success",
        "1 jika scan berjalan dan berhasil di-parse, 0 jika gagal.",
        ["project", "tool"],
        registry=registry,
    ).labels(project, tool).set(1 if scan_success else 0)

    Gauge(
        f"{NAMESPACE}_findings_reported",
        "Jumlah total temuan yang di-parse dari output scanner.",
        ["project", "tool"],
        registry=registry,
    ).labels(project, tool).set(len(findings))

    if detail_limit > 0 and findings:
        info = Gauge(
            f"{NAMESPACE}_finding_info",
            f"Detail {detail_limit} temuan paling parah (nilai selalu 1; "
            "informasinya ada pada label).",
            [
                "project",
                "tool",
                "severity",
                "identifier",
                "package",
                "installed_version",
                "fixed_version",
                "target_type",
            ],
            registry=registry,
        )

        ranked = sorted(
            findings,
            key=lambda f: (-SEVERITY_WEIGHTS.get(f.severity, 1), not f.is_fixable),
        )
        seen: set[tuple[str, str]] = set()
        emitted = 0
        for f in ranked:
            key = (f.identifier, f.package)
            if key in seen:
                continue
            seen.add(key)

            info.labels(
                f.project,
                f.tool,
                f.severity,
                f.identifier,
                f.package,
                f.installed_version,
                f.fixed_version or "none",
                f.target_type,
            ).set(1)

            emitted += 1
            if emitted >= detail_limit:
                break

    return registry
