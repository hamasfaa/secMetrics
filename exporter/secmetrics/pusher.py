from __future__ import annotations

from prometheus_client import CollectorRegistry, push_to_gateway

DEFAULT_JOB = "security_scan"

def push(
    registry: CollectorRegistry,
    gateway: str,
    project: str,
    tool: str,
    job: str = DEFAULT_JOB,
    timeout: int = 15,
) -> None:
    push_to_gateway(
        gateway=gateway,
        job=job,
        registry=registry,
        grouping_key={"project": project, "tool": tool},
        timeout=timeout,
    )
