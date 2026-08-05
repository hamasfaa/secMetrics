from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from prometheus_client import generate_latest

from secmetrics.metrics import (
    COMPLIANCE_STATUSES,
    DEFAULT_DETAIL_LIMIT,
    build_compliance_registry,
    build_registry,
)
from secmetrics.models import SEVERITIES
from secmetrics.parsers import ALL_TOOLS, COMPLIANCE_PARSERS, PARSERS
from secmetrics.pusher import DEFAULT_JOB, push


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Ubah output security scanner menjadi metrik Prometheus.",
    )
    p.add_argument(
        "--tool",
        required=True,
        choices=ALL_TOOLS,
        help="Scanner yang menghasilkan file input.",
    )
    p.add_argument("--input", required=True, type=Path, help="Path file output scanner.")
    p.add_argument(
        "--project",
        required=True,
        help="Nama unit yang dipindai (jadi label `project`).",
    )
    p.add_argument(
        "--gateway",
        default="http://pushgateway:9091",
        help="Alamat Pushgateway. Default memakai nama service Docker.",
    )
    p.add_argument("--job", default=DEFAULT_JOB, help="Label `job` di Prometheus.")
    p.add_argument(
        "--detail-limit",
        type=int,
        default=DEFAULT_DETAIL_LIMIT,
        help="Jumlah maksimum temuan yang diekspor rinci (0 = matikan). "
        "Membatasi cardinality Prometheus.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Cetak metrik ke stdout, jangan push. Berguna untuk debugging.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    is_compliance = args.tool in COMPLIANCE_PARSERS

    items: list = []
    scan_success = True

    try:
        raw = json.loads(args.input.read_text(encoding="utf-8"))
        parser = COMPLIANCE_PARSERS[args.tool] if is_compliance else PARSERS[args.tool]
        items = parser(raw, args.project)
    except FileNotFoundError:
        print(f"[error] file tidak ditemukan: {args.input}", file=sys.stderr)
        scan_success = False
    except json.JSONDecodeError as exc:
        print(f"[error] JSON tidak valid di {args.input}: {exc}", file=sys.stderr)
        scan_success = False

    if is_compliance:
        benchmark = items[0].benchmark if items else "unknown"
        registry = build_compliance_registry(
            checks=items,
            project=args.project,
            tool=args.tool,
            benchmark=benchmark,
            detail_limit=args.detail_limit,
            scan_success=scan_success,
        )
        counts = Counter(c.status for c in items)
        scored = counts["pass"] + counts["warn"]
        score = 100.0 * counts["pass"] / scored if scored else 0.0
        summary = "  ".join(f"{s}={counts[s]}" for s in COMPLIANCE_STATUSES)
        print(
            f"[{args.tool}/{args.project}] {len(items)} kontrol  |  {summary}"
            f"  |  skor = {score:.1f}%"
        )
    else:
        registry = build_registry(
            findings=items,
            project=args.project,
            tool=args.tool,
            detail_limit=args.detail_limit,
            scan_success=scan_success,
        )
        counts = Counter(f.severity for f in items)
        summary = "  ".join(f"{s}={counts[s]}" for s in SEVERITIES)
        print(f"[{args.tool}/{args.project}] {len(items)} temuan  |  {summary}")

    if args.dry_run:
        print(generate_latest(registry).decode("utf-8"))
        return 0 if scan_success else 1

    try:
        push(
            registry=registry,
            gateway=args.gateway,
            project=args.project,
            tool=args.tool,
            job=args.job,
        )
        print(f"[ok] metrik terkirim ke {args.gateway} (job={args.job})")
    except Exception as exc:
        print(f"[error] gagal push ke {args.gateway}: {exc}", file=sys.stderr)
        return 2

    return 0 if scan_success else 1


if __name__ == "__main__":
    raise SystemExit(main())
