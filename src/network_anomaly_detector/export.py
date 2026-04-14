from __future__ import annotations

import csv
from pathlib import Path

from .detector import ScoredFlow


def save_suspicious_flows_csv(output_path: str | Path, flows: list[ScoredFlow]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "score",
                "reasons",
            ],
        )
        writer.writeheader()

        for item in flows:
            writer.writerow(
                {
                    "timestamp": item.flow.timestamp,
                    "src_ip": item.flow.src_ip,
                    "dst_ip": item.flow.dst_ip,
                    "src_port": item.flow.src_port,
                    "dst_port": item.flow.dst_port,
                    "protocol": item.flow.protocol,
                    "score": f"{item.score:.2f}",
                    "reasons": "; ".join(item.reasons),
                }
            )
