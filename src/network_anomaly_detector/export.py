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
                "local_ip",
                "remote_ip",
                "local_port",
                "remote_port",
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
                    "local_ip": item.flow.local_ip,
                    "remote_ip": item.flow.remote_ip,
                    "local_port": item.flow.local_port,
                    "remote_port": item.flow.remote_port,
                    "protocol": item.flow.protocol,
                    "score": f"{item.score:.2f}",
                    "reasons": "; ".join(item.reasons),
                }
            )
