from __future__ import annotations

import csv
from pathlib import Path

from .features import FlowRecord


def load_flows(csv_path: str | Path) -> list[FlowRecord]:
    path = Path(csv_path)

    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        flows = [
            FlowRecord(
                timestamp=row["timestamp"],
                src_ip=row["src_ip"],
                dst_ip=row["dst_ip"],
                protocol=row["protocol"],
                duration_ms=float(row["duration_ms"]),
                bytes_sent=float(row["bytes_sent"]),
                bytes_received=float(row["bytes_received"]),
                packets=float(row["packets"]),
                failed_logins=int(row["failed_logins"]),
            )
            for row in reader
        ]

    return flows