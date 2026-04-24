from __future__ import annotations

import csv
from pathlib import Path

from .features import FlowRecord


class FlowDataError(Exception):
    """Raised when flow data cannot be loaded from a CSV file."""


def load_flows(csv_path: str | Path) -> list[FlowRecord]:
    path = Path(csv_path)

    if not path.exists():
        raise FlowDataError(f"Input file does not exist: {path}")

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            flows = [
                FlowRecord(
                    timestamp=row["timestamp"],
                    local_ip=row.get("local_ip") or row["src_ip"],
                    remote_ip=row.get("remote_ip") or row["dst_ip"],
                    local_port=int(row.get("local_port") or row.get("src_port") or 0),
                    remote_port=int(row.get("remote_port") or row.get("dst_port") or 0),
                    protocol=row["protocol"],
                    duration_ms=float(row["duration_ms"]),
                    bytes_sent=float(row["bytes_sent"]),
                    bytes_received=float(row["bytes_received"]),
                    packets_sent=float(row.get("packets_sent") or row.get("packets") or 0),
                    packets_received=float(row.get("packets_received") or 0),
                    failed_logins=int(row["failed_logins"]),
                )
                for row in reader
            ]
    except KeyError as error:
        raise FlowDataError(f"Missing required CSV column: {error}") from error
    except ValueError as error:
        raise FlowDataError(f"Invalid value in CSV file: {error}") from error
    except OSError as error:
        raise FlowDataError(f"Could not read input file: {path}") from error

    if not flows:
        raise FlowDataError(f"CSV file is empty or contains no data rows: {path}")

    return flows
