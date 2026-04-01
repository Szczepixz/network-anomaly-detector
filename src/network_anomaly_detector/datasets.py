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
    except KeyError as error:
        raise FlowDataError(f"Missing required CSV column: {error}") from error
    except ValueError as error:
        raise FlowDataError(f"Invalid value in CSV file: {error}") from error
    except OSError as error:
        raise FlowDataError(f"Could not read input file: {path}") from error

    if not flows:
        raise FlowDataError(f"CSV file is empty or contains no data rows: {path}")

    return flows
