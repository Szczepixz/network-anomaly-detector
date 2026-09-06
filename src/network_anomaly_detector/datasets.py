from __future__ import annotations

import csv
from math import isfinite
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
            flows = []
            for row_number, row in enumerate(reader, start=2):
                try:
                    flows.append(_parse_flow(row))
                except KeyError as error:
                    raise FlowDataError(
                        f"CSV row {row_number}: missing required column {error}."
                    ) from error
                except ValueError as error:
                    raise FlowDataError(f"CSV row {row_number}: {error}") from error
    except OSError as error:
        raise FlowDataError(f"Could not read input file: {path}") from error

    if not flows:
        raise FlowDataError(f"CSV file is empty or contains no data rows: {path}")

    return flows


def _parse_flow(row: dict[str, str | None]) -> FlowRecord:
    local_port = "local_port" if row.get("local_port") else "src_port"
    remote_port = "remote_port" if row.get("remote_port") else "dst_port"
    packets_sent = "packets_sent" if row.get("packets_sent") else "packets"

    return FlowRecord(
        timestamp=row["timestamp"],
        local_ip=row.get("local_ip") or row["src_ip"],
        remote_ip=row.get("remote_ip") or row["dst_ip"],
        local_port=_parse_non_negative_int(
            row.get(local_port) or "0", local_port, maximum=65535
        ),
        remote_port=_parse_non_negative_int(
            row.get(remote_port) or "0", remote_port, maximum=65535
        ),
        protocol=row["protocol"],
        duration_ms=_parse_non_negative_float(row["duration_ms"], "duration_ms"),
        bytes_sent=_parse_non_negative_float(row["bytes_sent"], "bytes_sent"),
        bytes_received=_parse_non_negative_float(row["bytes_received"], "bytes_received"),
        packets_sent=_parse_non_negative_float(row.get(packets_sent) or "0", packets_sent),
        packets_received=_parse_non_negative_float(
            row.get("packets_received") or "0", "packets_received"
        ),
        failed_logins=_parse_non_negative_int(row["failed_logins"], "failed_logins"),
    )


def _parse_non_negative_float(value: str | None, column: str) -> float:
    message = f"column '{column}' must contain a finite, non-negative number."
    if value is None:
        raise ValueError(message)
    try:
        number = float(value)
    except ValueError as error:
        raise ValueError(message) from error
    if not isfinite(number) or number < 0:
        raise ValueError(message)
    return number


def _parse_non_negative_int(
    value: str | None, column: str, maximum: int | None = None
) -> int:
    message = f"column '{column}' must contain a non-negative integer."
    if maximum is not None:
        message = f"column '{column}' must contain an integer between 0 and {maximum}."
    if value is None:
        raise ValueError(message)
    try:
        number = int(value)
    except ValueError as error:
        raise ValueError(message) from error
    if number < 0 or (maximum is not None and number > maximum):
        raise ValueError(message)
    return number
