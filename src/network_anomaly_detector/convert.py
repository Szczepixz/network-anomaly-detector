from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address
from math import isfinite
from pathlib import Path

from .datasets import FlowDataError


@dataclass
class PacketRow:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int


def convert_tshark_packets_to_flows(
    input_path: str | Path,
    output_path: str | Path,
    local_ip: str,
) -> None:
    try:
        local_ip = str(IPv4Address(local_ip))
    except ValueError as error:
        raise FlowDataError("The local IP must be a valid IPv4 address.") from error
    packets = _load_packet_rows(input_path)
    flow_rows = _build_flow_rows(packets, local_ip=local_ip)
    try:
        _save_flow_rows(output_path, flow_rows)
    except OSError as error:
        raise FlowDataError(f"Could not write flow CSV: {output_path}") from error


def _load_packet_rows(input_path: str | Path) -> list[PacketRow]:
    path = Path(input_path)

    if not path.exists():
        raise FlowDataError(f"Input file does not exist: {path}")

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            required = {"frame.time_epoch", "ip.src", "ip.dst", "frame.len"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                raise FlowDataError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
            packets = []
            for row_number, row in enumerate(reader, start=2):
                try:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError("row has a different number of fields than the header.")
                    # Non-IPv4 traffic has no addresses in either IPv4 column.
                    if not row["ip.src"].strip() and not row["ip.dst"].strip():
                        continue
                    packets.append(_parse_packet(row))
                except ValueError as error:
                    raise FlowDataError(f"CSV row {row_number}: {error}") from error
    except OSError as error:
        raise FlowDataError(f"Could not read packet CSV: {path}") from error

    if not packets:
        raise FlowDataError(f"CSV file is empty or contains no data rows: {path}")

    return packets


def _parse_packet(row: dict[str, str]) -> PacketRow:
    row = {column: value.strip() for column, value in row.items()}
    addresses = {}
    for column in ("ip.src", "ip.dst"):
        try:
            addresses[column] = str(IPv4Address(row[column].strip()))
        except ValueError as error:
            raise ValueError(f"column '{column}' must contain one IPv4 address.") from error
    ports = {}
    for column in ("tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"):
        value = row.get(column, "").strip()
        ports[column] = _parse_integer(value, column, 0, 65535) if value else 0
    if (row.get("tcp.srcport") or row.get("tcp.dstport")) and (
        row.get("udp.srcport") or row.get("udp.dstport")
    ):
        raise ValueError("TCP and UDP port columns cannot both be populated.")
    protocol = _read_protocol(row)
    transport = "tcp" if protocol == "TCP" else "udp"
    return PacketRow(
        timestamp=_parse_tshark_timestamp(row["frame.time_epoch"]),
        src_ip=addresses["ip.src"],
        dst_ip=addresses["ip.dst"],
        src_port=ports[f"{transport}.srcport"],
        dst_port=ports[f"{transport}.dstport"],
        protocol=protocol,
        length=_parse_integer(row["frame.len"], "frame.len", 1),
    )


def _parse_integer(value: str, column: str, minimum: int, maximum: int | None = None) -> int:
    message = f"column '{column}' must contain an integer >= {minimum}"
    if maximum is not None:
        message += f" and <= {maximum}"
    try:
        number = int(value)
    except ValueError as error:
        raise ValueError(message + ".") from error
    if number < minimum or (maximum is not None and number > maximum):
        raise ValueError(message + ".")
    return number


def _build_flow_rows(packets: list[PacketRow], local_ip: str) -> list[dict[str, str]]:
    grouped_packets: dict[tuple[str, str, int, int, str], dict[str, object]] = {}

    for packet in packets:
        direction = _classify_packet_direction(packet, local_ip=local_ip)
        if direction is None:
            continue

        remote_ip = packet.dst_ip if direction == "outgoing" else packet.src_ip
        local_port = packet.src_port if direction == "outgoing" else packet.dst_port
        remote_port = packet.dst_port if direction == "outgoing" else packet.src_port
        key = (local_ip, remote_ip, local_port, remote_port, packet.protocol)
        entry = grouped_packets.setdefault(
            key,
            {
                "timestamps": [],
                "bytes_sent": 0.0,
                "bytes_received": 0.0,
                "packets_sent": 0,
                "packets_received": 0,
            },
        )
        entry["timestamps"].append(packet.timestamp)
        if direction == "outgoing":
            entry["bytes_sent"] += packet.length
            entry["packets_sent"] += 1
        else:
            entry["bytes_received"] += packet.length
            entry["packets_received"] += 1

    flow_rows: list[dict[str, str]] = []
    for (local_ip, remote_ip, local_port, remote_port, protocol), group in grouped_packets.items():
        timestamps = group["timestamps"]
        duration_ms = (max(timestamps) - min(timestamps)).total_seconds() * 1000

        flow_rows.append(
            {
                "timestamp": min(timestamps).isoformat(),
                "local_ip": local_ip,
                "remote_ip": remote_ip,
                "local_port": str(local_port),
                "remote_port": str(remote_port),
                "protocol": protocol,
                "duration_ms": f"{duration_ms:.3f}",
                "bytes_sent": f"{group['bytes_sent']:.2f}",
                "bytes_received": f"{group['bytes_received']:.2f}",
                "packets_sent": str(group["packets_sent"]),
                "packets_received": str(group["packets_received"]),
                "failed_logins": "0",
            }
        )

    if not flow_rows:
        raise FlowDataError(
            "No packets matched the selected local IP. Try a different --local-ip value."
        )

    return flow_rows


def _save_flow_rows(output_path: str | Path, rows: list[dict[str, str]]) -> None:
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
                "duration_ms",
                "bytes_sent",
                "bytes_received",
                "packets_sent",
                "packets_received",
                "failed_logins",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def _parse_tshark_timestamp(value: str) -> datetime:
    try:
        timestamp = float(value)
        if not isfinite(timestamp):
            raise ValueError("Non-finite timestamp")
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (ValueError, OverflowError, OSError) as error:
        raise ValueError(
            "column 'frame.time_epoch' must contain a finite, representable Unix timestamp."
        ) from error


def _read_protocol(row: dict[str, str]) -> str:
    """Use transport fields so application labels do not split a flow."""
    if row.get("tcp.srcport") or row.get("tcp.dstport"):
        return "TCP"
    if row.get("udp.srcport") or row.get("udp.dstport"):
        return "UDP"
    return row.get("_ws.col.Protocol") or row.get("_ws.col.protocol") or "UNKNOWN"


def _classify_packet_direction(packet: PacketRow, local_ip: str) -> str | None:
    if packet.src_ip == local_ip:
        return "outgoing"
    if packet.dst_ip == local_ip:
        return "incoming"
    return None
