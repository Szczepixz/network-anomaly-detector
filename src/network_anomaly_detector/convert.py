from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
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
    length: float


def convert_tshark_packets_to_flows(
    input_path: str | Path,
    output_path: str | Path,
    local_ip: str,
) -> None:
    packets = _load_packet_rows(input_path)
    flow_rows = _build_flow_rows(packets, local_ip=local_ip)
    _save_flow_rows(output_path, flow_rows)


def _load_packet_rows(input_path: str | Path) -> list[PacketRow]:
    path = Path(input_path)

    if not path.exists():
        raise FlowDataError(f"Input file does not exist: {path}")

    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            packets = [
                PacketRow(
                    timestamp=_parse_tshark_timestamp(row["frame.time_epoch"]),
                    src_ip=row["ip.src"],
                    dst_ip=row["ip.dst"],
                    src_port=_read_port(row, "tcp.srcport", "udp.srcport"),
                    dst_port=_read_port(row, "tcp.dstport", "udp.dstport"),
                    protocol=row.get("_ws.col.protocol") or "UNKNOWN",
                    length=float(row["frame.len"]),
                )
                for row in reader
                if row.get("ip.src") and row.get("ip.dst") and row.get("frame.len")
            ]
    except KeyError as error:
        raise FlowDataError(f"Missing required CSV column: {error}") from error
    except ValueError as error:
        raise FlowDataError(f"Invalid value in CSV file: {error}") from error

    if not packets:
        raise FlowDataError(f"CSV file is empty or contains no data rows: {path}")

    return packets


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
                "duration_ms": f"{duration_ms:.2f}",
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
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _read_port(row: dict[str, str], tcp_field: str, udp_field: str) -> int:
    value = row.get(tcp_field) or row.get(udp_field) or "0"
    value = value.split(",")[0].strip()
    return int(value) if value else 0


def _classify_packet_direction(packet: PacketRow, local_ip: str) -> str | None:
    if packet.src_ip == local_ip:
        return "outgoing"
    if packet.dst_ip == local_ip:
        return "incoming"
    return None
