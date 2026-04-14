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


def convert_tshark_packets_to_flows(input_path: str | Path, output_path: str | Path) -> None:
    packets = _load_packet_rows(input_path)
    flow_rows = _build_flow_rows(packets)
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
                    protocol=row["_ws.col.protocol"],
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


def _build_flow_rows(packets: list[PacketRow]) -> list[dict[str, str]]:
    grouped_packets: dict[tuple[str, str, int, int, str], list[PacketRow]] = {}

    for packet in packets:
        key = (
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.protocol,
        )
        grouped_packets.setdefault(key, []).append(packet)

    flow_rows: list[dict[str, str]] = []
    for (src_ip, dst_ip, src_port, dst_port, protocol), group in grouped_packets.items():
        timestamps = [packet.timestamp for packet in group]
        duration_ms = (max(timestamps) - min(timestamps)).total_seconds() * 1000
        total_bytes = sum(packet.length for packet in group)

        flow_rows.append(
            {
                "timestamp": min(timestamps).isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": str(src_port),
                "dst_port": str(dst_port),
                "protocol": protocol,
                "duration_ms": f"{duration_ms:.2f}",
                "bytes_sent": f"{total_bytes:.2f}",
                "bytes_received": "0.00",
                "packets": str(len(group)),
                "failed_logins": "0",
            }
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
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "duration_ms",
                "bytes_sent",
                "bytes_received",
                "packets",
                "failed_logins",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def _parse_tshark_timestamp(value: str) -> datetime:
    return datetime.fromtimestamp(float(value), tz=timezone.utc)


def _read_port(row: dict[str, str], tcp_field: str, udp_field: str) -> int:
    value = row.get(tcp_field) or row.get(udp_field) or "0"
    return int(value) if value else 0
