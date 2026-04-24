from __future__ import annotations

from dataclasses import dataclass
from statistics import pstdev

from .features import FlowRecord


@dataclass
class FlowStats:
    flow_count: int
    avg_duration_ms: float
    std_duration_ms: float
    avg_bytes_sent: float
    std_bytes_sent: float
    avg_bytes_received: float
    std_bytes_received: float
    avg_packets_total: float
    std_packets_total: float
    protocols: list[str]


def calculate_flow_stats(flows: list[FlowRecord]) -> FlowStats:
    if not flows:
        return FlowStats(
            flow_count=0,
            avg_duration_ms=0.0,
            std_duration_ms=0.0,
            avg_bytes_sent=0.0,
            std_bytes_sent=0.0,
            avg_bytes_received=0.0,
            std_bytes_received=0.0,
            avg_packets_total=0.0,
            std_packets_total=0.0,
            protocols=[],
        )

    flow_count = len(flows)
    duration_values = [flow.duration_ms for flow in flows]
    bytes_sent_values = [flow.bytes_sent for flow in flows]
    bytes_received_values = [flow.bytes_received for flow in flows]
    packet_values = [flow.total_packets for flow in flows]

    return FlowStats(
        flow_count=flow_count,
        avg_duration_ms=sum(duration_values) / flow_count,
        std_duration_ms=pstdev(duration_values),
        avg_bytes_sent=sum(bytes_sent_values) / flow_count,
        std_bytes_sent=pstdev(bytes_sent_values),
        avg_bytes_received=sum(bytes_received_values) / flow_count,
        std_bytes_received=pstdev(bytes_received_values),
        avg_packets_total=sum(packet_values) / flow_count,
        std_packets_total=pstdev(packet_values),
        protocols=sorted({flow.protocol for flow in flows}),
    )
