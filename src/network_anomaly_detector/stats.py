from __future__ import annotations

from dataclasses import dataclass

from .features import FlowRecord


@dataclass
class FlowStats:
    flow_count: int
    avg_duration_ms: float
    avg_bytes_sent: float
    avg_bytes_received: float
    avg_packets: float
    protocols: list[str]


def calculate_flow_stats(flows: list[FlowRecord]) -> FlowStats:
    if not flows:
        return FlowStats(
            flow_count=0,
            avg_duration_ms=0.0,
            avg_bytes_sent=0.0,
            avg_bytes_received=0.0,
            avg_packets=0.0,
            protocols=[],
        )

    flow_count = len(flows)

    return FlowStats(
        flow_count=flow_count,
        avg_duration_ms=sum(flow.duration_ms for flow in flows) / flow_count,
        avg_bytes_sent=sum(flow.bytes_sent for flow in flows) / flow_count,
        avg_bytes_received=sum(flow.bytes_received for flow in flows) / flow_count,
        avg_packets=sum(flow.packets for flow in flows) / flow_count,
        protocols=sorted({flow.protocol for flow in flows}),
    )
