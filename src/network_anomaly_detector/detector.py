from __future__ import annotations

from dataclasses import dataclass

from .features import FlowRecord
from .stats import FlowStats


@dataclass
class ScoredFlow:
    flow: FlowRecord
    score: float
    reasons: list[str]


Z_SCORE_LIMIT = 1.3


def calculate_z_score(value: float, mean: float, std_dev: float) -> float:
    if std_dev == 0:
        return 0.0
    return (value - mean) / std_dev


def score_flows(flows: list[FlowRecord], stats: FlowStats) -> list[ScoredFlow]:
    scored_flows: list[ScoredFlow] = []

    for flow in flows:
        reasons: list[str] = []
        score = 0.0

        duration_z_score = calculate_z_score(
            flow.duration_ms, stats.avg_duration_ms, stats.std_duration_ms
        )
        if duration_z_score >= Z_SCORE_LIMIT:
            score += duration_z_score
            reasons.append(f"high duration (z={duration_z_score:.2f})")

        bytes_sent_z_score = calculate_z_score(
            flow.bytes_sent, stats.avg_bytes_sent, stats.std_bytes_sent
        )
        if bytes_sent_z_score >= Z_SCORE_LIMIT:
            score += bytes_sent_z_score
            reasons.append(f"high bytes sent (z={bytes_sent_z_score:.2f})")

        bytes_received_z_score = calculate_z_score(
            flow.bytes_received, stats.avg_bytes_received, stats.std_bytes_received
        )
        if bytes_received_z_score >= Z_SCORE_LIMIT:
            score += bytes_received_z_score
            reasons.append(f"high bytes received (z={bytes_received_z_score:.2f})")

        packets_z_score = calculate_z_score(
            flow.packets, stats.avg_packets, stats.std_packets
        )
        if packets_z_score >= Z_SCORE_LIMIT:
            score += packets_z_score
            reasons.append(f"high packet count (z={packets_z_score:.2f})")

        if flow.failed_logins > 0:
            score += 1.5
            reasons.append("failed logins detected")

        scored_flows.append(ScoredFlow(flow=flow, score=score, reasons=reasons))

    return scored_flows


def detect_suspicious_flows(
    flows: list[FlowRecord], stats: FlowStats, threshold: float = 4.0
) -> list[ScoredFlow]:
    scored_flows = score_flows(flows, stats)
    return [scored_flow for scored_flow in scored_flows if scored_flow.score >= threshold]
