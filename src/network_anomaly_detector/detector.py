from __future__ import annotations

from dataclasses import dataclass

from .features import FlowRecord
from .stats import FlowStats


@dataclass
class ScoredFlow:
    flow: FlowRecord
    score: float
    reasons: list[str]


def score_flows(flows: list[FlowRecord], stats: FlowStats) -> list[ScoredFlow]:
    scored_flows: list[ScoredFlow] = []

    for flow in flows:
        reasons: list[str] = []
        score = 0.0

        if stats.avg_duration_ms > 0 and flow.duration_ms > stats.avg_duration_ms * 1.5:
            score += 1.0
            reasons.append("duration above average")

        if stats.avg_bytes_received > 0 and flow.bytes_received > stats.avg_bytes_received * 1.5:
            score += 1.0
            reasons.append("bytes received above average")

        if stats.avg_packets > 0 and flow.packets > stats.avg_packets * 1.5:
            score += 1.0
            reasons.append("packet count above average")

        if flow.failed_logins > 0:
            score += 1.0
            reasons.append("failed logins detected")

        scored_flows.append(ScoredFlow(flow=flow, score=score, reasons=reasons))

    return scored_flows


def detect_suspicious_flows(
    flows: list[FlowRecord], stats: FlowStats, threshold: float = 2.0
) -> list[ScoredFlow]:
    scored_flows = score_flows(flows, stats)
    return [scored_flow for scored_flow in scored_flows if scored_flow.score >= threshold]
