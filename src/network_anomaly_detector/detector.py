from __future__ import annotations

from dataclasses import dataclass

from .features import FlowRecord


@dataclass
class SuspiciousFlow:
    flow: FlowRecord
    reasons: list[str]


def detect_suspicious_flows(flows: list[FlowRecord]) -> list[SuspiciousFlow]:
    suspicious_flows: list[SuspiciousFlow] = []

    for flow in flows:
        reasons: list[str] = []

        if flow.bytes_received > 10_000:
            reasons.append("high bytes received")
        if flow.packets > 30:
            reasons.append("high packet count")
        if flow.failed_logins > 0:
            reasons.append("failed logins detected")

        if reasons:
            suspicious_flows.append(SuspiciousFlow(flow=flow, reasons=reasons))

    return suspicious_flows
