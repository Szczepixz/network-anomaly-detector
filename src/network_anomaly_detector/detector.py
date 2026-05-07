from __future__ import annotations

from dataclasses import dataclass

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
except ImportError:
    IsolationForest = None
    LocalOutlierFactor = None

from .features import FlowRecord
from .stats import FlowStats


@dataclass
class ScoredFlow:
    flow: FlowRecord
    score: float
    reasons: list[str]
    is_suspicious: bool = False


class DetectorError(Exception):
    """Raised when the detector cannot score flows."""


Z_SCORE_LIMIT = 1.3
SUPPORTED_METHODS = ("statistical", "isolation-forest", "local-outlier-factor")


def calculate_z_score(value: float, mean: float, std_dev: float) -> float:
    if std_dev == 0:
        return 0.0
    return (value - mean) / std_dev


def score_flows(flows: list[FlowRecord], stats: FlowStats) -> list[ScoredFlow]:
    scored_flows: list[ScoredFlow] = []

    for flow in flows:
        score, reasons = build_statistical_score(flow, stats)
        scored_flows.append(ScoredFlow(flow=flow, score=score, reasons=reasons))

    return scored_flows


def build_statistical_score(flow: FlowRecord, stats: FlowStats) -> tuple[float, list[str]]:
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

    total_bytes_z_score = calculate_z_score(
        flow.total_bytes, stats.avg_total_bytes, stats.std_total_bytes
    )
    if total_bytes_z_score >= Z_SCORE_LIMIT:
        score += total_bytes_z_score
        reasons.append(f"high total bytes (z={total_bytes_z_score:.2f})")

    packets_z_score = calculate_z_score(
        flow.total_packets, stats.avg_packets_total, stats.std_packets_total
    )
    if packets_z_score >= Z_SCORE_LIMIT:
        score += packets_z_score
        reasons.append(f"high packet count (z={packets_z_score:.2f})")

    bytes_per_second_z_score = calculate_z_score(
        flow.bytes_per_second,
        stats.avg_bytes_per_second,
        stats.std_bytes_per_second,
    )
    if bytes_per_second_z_score >= Z_SCORE_LIMIT:
        score += bytes_per_second_z_score
        reasons.append(f"high bytes per second (z={bytes_per_second_z_score:.2f})")

    packets_per_second_z_score = calculate_z_score(
        flow.packets_per_second,
        stats.avg_packets_per_second,
        stats.std_packets_per_second,
    )
    if packets_per_second_z_score >= Z_SCORE_LIMIT:
        score += packets_per_second_z_score
        reasons.append(f"high packets per second (z={packets_per_second_z_score:.2f})")

    sent_received_ratio_z_score = calculate_z_score(
        flow.sent_received_ratio,
        stats.avg_sent_received_ratio,
        stats.std_sent_received_ratio,
    )
    if sent_received_ratio_z_score >= Z_SCORE_LIMIT:
        score += sent_received_ratio_z_score
        reasons.append(
            f"unusual sent/received ratio (z={sent_received_ratio_z_score:.2f})"
        )

    if flow.failed_logins > 0:
        score += 1.5
        reasons.append("failed logins detected")

    return score, reasons


def build_feature_vector(flow: FlowRecord) -> list[float]:
    return [
        flow.duration_ms,
        flow.bytes_sent,
        flow.bytes_received,
        flow.packets_sent,
        flow.packets_received,
        flow.total_bytes,
        flow.total_packets,
        flow.bytes_per_second,
        flow.packets_per_second,
        flow.sent_received_ratio,
        float(flow.local_port),
        float(flow.remote_port),
        float(flow.failed_logins),
    ]


def build_feature_matrix(flows: list[FlowRecord]) -> list[list[float]]:
    return [build_feature_vector(flow) for flow in flows]


def score_flows_isolation_forest(
    flows: list[FlowRecord],
    stats: FlowStats,
    contamination: float = 0.2,
) -> list[ScoredFlow]:
    if IsolationForest is None:
        raise DetectorError(
            "Isolation Forest needs scikit-learn in the current Python environment."
        )

    if len(flows) < 2:
        raise DetectorError("Isolation Forest needs at least 2 flows.")

    model = IsolationForest(
        contamination=contamination,
        random_state=42,
    )
    feature_matrix = build_feature_matrix(flows)
    predictions = model.fit_predict(feature_matrix)
    raw_scores = model.score_samples(feature_matrix)
    max_raw_score = max(raw_scores)

    scored_flows: list[ScoredFlow] = []

    for flow, prediction, raw_score in zip(flows, predictions, raw_scores):
        score = max_raw_score - float(raw_score)
        _, reasons = build_statistical_score(flow, stats)

        if prediction == -1 and not reasons:
            reasons.append("unusual combination of flow features")

        scored_flows.append(
            ScoredFlow(
                flow=flow,
                score=score,
                reasons=reasons,
                is_suspicious=prediction == -1,
            )
        )

    return scored_flows


def score_flows_local_outlier_factor(
    flows: list[FlowRecord],
    stats: FlowStats,
    contamination: float = 0.2,
) -> list[ScoredFlow]:
    if LocalOutlierFactor is None:
        raise DetectorError(
            "Local Outlier Factor needs scikit-learn in the current Python environment."
        )

    if len(flows) < 3:
        raise DetectorError("Local Outlier Factor needs at least 3 flows.")

    feature_matrix = build_feature_matrix(flows)
    neighbor_count = min(5, len(flows) - 1)
    model = LocalOutlierFactor(
        contamination=contamination,
        n_neighbors=neighbor_count,
    )
    predictions = model.fit_predict(feature_matrix)
    raw_scores = list(model.negative_outlier_factor_)
    max_raw_score = max(raw_scores)

    scored_flows: list[ScoredFlow] = []

    for flow, prediction, raw_score in zip(flows, predictions, raw_scores):
        score = max_raw_score - float(raw_score)
        _, reasons = build_statistical_score(flow, stats)

        if prediction == -1 and not reasons:
            reasons.append("unusual local density around this flow")

        scored_flows.append(
            ScoredFlow(
                flow=flow,
                score=score,
                reasons=reasons,
                is_suspicious=prediction == -1,
            )
        )

    return scored_flows


def detect_suspicious_flows(
    flows: list[FlowRecord],
    stats: FlowStats,
    threshold: float = 4.0,
    method: str = "statistical",
    contamination: float = 0.2,
) -> list[ScoredFlow]:
    if method not in SUPPORTED_METHODS:
        raise DetectorError(f"Unsupported detection method: {method}")

    if method == "isolation-forest":
        scored_flows = score_flows_isolation_forest(
            flows,
            stats,
            contamination=contamination,
        )
        return [scored_flow for scored_flow in scored_flows if scored_flow.is_suspicious]

    if method == "local-outlier-factor":
        scored_flows = score_flows_local_outlier_factor(
            flows,
            stats,
            contamination=contamination,
        )
        return [scored_flow for scored_flow in scored_flows if scored_flow.is_suspicious]

    scored_flows = score_flows(flows, stats)
    return [scored_flow for scored_flow in scored_flows if scored_flow.score >= threshold]
