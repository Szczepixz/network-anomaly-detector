from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import load_flows
from network_anomaly_detector.detector import detect_suspicious_flows
from network_anomaly_detector.stats import calculate_flow_stats


def main() -> None:
    data_path = ROOT / "data" / "demo_flows.csv"
    flows = load_flows(data_path)
    stats = calculate_flow_stats(flows)
    suspicious_flows = detect_suspicious_flows(flows)

    print(f"Loaded {len(flows)} flows.")
    print(f"Average duration: {stats.avg_duration_ms:.2f} ms")
    print(f"Average bytes sent: {stats.avg_bytes_sent:.2f}")
    print(f"Average bytes received: {stats.avg_bytes_received:.2f}")
    print(f"Average packets: {stats.avg_packets:.2f}")
    print(f"Protocols: {', '.join(stats.protocols)}")
    print(f"Suspicious flows: {len(suspicious_flows)}")

    if flows:
        print(f"First flow: {flows[0]}")

    for suspicious_flow in suspicious_flows:
        print(
            "Suspicious record: "
            f"{suspicious_flow.flow.src_ip} -> {suspicious_flow.flow.dst_ip} "
            f"({', '.join(suspicious_flow.reasons)})"
        )


if __name__ == "__main__":
    main()
