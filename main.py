from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import FlowDataError, load_flows
from network_anomaly_detector.detector import detect_suspicious_flows
from network_anomaly_detector.export import save_suspicious_flows_csv
from network_anomaly_detector.stats import calculate_flow_stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze network flow data.")
    parser.add_argument(
        "--input",
        default=str(ROOT / "data" / "demo_flows.csv"),
        help="Path to the CSV file with flow data.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=4.0,
        help="Minimum anomaly score required to mark a flow as suspicious.",
    )
    parser.add_argument(
        "--output",
        help="Optional path to save suspicious flows as CSV.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        flows = load_flows(args.input)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    stats = calculate_flow_stats(flows)
    suspicious_flows = detect_suspicious_flows(flows, stats, threshold=args.threshold)

    print(f"Input file: {args.input}")
    print(f"Loaded {len(flows)} flows.")
    print(f"Average duration: {stats.avg_duration_ms:.2f} ms")
    print(f"Average bytes sent: {stats.avg_bytes_sent:.2f}")
    print(f"Average bytes received: {stats.avg_bytes_received:.2f}")
    print(f"Average packets: {stats.avg_packets:.2f}")
    print(f"Protocols: {', '.join(stats.protocols)}")
    print(f"Threshold: {args.threshold:.1f}")
    print(f"Suspicious flows: {len(suspicious_flows)}")

    if flows:
        print(f"First flow: {flows[0]}")

    for suspicious_flow in suspicious_flows:
        print(
            "Suspicious record: "
            f"{suspicious_flow.flow.src_ip} -> {suspicious_flow.flow.dst_ip} "
            f"score={suspicious_flow.score:.1f} "
            f"({', '.join(suspicious_flow.reasons)})"
        )

    if args.output:
        save_suspicious_flows_csv(args.output, suspicious_flows)
        print(f"Saved suspicious flows to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
