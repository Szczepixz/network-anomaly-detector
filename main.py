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
from network_anomaly_detector.convert import convert_tshark_packets_to_flows
from network_anomaly_detector.stats import calculate_flow_stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze network flow data.")
    parser.add_argument(
        "--convert-tshark",
        action="store_true",
        help="Convert a simple tshark-like packet CSV into the flow CSV format.",
    )
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

    if args.convert_tshark:
        if not args.output:
            print("Error: --output is required when using --convert-tshark")
            return 1

        try:
            convert_tshark_packets_to_flows(args.input, args.output)
        except FlowDataError as error:
            print(f"Error: {error}")
            return 1

        print(f"Converted tshark-like CSV to flow CSV: {args.output}")
        return 0

    try:
        flows = load_flows(args.input)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    stats = calculate_flow_stats(flows)
    suspicious_flows = detect_suspicious_flows(flows, stats, threshold=args.threshold)

    print("Summary")
    print(f"Input file: {args.input}")
    print(f"Loaded flows: {len(flows)}")
    print(f"Threshold: {args.threshold:.1f}")
    print(f"Suspicious flows: {len(suspicious_flows)}")

    print()
    print("Traffic stats")
    print(f"Average duration: {stats.avg_duration_ms:.2f} ms")
    print(f"Average bytes sent: {stats.avg_bytes_sent:.2f}")
    print(f"Average bytes received: {stats.avg_bytes_received:.2f}")
    print(f"Average packets: {stats.avg_packets:.2f}")
    print(f"Protocols: {', '.join(stats.protocols)}")

    print()
    print("Suspicious flows")
    if not suspicious_flows:
        print("No suspicious flows detected.")
    for suspicious_flow in suspicious_flows:
        print(
            f"{suspicious_flow.flow.src_ip}:{suspicious_flow.flow.src_port} -> "
            f"{suspicious_flow.flow.dst_ip}:{suspicious_flow.flow.dst_port} | "
            f"score={suspicious_flow.score:.1f} | "
            f"{', '.join(suspicious_flow.reasons)}"
        )

    if args.output:
        save_suspicious_flows_csv(args.output, suspicious_flows)
        print()
        print(f"Saved suspicious flows to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
