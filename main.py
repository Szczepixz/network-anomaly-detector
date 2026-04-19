from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.capture import capture_tshark_csv
from network_anomaly_detector.datasets import FlowDataError, load_flows
from network_anomaly_detector.detector import detect_suspicious_flows
from network_anomaly_detector.convert import convert_tshark_packets_to_flows
from network_anomaly_detector.export import save_suspicious_flows_csv
from network_anomaly_detector.stats import calculate_flow_stats


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Network anomaly detector.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze flow CSV data.")
    analyze_parser.add_argument(
        "--input",
        default=str(ROOT / "data" / "demo_flows.csv"),
        help="Path to the CSV file with flow data.",
    )
    analyze_parser.add_argument(
        "--threshold",
        type=float,
        default=4.0,
        help="Minimum anomaly score required to mark a flow as suspicious.",
    )
    analyze_parser.add_argument(
        "--output",
        help="Optional path to save suspicious flows as CSV.",
    )

    convert_parser = subparsers.add_parser(
        "convert-tshark",
        help="Convert a tshark packet CSV into the flow CSV format.",
    )
    convert_parser.add_argument(
        "--input",
        required=True,
        help="Path to the tshark packet CSV file.",
    )
    convert_parser.add_argument(
        "--output",
        required=True,
        help="Path where the converted flow CSV should be saved.",
    )

    capture_parser = subparsers.add_parser(
        "capture-tshark",
        help="Capture packets with tshark and save them as CSV.",
    )
    capture_parser.add_argument(
        "--interface",
        required=True,
        help="tshark interface number or name.",
    )
    capture_parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of packets to capture.",
    )
    capture_parser.add_argument(
        "--output",
        required=True,
        help="Path where the captured packet CSV should be saved.",
    )
    capture_parser.add_argument(
        "--tshark-path",
        default="tshark",
        help="Path to tshark executable.",
    )

    scan_parser = subparsers.add_parser(
        "scan-tshark",
        help="Capture a packet sample with tshark, convert it, and analyze it.",
    )
    scan_parser.add_argument(
        "--interface",
        required=True,
        help="tshark interface number or name.",
    )
    scan_parser.add_argument(
        "--count",
        type=int,
        default=50,
        help="Number of packets to capture.",
    )
    scan_parser.add_argument(
        "--threshold",
        type=float,
        default=2.0,
        help="Minimum anomaly score required to mark a flow as suspicious.",
    )
    scan_parser.add_argument(
        "--packet-output",
        default=str(ROOT / "data" / "real_tshark_packets.csv"),
        help="Path where the captured packet CSV should be saved.",
    )
    scan_parser.add_argument(
        "--flow-output",
        default=str(ROOT / "output" / "real_flows.csv"),
        help="Path where the converted flow CSV should be saved.",
    )
    scan_parser.add_argument(
        "--output",
        help="Optional path to save suspicious flows as CSV.",
    )
    scan_parser.add_argument(
        "--tshark-path",
        default="tshark",
        help="Path to tshark executable.",
    )
    return parser.parse_args()


def capture_tshark_command(args: argparse.Namespace) -> int:
    try:
        capture_tshark_csv(
            output_path=args.output,
            interface=args.interface,
            packet_count=args.count,
            tshark_path=args.tshark_path,
        )
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    print(f"Captured tshark CSV: {args.output}")
    return 0


def convert_tshark_command(args: argparse.Namespace) -> int:
    try:
        convert_tshark_packets_to_flows(args.input, args.output)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    print(f"Converted tshark CSV to flow CSV: {args.output}")
    return 0


def analyze_command(args: argparse.Namespace) -> int:
    try:
        flows = load_flows(args.input)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    stats = calculate_flow_stats(flows)
    suspicious_flows = detect_suspicious_flows(flows, stats, threshold=args.threshold)
    print_analysis(
        input_path=args.input,
        threshold=args.threshold,
        flows=flows,
        suspicious_flows=suspicious_flows,
        stats=stats,
    )

    if args.output:
        save_suspicious_flows_csv(args.output, suspicious_flows)
        print()
        print(f"Saved suspicious flows to: {args.output}")

    return 0


def scan_tshark_command(args: argparse.Namespace) -> int:
    try:
        capture_tshark_csv(
            output_path=args.packet_output,
            interface=args.interface,
            packet_count=args.count,
            tshark_path=args.tshark_path,
        )
        convert_tshark_packets_to_flows(args.packet_output, args.flow_output)
        flows = load_flows(args.flow_output)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    stats = calculate_flow_stats(flows)
    suspicious_flows = detect_suspicious_flows(flows, stats, threshold=args.threshold)

    print("Scan files")
    print(f"Packet CSV: {args.packet_output}")
    print(f"Flow CSV: {args.flow_output}")
    if args.output:
        print(f"Suspicious CSV: {args.output}")
    print()
    print_analysis(
        input_path=args.flow_output,
        threshold=args.threshold,
        flows=flows,
        suspicious_flows=suspicious_flows,
        stats=stats,
    )

    if args.output:
        save_suspicious_flows_csv(args.output, suspicious_flows)
        print()
        print("Saved suspicious flows.")

    return 0


def print_analysis(
    input_path: str,
    threshold: float,
    flows: list,
    suspicious_flows: list,
    stats,
) -> None:
    print("Summary")
    print(f"Input file: {input_path}")
    print(f"Loaded flows: {len(flows)}")
    print(f"Threshold: {threshold:.1f}")
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


def main() -> int:
    args = parse_args()

    if args.command == "convert-tshark":
        return convert_tshark_command(args)
    if args.command == "capture-tshark":
        return capture_tshark_command(args)
    if args.command == "scan-tshark":
        return scan_tshark_command(args)

    return analyze_command(args)


if __name__ == "__main__":
    raise SystemExit(main())
