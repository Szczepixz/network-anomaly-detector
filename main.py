from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.capture import capture_tshark_csv, list_tshark_interfaces
from network_anomaly_detector.datasets import FlowDataError, load_flows
from network_anomaly_detector.detector import (
    DetectorError,
    SUPPORTED_METHODS,
    detect_suspicious_flows,
)
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
        help="Minimum anomaly score used by the statistical method.",
    )
    analyze_parser.add_argument(
        "--method",
        choices=SUPPORTED_METHODS,
        default="statistical",
        help="Detection method.",
    )
    analyze_parser.add_argument(
        "--contamination",
        type=float,
        default=0.2,
        help="Expected anomaly ratio for Isolation Forest.",
    )
    analyze_parser.add_argument(
        "--output",
        help="Optional path to save suspicious flows as CSV.",
    )

    compare_parser = subparsers.add_parser(
        "compare-methods",
        help="Run all detection methods on the same flow CSV and compare the results.",
    )
    compare_parser.add_argument(
        "--input",
        default=str(ROOT / "data" / "demo_flows.csv"),
        help="Path to the CSV file with flow data.",
    )
    compare_parser.add_argument(
        "--threshold",
        type=float,
        default=4.0,
        help="Minimum anomaly score used by the statistical method.",
    )
    compare_parser.add_argument(
        "--contamination",
        type=float,
        default=0.2,
        help="Expected anomaly ratio for ML methods.",
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
    convert_parser.add_argument(
        "--local-ip",
        required=True,
        help="Local IP address used to build bidirectional flows.",
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

    interfaces_parser = subparsers.add_parser(
        "list-interfaces",
        help="List available tshark capture interfaces.",
    )
    interfaces_parser.add_argument(
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
        "--local-ip",
        required=True,
        help="Local IP address used to build bidirectional flows.",
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
        help="Minimum anomaly score used by the statistical method.",
    )
    scan_parser.add_argument(
        "--method",
        choices=SUPPORTED_METHODS,
        default="statistical",
        help="Detection method.",
    )
    scan_parser.add_argument(
        "--contamination",
        type=float,
        default=0.2,
        help="Expected anomaly ratio for Isolation Forest.",
    )
    scan_parser.add_argument(
        "--packet-output",
        help="Path where the captured packet CSV should be saved.",
    )
    scan_parser.add_argument(
        "--flow-output",
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
    scan_parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove packet and flow CSV files after the scan.",
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


def list_interfaces_command(args: argparse.Namespace) -> int:
    try:
        output = list_tshark_interfaces(tshark_path=args.tshark_path)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    print("Available interfaces")
    print(output)
    return 0


def convert_tshark_command(args: argparse.Namespace) -> int:
    try:
        convert_tshark_packets_to_flows(args.input, args.output, local_ip=args.local_ip)
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
    try:
        suspicious_flows = detect_suspicious_flows(
            flows,
            stats,
            threshold=args.threshold,
            method=args.method,
            contamination=args.contamination,
        )
    except DetectorError as error:
        print(f"Error: {error}")
        return 1

    print_analysis(
        input_path=args.input,
        flows=flows,
        suspicious_flows=suspicious_flows,
        stats=stats,
        method=args.method,
        threshold=args.threshold,
        contamination=args.contamination,
    )

    if args.output:
        save_suspicious_flows_csv(args.output, suspicious_flows)
        print()
        print(f"Saved suspicious flows to: {args.output}")

    return 0


def compare_methods_command(args: argparse.Namespace) -> int:
    try:
        flows = load_flows(args.input)
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    stats = calculate_flow_stats(flows)
    results: dict[str, list] = {}

    for method in SUPPORTED_METHODS:
        try:
            results[method] = detect_suspicious_flows(
                flows,
                stats,
                threshold=args.threshold,
                method=method,
                contamination=args.contamination,
            )
        except DetectorError as error:
            print(f"Error in {method}: {error}")
            return 1

    print_method_comparison(
        input_path=args.input,
        total_flows=len(flows),
        threshold=args.threshold,
        contamination=args.contamination,
        results=results,
    )
    return 0


def scan_tshark_command(args: argparse.Namespace) -> int:
    scan_paths = build_scan_paths(
        packet_output=args.packet_output,
        flow_output=args.flow_output,
    )

    try:
        capture_tshark_csv(
            output_path=scan_paths["packet_output"],
            interface=args.interface,
            packet_count=args.count,
            tshark_path=args.tshark_path,
        )
        convert_tshark_packets_to_flows(
            scan_paths["packet_output"],
            scan_paths["flow_output"],
            local_ip=args.local_ip,
        )
        flows = load_flows(scan_paths["flow_output"])
    except FlowDataError as error:
        print(f"Error: {error}")
        return 1

    stats = calculate_flow_stats(flows)
    try:
        suspicious_flows = detect_suspicious_flows(
            flows,
            stats,
            threshold=args.threshold,
            method=args.method,
            contamination=args.contamination,
        )
    except DetectorError as error:
        print(f"Error: {error}")
        return 1

    print("Scan files")
    print(f"Packet CSV: {scan_paths['packet_output']}")
    print(f"Flow CSV: {scan_paths['flow_output']}")
    if args.output:
        print(f"Suspicious CSV: {args.output}")
    print()
    print_analysis(
        input_path=scan_paths["flow_output"],
        flows=flows,
        suspicious_flows=suspicious_flows,
        stats=stats,
        method=args.method,
        threshold=args.threshold,
        contamination=args.contamination,
    )

    if args.output:
        save_suspicious_flows_csv(args.output, suspicious_flows)
        print()
        print("Saved suspicious flows.")

    if args.cleanup:
        cleanup_scan_files(scan_paths)
        print()
        print("Cleaned up packet and flow CSV files.")

    return 0


def build_scan_paths(
    packet_output: str | None,
    flow_output: str | None,
) -> dict[str, str]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return {
        "packet_output": packet_output
        or str(ROOT / "data" / f"real_tshark_packets_{timestamp}.csv"),
        "flow_output": flow_output
        or str(ROOT / "output" / f"real_flows_{timestamp}.csv"),
    }


def cleanup_scan_files(scan_paths: dict[str, str]) -> None:
    for key in ("packet_output", "flow_output"):
        path = Path(scan_paths[key])
        if path.exists():
            path.unlink()


def print_analysis(
    input_path: str,
    flows: list,
    suspicious_flows: list,
    stats,
    method: str,
    threshold: float,
    contamination: float,
) -> None:
    print("Summary")
    print(f"Input file: {input_path}")
    print(f"Method: {method}")
    print(f"Loaded flows: {len(flows)}")
    if method == "statistical":
        print(f"Threshold: {threshold:.1f}")
    else:
        print(f"Contamination: {contamination:.2f}")
    print(f"Suspicious flows: {len(suspicious_flows)}")

    print()
    print("Traffic stats")
    print(f"Average duration: {stats.avg_duration_ms:.2f} ms")
    print(f"Average bytes sent: {stats.avg_bytes_sent:.2f}")
    print(f"Average bytes received: {stats.avg_bytes_received:.2f}")
    print(f"Average total bytes: {stats.avg_total_bytes:.2f}")
    print(f"Average packets: {stats.avg_packets_total:.2f}")
    print(f"Average bytes/sec: {stats.avg_bytes_per_second:.2f}")
    print(f"Average packets/sec: {stats.avg_packets_per_second:.2f}")
    print(f"Average sent/received ratio: {stats.avg_sent_received_ratio:.2f}")
    print(f"Protocols: {', '.join(stats.protocols)}")

    print()
    print("Suspicious flows")
    if not suspicious_flows:
        print("No suspicious flows detected.")
    for suspicious_flow in suspicious_flows:
        print(
            f"{suspicious_flow.flow.local_ip}:{suspicious_flow.flow.local_port} <-> "
            f"{suspicious_flow.flow.remote_ip}:{suspicious_flow.flow.remote_port} | "
            f"protocol={suspicious_flow.flow.protocol} | "
            f"score={format_score(suspicious_flow.score)} | "
            f"{', '.join(suspicious_flow.reasons)}"
        )


def print_method_comparison(
    input_path: str,
    total_flows: int,
    threshold: float,
    contamination: float,
    results: dict[str, list],
) -> None:
    print("Method comparison")
    print(f"Input file: {input_path}")
    print(f"Loaded flows: {total_flows}")
    print(f"Statistical threshold: {threshold:.1f}")
    print(f"ML contamination: {contamination:.2f}")
    print()
    print_method_agreement(results)

    for method in SUPPORTED_METHODS:
        suspicious_flows = results[method]
        print()
        print(method)
        print(f"Suspicious flows: {len(suspicious_flows)}")
        if not suspicious_flows:
            print("No suspicious flows detected.")
            continue

        for suspicious_flow in suspicious_flows[:3]:
            print(
                f"{suspicious_flow.flow.local_ip}:{suspicious_flow.flow.local_port} <-> "
                f"{suspicious_flow.flow.remote_ip}:{suspicious_flow.flow.remote_port} | "
                f"protocol={suspicious_flow.flow.protocol} | "
                f"score={format_score(suspicious_flow.score)} | "
                f"{', '.join(suspicious_flow.reasons)}"
            )


def print_method_agreement(results: dict[str, list]) -> None:
    print("Method agreement")

    detections_by_flow: dict[tuple[str, str, int, str, str, int], set[str]] = {}

    for method, suspicious_flows in results.items():
        for suspicious_flow in suspicious_flows:
            key = build_flow_key(suspicious_flow.flow)
            detections_by_flow.setdefault(key, set()).add(method)

    groups = {
        "Detected by all methods": [],
        "Detected by two methods": [],
        "Detected by one method": [],
    }

    for key, methods in detections_by_flow.items():
        flow_summary = format_flow_key(key)
        method_list = ", ".join(sorted(methods))
        line = f"{flow_summary} | methods={method_list}"

        if len(methods) == len(SUPPORTED_METHODS):
            groups["Detected by all methods"].append(line)
        elif len(methods) == 2:
            groups["Detected by two methods"].append(line)
        else:
            groups["Detected by one method"].append(line)

    for title, lines in groups.items():
        print(title)
        if not lines:
            print("None")
            continue
        for line in lines:
            print(line)


def build_flow_key(flow) -> tuple[str, str, int, str, str, int]:
    return (
        flow.local_ip,
        flow.remote_ip,
        flow.remote_port,
        flow.protocol,
        flow.timestamp,
        flow.local_port,
    )


def format_flow_key(flow_key: tuple[str, str, int, str, str, int]) -> str:
    local_ip, remote_ip, remote_port, protocol, timestamp, local_port = flow_key
    return (
        f"{local_ip}:{local_port} <-> {remote_ip}:{remote_port} | "
        f"protocol={protocol} | timestamp={timestamp}"
    )


def format_score(score: float) -> str:
    if score < 1:
        return f"{score:.3f}"
    return f"{score:.1f}"


def main() -> int:
    args = parse_args()

    if args.command == "analyze":
        return analyze_command(args)
    if args.command == "compare-methods":
        return compare_methods_command(args)
    if args.command == "convert-tshark":
        return convert_tshark_command(args)
    if args.command == "capture-tshark":
        return capture_tshark_command(args)
    if args.command == "list-interfaces":
        return list_interfaces_command(args)
    if args.command == "scan-tshark":
        return scan_tshark_command(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
