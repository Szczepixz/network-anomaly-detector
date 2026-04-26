from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.capture import (
    TSHARK_FIELDS,
    build_tshark_command,
    build_tshark_list_interfaces_command,
)
from network_anomaly_detector.datasets import FlowDataError, load_flows
from network_anomaly_detector.detector import detect_suspicious_flows
from network_anomaly_detector.convert import convert_tshark_packets_to_flows
from network_anomaly_detector.export import save_suspicious_flows_csv
from network_anomaly_detector.stats import calculate_flow_stats
from main import build_scan_paths, cleanup_scan_files


class NetworkAnomalyDetectorTests(unittest.TestCase):
    def test_build_scan_paths_uses_custom_paths(self) -> None:
        paths = build_scan_paths(
            packet_output="data/custom_packets.csv",
            flow_output="output/custom_flows.csv",
        )

        self.assertEqual(paths["packet_output"], "data/custom_packets.csv")
        self.assertEqual(paths["flow_output"], "output/custom_flows.csv")

    def test_build_scan_paths_generates_default_paths(self) -> None:
        paths = build_scan_paths(packet_output=None, flow_output=None)

        self.assertIn("real_tshark_packets_", paths["packet_output"])
        self.assertIn("real_flows_", paths["flow_output"])
        self.assertTrue(paths["packet_output"].endswith(".csv"))
        self.assertTrue(paths["flow_output"].endswith(".csv"))

    def test_cleanup_scan_files_removes_packet_and_flow_files(self) -> None:
        packet_path = ROOT / "tests" / "tmp_packet.csv"
        flow_path = ROOT / "tests" / "tmp_flow.csv"
        packet_path.write_text("packet", encoding="utf-8")
        flow_path.write_text("flow", encoding="utf-8")

        cleanup_scan_files(
            {
                "packet_output": str(packet_path),
                "flow_output": str(flow_path),
            }
        )

        self.assertFalse(packet_path.exists())
        self.assertFalse(flow_path.exists())

    def test_build_tshark_command_contains_expected_fields(self) -> None:
        command = build_tshark_command(
            tshark_path="tshark",
            interface="7",
            packet_count=50,
        )

        self.assertIn("-i", command)
        self.assertIn("7", command)
        self.assertIn("-c", command)
        self.assertIn("50", command)
        for field in TSHARK_FIELDS:
            self.assertIn(field, command)

    def test_build_tshark_list_interfaces_command(self) -> None:
        command = build_tshark_list_interfaces_command("tshark")

        self.assertEqual(command, ["tshark", "-D"])

    def test_load_flows_reads_all_records(self) -> None:
        flows = load_flows(ROOT / "data" / "demo_flows.csv")

        self.assertEqual(len(flows), 5)
        self.assertEqual(flows[0].protocol, "TCP")
        self.assertEqual(flows[2].protocol, "UDP")

    def test_calculate_flow_stats_returns_expected_values(self) -> None:
        flows = load_flows(ROOT / "data" / "demo_flows.csv")
        stats = calculate_flow_stats(flows)

        self.assertEqual(stats.flow_count, 5)
        self.assertAlmostEqual(stats.avg_duration_ms, 197.0)
        self.assertAlmostEqual(stats.std_duration_ms, 132.87588193498473)
        self.assertAlmostEqual(stats.avg_bytes_sent, 1900.0)
        self.assertAlmostEqual(stats.std_bytes_sent, 1063.954886261631)
        self.assertAlmostEqual(stats.avg_bytes_received, 6700.0)
        self.assertAlmostEqual(stats.std_bytes_received, 3798.947222586805)
        self.assertAlmostEqual(stats.avg_total_bytes, 8600.0)
        self.assertAlmostEqual(stats.std_total_bytes, 4850.15463671005)
        self.assertAlmostEqual(stats.avg_packets_total, 18.4)
        self.assertAlmostEqual(stats.std_packets_total, 10.150862032359615)
        self.assertAlmostEqual(stats.avg_bytes_per_second, 46797.32762137903)
        self.assertAlmostEqual(stats.std_bytes_per_second, 8740.693249903614)
        self.assertAlmostEqual(stats.avg_packets_per_second, 102.35437654960299)
        self.assertAlmostEqual(stats.std_packets_per_second, 15.621409253155031)
        self.assertAlmostEqual(stats.avg_sent_received_ratio, 0.29360731705225507)
        self.assertAlmostEqual(stats.std_sent_received_ratio, 0.040984608239216895)
        self.assertEqual(stats.protocols, ["TCP", "UDP"])

    def test_detect_suspicious_flows_finds_outlier_record(self) -> None:
        flows = load_flows(ROOT / "data" / "demo_flows.csv")
        stats = calculate_flow_stats(flows)
        suspicious_flows = detect_suspicious_flows(flows, stats)

        self.assertEqual(len(suspicious_flows), 1)
        self.assertEqual(suspicious_flows[0].flow.local_ip, "10.0.0.13")
        self.assertAlmostEqual(suspicious_flows[0].score, 8.58, places=2)

    def test_load_flows_raises_error_for_missing_file(self) -> None:
        with self.assertRaises(FlowDataError):
            load_flows(ROOT / "data" / "missing.csv")

    def test_save_suspicious_flows_csv_creates_output_file(self) -> None:
        flows = load_flows(ROOT / "data" / "demo_flows.csv")
        stats = calculate_flow_stats(flows)
        suspicious_flows = detect_suspicious_flows(flows, stats)
        output_path = ROOT / "tests" / "tmp_suspicious_flows.csv"

        try:
            save_suspicious_flows_csv(output_path, suspicious_flows)

            self.assertTrue(output_path.exists())
            content = output_path.read_text(encoding="utf-8")
            self.assertIn(
                "timestamp,local_ip,remote_ip,local_port,remote_port,protocol,score,reasons",
                content,
            )
            self.assertIn("10.0.0.13", content)
        finally:
            if output_path.exists():
                output_path.unlink()

    def test_convert_tshark_packets_to_flows_creates_flow_csv(self) -> None:
        output_path = ROOT / "tests" / "tmp_converted_flows.csv"

        try:
            convert_tshark_packets_to_flows(
                ROOT / "data" / "tshark_packets_sample.csv",
                output_path,
                local_ip="192.168.33.16",
            )
            flows = load_flows(output_path)

            self.assertEqual(len(flows), 3)
            self.assertEqual(flows[0].local_ip, "192.168.33.16")
            self.assertEqual(flows[0].local_port, 5353)
            self.assertEqual(flows[0].remote_port, 5353)
            self.assertEqual(flows[0].bytes_sent, 62.0)
            self.assertEqual(flows[0].bytes_received, 80.0)
            self.assertEqual(flows[2].bytes_sent, 10000.0)
            self.assertEqual(flows[2].bytes_received, 6100.0)
            self.assertEqual(flows[2].packets_sent, 2.0)
            self.assertEqual(flows[2].packets_received, 1.0)
        finally:
            if output_path.exists():
                output_path.unlink()

    def test_convert_tshark_packets_handles_missing_ports(self) -> None:
        input_path = ROOT / "tests" / "tmp_packets_missing_ports.csv"
        output_path = ROOT / "tests" / "tmp_flows_missing_ports.csv"

        try:
            input_path.write_text(
                "\n".join(
                    [
                        "frame.time_epoch,ip.src,ip.dst,_ws.col.protocol,frame.len,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport",
                        "1775942574.783329000,192.168.1.10,192.168.1.1,,98,,,,",
                    ]
                ),
                encoding="utf-8",
            )

            convert_tshark_packets_to_flows(
                input_path,
                output_path,
                local_ip="192.168.1.10",
            )
            flows = load_flows(output_path)

            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0].local_port, 0)
            self.assertEqual(flows[0].remote_port, 0)
            self.assertEqual(flows[0].protocol, "UNKNOWN")
        finally:
            if input_path.exists():
                input_path.unlink()
            if output_path.exists():
                output_path.unlink()


if __name__ == "__main__":
    unittest.main()
