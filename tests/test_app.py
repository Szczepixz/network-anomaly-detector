from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import FlowDataError, load_flows
from network_anomaly_detector.detector import detect_suspicious_flows
from network_anomaly_detector.export import save_suspicious_flows_csv
from network_anomaly_detector.stats import calculate_flow_stats


class NetworkAnomalyDetectorTests(unittest.TestCase):
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
        self.assertAlmostEqual(stats.avg_packets, 18.4)
        self.assertAlmostEqual(stats.std_packets, 10.150862032359615)
        self.assertEqual(stats.protocols, ["TCP", "UDP"])

    def test_detect_suspicious_flows_finds_outlier_record(self) -> None:
        flows = load_flows(ROOT / "data" / "demo_flows.csv")
        stats = calculate_flow_stats(flows)
        suspicious_flows = detect_suspicious_flows(flows, stats)

        self.assertEqual(len(suspicious_flows), 1)
        self.assertEqual(suspicious_flows[0].flow.src_ip, "10.0.0.13")
        self.assertAlmostEqual(suspicious_flows[0].score, 6.796873150257308)

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
            self.assertIn("timestamp,src_ip,dst_ip,protocol,score,reasons", content)
            self.assertIn("10.0.0.13", content)
        finally:
            if output_path.exists():
                output_path.unlink()


if __name__ == "__main__":
    unittest.main()
