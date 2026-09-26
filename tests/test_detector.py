from __future__ import annotations

import sys
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from importlib.util import find_spec
from io import StringIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import load_flows
from network_anomaly_detector.detector import (
    DetectorError,
    detect_suspicious_flows,
    score_flows,
)
from network_anomaly_detector.stats import calculate_flow_stats
from main import main


HAS_SKLEARN = find_spec("sklearn") is not None


class StatisticalScoringTests(unittest.TestCase):
    def test_detected_flow_is_marked_as_suspicious(self) -> None:
        flows = load_flows(ROOT / "data" / "demo_flows.csv")
        results = detect_suspicious_flows(flows, calculate_flow_stats(flows))

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].is_suspicious)

    def test_statistical_flags_follow_the_selected_threshold(self) -> None:
        base = load_flows(ROOT / "data" / "demo_flows.csv")[0]
        flows = [replace(base, failed_logins=0), replace(base, failed_logins=1)]
        stats = calculate_flow_stats(flows)
        # Identical traffic features give scores of 0 and 1.5 (for failed logins).
        cases = [
            (0.0, [True, True], [flows[1], flows[0]]),
            (1.5, [False, True], [flows[1]]),
            (2.0, [False, False], []),
        ]
        for threshold, expected_flags, expected_flows in cases:
            with self.subTest(threshold=threshold):
                scored = score_flows(flows, stats, threshold=threshold)
                detected = detect_suspicious_flows(flows, stats, threshold=threshold)

                self.assertEqual([item.score for item in scored], [0.0, 1.5])
                self.assertEqual([item.is_suspicious for item in scored], expected_flags)
                self.assertEqual([item.flow for item in detected], expected_flows)
                self.assertTrue(all(item.is_suspicious for item in detected))


class DetectorOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.flows = load_flows(ROOT / "data" / "demo_flows.csv")
        self.stats = calculate_flow_stats(self.flows)

    def test_statistical_alerts_are_sorted_by_score(self) -> None:
        original_order = list(self.flows)

        results = detect_suspicious_flows(self.flows, self.stats, threshold=0.0)

        self.assertEqual(len(results), len(self.flows))
        self.assertEqual(results[0].flow, self.flows[3])
        for higher, lower in zip(results, results[1:]):
            self.assertGreaterEqual(higher.score, lower.score)
        self.assertEqual(self.flows, original_order)

    def test_equal_scores_keep_the_input_order(self) -> None:
        base = self.flows[0]
        first = replace(base, failed_logins=1, timestamp="2026-03-26T10:01:00")
        second = replace(base, failed_logins=1, timestamp="2026-03-26T10:02:00")
        flows = [base, first, second]

        results = detect_suspicious_flows(
            flows, calculate_flow_stats(flows), threshold=0.0
        )

        self.assertEqual([item.score for item in results], [1.5, 1.5, 0.0])
        self.assertEqual([item.flow for item in results], [first, second, base])

    @unittest.skipUnless(HAS_SKLEARN, "scikit-learn is not installed in this Python")
    def test_ml_alerts_are_sorted_by_score(self) -> None:
        for method in ("isolation-forest", "local-outlier-factor"):
            with self.subTest(method=method):
                results = detect_suspicious_flows(
                    self.flows, self.stats, method=method, contamination=0.5
                )

                self.assertGreaterEqual(len(results), 2)
                for higher, lower in zip(results, results[1:]):
                    self.assertGreaterEqual(higher.score, lower.score)


class DetectorValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.flows = load_flows(ROOT / "data" / "demo_flows.csv")
        self.stats = calculate_flow_stats(self.flows)

    def test_rejects_invalid_statistical_thresholds(self) -> None:
        for threshold in (-1.0, float("nan"), float("inf"), float("-inf")):
            with self.subTest(threshold=threshold):
                with self.assertRaisesRegex(DetectorError, "Threshold"):
                    detect_suspicious_flows(self.flows, self.stats, threshold=threshold)

    def test_rejects_invalid_ml_contamination(self) -> None:
        for method in ("isolation-forest", "local-outlier-factor"):
            for contamination in (0.0, -0.1, 0.51, float("nan"), float("inf"), float("-inf")):
                with self.subTest(method=method, contamination=contamination):
                    with self.assertRaisesRegex(DetectorError, "Contamination"):
                        detect_suspicious_flows(
                            self.flows, self.stats,
                            method=method, contamination=contamination,
                        )

    def test_zero_threshold_includes_all_flows(self) -> None:
        results = detect_suspicious_flows(self.flows, self.stats, threshold=0.0)

        self.assertCountEqual([item.flow for item in results], self.flows)

    @unittest.skipUnless(HAS_SKLEARN, "scikit-learn is not installed in this Python")
    def test_accepts_valid_contamination_boundaries(self) -> None:
        for method in ("isolation-forest", "local-outlier-factor"):
            for contamination in (0.001, 0.5):
                with self.subTest(method=method, contamination=contamination):
                    results = detect_suspicious_flows(
                        self.flows, self.stats,
                        method=method, contamination=contamination,
                    )
                    self.assertGreater(len(results), 0)
                    self.assertLess(len(results), len(self.flows))

    def test_statistical_method_ignores_unused_contamination(self) -> None:
        expected = detect_suspicious_flows(self.flows, self.stats)
        actual = detect_suspicious_flows(
            self.flows, self.stats, contamination=float("nan")
        )

        self.assertEqual(actual, expected)

    def test_cli_rejects_invalid_options_before_loading_data(self) -> None:
        cases = [
            ("analyze", ["--threshold=-1"], "Threshold"),
            ("analyze", ["--method", "isolation-forest", "--contamination", "0.9"], "Contamination"),
            ("compare-methods", ["--threshold", "nan"], "Threshold"),
            ("compare-methods", ["--contamination", "0"], "Contamination"),
        ]
        for command, options, message in cases:
            with self.subTest(command=command, options=options):
                output = StringIO()
                with patch.object(sys, "argv", ["main.py", command, *options]):
                    with patch("main.load_flows") as loader, redirect_stdout(output):
                        exit_code = main()

                self.assertEqual(exit_code, 1)
                self.assertIn(f"Error: {message}", output.getvalue())
                loader.assert_not_called()

    def test_scan_rejects_invalid_options_before_capturing_packets(self) -> None:
        cases = [
            (["--threshold", "inf"], "Threshold"),
            (["--method", "local-outlier-factor", "--contamination", "0"], "Contamination"),
        ]
        for options, message in cases:
            with self.subTest(options=options):
                output = StringIO()
                args = [
                    "main.py", "scan-tshark", "--interface", "1",
                    "--local-ip", "192.168.1.10", *options,
                ]
                with patch.object(sys, "argv", args):
                    with patch("main.capture_tshark_csv") as capture:
                        # Fail immediately if a scan starts with invalid options.
                        capture.side_effect = AssertionError("Capture should not start")
                        with redirect_stdout(output):
                            exit_code = main()

                self.assertEqual(exit_code, 1)
                self.assertIn(f"Error: {message}", output.getvalue())
                capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
