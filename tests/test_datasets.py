from __future__ import annotations

import csv
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import FlowDataError, load_flows
from main import main


class FlowDataValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.input_path = Path(directory.name) / "flows.csv"
        with (ROOT / "data" / "demo_flows.csv").open(newline="", encoding="utf-8") as handle:
            self.valid_row = next(csv.DictReader(handle))

    def write_rows(self, rows: list[dict[str, str]]) -> None:
        with self.input_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

    def test_rejects_invalid_measurements_with_row_and_column(self) -> None:
        columns = (
            "duration_ms", "bytes_sent", "bytes_received",
            "packets_sent", "packets_received",
        )
        for column in columns:
            for value in ("NaN", "inf", "-inf", "-1", "not-a-number"):
                with self.subTest(column=column, value=value):
                    self.write_rows([self.valid_row, {**self.valid_row, column: value}])
                    with self.assertRaisesRegex(FlowDataError, f"row 3.*{column}"):
                        load_flows(self.input_path)

    def test_rejects_invalid_ports_and_failed_logins(self) -> None:
        for column in ("local_port", "remote_port", "failed_logins"):
            values = ["-1", "NaN", "inf", "1.5", "not-a-number"]
            if column != "failed_logins":
                values.append("65536")
            for value in values:
                with self.subTest(column=column, value=value):
                    self.write_rows([{**self.valid_row, column: value}])
                    with self.assertRaisesRegex(FlowDataError, f"row 2.*{column}"):
                        load_flows(self.input_path)

    def test_rejects_empty_or_missing_required_numeric_values(self) -> None:
        for column in ("duration_ms", "bytes_sent", "bytes_received", "failed_logins"):
            for missing in (False, True):
                with self.subTest(column=column, missing=missing):
                    row = {**self.valid_row, column: ""}
                    if missing:
                        del row[column]
                    self.write_rows([row])
                    with self.assertRaisesRegex(FlowDataError, f"row 2.*{column}"):
                        load_flows(self.input_path)

    def test_rejects_a_row_with_missing_trailing_values(self) -> None:
        self.input_path.write_text(
            ",".join(self.valid_row) + "\n"
            + ",".join(list(self.valid_row.values())[:-1]) + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(FlowDataError, "row 2.*failed_logins"):
            load_flows(self.input_path)

    def test_accepts_zero_measurements_and_port_boundaries(self) -> None:
        row = dict(self.valid_row)
        for column in (
            "duration_ms", "bytes_sent", "bytes_received",
            "packets_sent", "packets_received", "failed_logins",
        ):
            row[column] = "0"
        row.update(local_port="0", remote_port="65535")
        self.write_rows([row])

        flow = load_flows(self.input_path)[0]

        self.assertEqual(flow.local_port, 0)
        self.assertEqual(flow.remote_port, 65535)
        self.assertEqual(flow.duration_ms, 0)
        self.assertEqual(flow.total_bytes, 0)
        self.assertEqual(flow.total_packets, 0)
        self.assertEqual(flow.failed_logins, 0)

    def test_keeps_legacy_columns_and_optional_defaults(self) -> None:
        row = dict(self.valid_row)
        for current, legacy in (
            ("local_ip", "src_ip"), ("remote_ip", "dst_ip"),
            ("local_port", "src_port"), ("remote_port", "dst_port"),
            ("packets_sent", "packets"),
        ):
            row[legacy] = row.pop(current)
        del row["packets_received"]
        row["src_port"] = ""
        self.write_rows([row])

        flow = load_flows(self.input_path)[0]

        self.assertEqual(flow.local_ip, self.valid_row["local_ip"])
        self.assertEqual(flow.local_port, 0)
        self.assertEqual(flow.remote_port, 443)
        self.assertEqual(flow.packets_sent, 5)
        self.assertEqual(flow.packets_received, 0)

    def test_rejects_invalid_values_in_legacy_columns(self) -> None:
        for current, legacy in (
            ("local_port", "src_port"), ("remote_port", "dst_port"),
            ("packets_sent", "packets"),
        ):
            with self.subTest(column=legacy):
                row = dict(self.valid_row)
                del row[current]
                row[legacy] = "-1"
                self.write_rows([row])
                with self.assertRaisesRegex(FlowDataError, f"row 2.*{legacy}"):
                    load_flows(self.input_path)

    def test_cli_reports_invalid_data_without_a_traceback(self) -> None:
        self.write_rows([{**self.valid_row, "duration_ms": "NaN"}])
        output = StringIO()
        args = ["main.py", "analyze", "--input", str(self.input_path)]
        with patch.object(sys, "argv", args):
            with redirect_stdout(output):
                exit_code = main()

        self.assertEqual(exit_code, 1)
        self.assertIn("row 2", output.getvalue())
        self.assertIn("duration_ms", output.getvalue())


if __name__ == "__main__":
    unittest.main()
