from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from network_anomaly_detector.capture import TSHARK_FIELDS
from network_anomaly_detector.convert import convert_tshark_packets_to_flows
from network_anomaly_detector.datasets import FlowDataError, load_flows


class PacketConversionTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.input = Path(directory.name) / "packets.csv"
        self.output = Path(directory.name) / "flows.csv"
        self.row = dict.fromkeys(TSHARK_FIELDS, "")
        self.row.update({"frame.time_epoch": "1700000000", "ip.src": "192.168.1.10",
                         "ip.dst": "192.168.1.1", "frame.len": "100",
                         "_ws.col.Protocol": "ICMP"})

    def write_rows(
        self, rows: list[dict[str, str]], fields: list[str] | None = None
    ) -> None:
        with self.input.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields or TSHARK_FIELDS)
            writer.writeheader()
            writer.writerows(rows)

    def convert(self, local_ip: str = "192.168.1.10") -> None:
        convert_tshark_packets_to_flows(self.input, self.output, local_ip)

    def test_capture_header_and_legacy_header_preserve_protocol(self) -> None:
        for field in ("_ws.col.Protocol", "_ws.col.protocol"):
            with self.subTest(field=field):
                row = dict(self.row)
                row[field] = row.pop("_ws.col.Protocol")
                self.write_rows([row], list(row))
                self.convert()
                self.assertEqual(load_flows(self.output)[0].protocol, "ICMP")

    def test_rejects_invalid_values_without_overwriting_output(self) -> None:
        cases = {
            "frame.len": ("", "NaN", "inf", "-1", "0", "1.5"),
            "frame.time_epoch": ("", "NaN", "inf", "1e100", "invalid"),
            "ip.src": ("", "invalid", "::1", "192.168.1.10,10.0.0.1"),
            "ip.dst": ("", "999.1.1.1"),
            "tcp.srcport": ("-1", "65536", "1.5", "80,443"),
            "udp.dstport": ("-1", "NaN"),
        }
        for column, values in cases.items():
            for value in values:
                with self.subTest(column=column, value=value):
                    self.write_rows([self.row, {**self.row, column: value}])
                    self.output.write_text("existing output", encoding="utf-8")
                    with self.assertRaisesRegex(FlowDataError, f"row 3.*{column}"):
                        self.convert()
                    self.assertEqual(self.output.read_text(), "existing output")

    def test_missing_headers_are_rejected_even_without_data(self) -> None:
        for column in ("frame.time_epoch", "ip.src", "ip.dst", "frame.len"):
            with self.subTest(column=column):
                self.write_rows([], [field for field in TSHARK_FIELDS if field != column])
                with self.assertRaisesRegex(FlowDataError, column):
                    self.convert()

    def test_non_ipv4_packets_are_skipped(self) -> None:
        self.write_rows([{**self.row, "ip.src": "", "ip.dst": ""}, self.row])
        self.convert()
        self.assertEqual(load_flows(self.output)[0].total_packets, 1)

    def test_short_flow_preserves_microsecond_duration(self) -> None:
        self.write_rows([self.row, {**self.row, "frame.time_epoch": "1700000000.000001"}])
        self.convert()
        flow = load_flows(self.output)[0]
        self.assertAlmostEqual(flow.duration_ms, 0.001)
        self.assertGreater(flow.bytes_per_second, 0)

    def test_rejects_mixed_transport_fields(self) -> None:
        self.write_rows([{**self.row, "tcp.srcport": "80", "udp.dstport": "53"}])
        with self.assertRaisesRegex(FlowDataError, "row 2.*TCP and UDP"):
            self.convert()

    def test_rejects_truncated_and_extra_fields(self) -> None:
        for values in (list(self.row.values())[:-1], list(self.row.values()) + ["extra"]):
            with self.subTest(values=values):
                self.input.write_text(
                    ",".join(TSHARK_FIELDS) + "\n" + ",".join(values) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(FlowDataError, "row 2.*number of fields"):
                    self.convert()

    def test_port_boundaries_and_reverse_packets(self) -> None:
        outgoing = {**self.row, "tcp.srcport": "0", "tcp.dstport": "65535"}
        incoming = {**outgoing, "ip.src": self.row["ip.dst"],
                    "ip.dst": self.row["ip.src"], "tcp.srcport": "65535",
                    "tcp.dstport": "0", "frame.time_epoch": "1700000001"}
        self.write_rows([incoming, outgoing])
        self.convert()
        flows = load_flows(self.output)
        self.assertEqual(len(flows), 1)
        self.assertEqual((flows[0].local_port, flows[0].remote_port), (0, 65535))
        self.assertEqual((flows[0].packets_sent, flows[0].packets_received), (1, 1))
        self.assertEqual(flows[0].duration_ms, 1000)

    def test_empty_and_non_matching_input_do_not_create_output(self) -> None:
        for rows in ([], [{**self.row, "ip.src": "", "ip.dst": ""}],
                     [{**self.row, "ip.src": "192.168.1.20"}]):
            with self.subTest(rows=rows):
                self.write_rows(rows)
                with self.assertRaises(FlowDataError):
                    self.convert()
                self.assertFalse(self.output.exists())

    def test_invalid_local_ip_is_rejected_before_reading(self) -> None:
        with patch("network_anomaly_detector.convert._load_packet_rows") as loader:
            with self.assertRaisesRegex(FlowDataError, "local IP"):
                self.convert("::1")
            loader.assert_not_called()

    def test_read_and_write_errors_use_domain_exception(self) -> None:
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            self.input.touch()
            with self.assertRaisesRegex(FlowDataError, "read"):
                self.convert()
        self.write_rows([self.row])
        self.output = Path(self.input.parent)  # Opening a directory for writing fails.
        with self.assertRaisesRegex(FlowDataError, "write"):
            self.convert()


if __name__ == "__main__":
    unittest.main()
