from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import load_flows
from network_anomaly_detector.stats import calculate_flow_stats


def main() -> None:
    data_path = ROOT / "data" / "demo_flows.csv"
    flows = load_flows(data_path)
    stats = calculate_flow_stats(flows)

    print(f"Loaded {len(flows)} flows.")
    print(f"Average duration: {stats.avg_duration_ms:.2f} ms")
    print(f"Average bytes sent: {stats.avg_bytes_sent:.2f}")
    print(f"Average bytes received: {stats.avg_bytes_received:.2f}")
    print(f"Average packets: {stats.avg_packets:.2f}")
    print(f"Protocols: {', '.join(stats.protocols)}")

    if flows:
        print(f"First flow: {flows[0]}")


if __name__ == "__main__":
    main()
