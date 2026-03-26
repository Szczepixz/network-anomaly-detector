from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from network_anomaly_detector.datasets import load_flows


def main() -> None:
    data_path = ROOT / "data" / "demo_flows.csv"
    flows = load_flows(data_path)

    print(f"Loaded {len(flows)} flows.")
    if flows:
        print(f"First flow: {flows[0]}")


if __name__ == "__main__":
    main()
