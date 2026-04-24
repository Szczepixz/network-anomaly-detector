from __future__ import annotations

import subprocess
from pathlib import Path

from .datasets import FlowDataError


TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "frame.len",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
]


def build_tshark_command(
    tshark_path: str,
    interface: str,
    packet_count: int,
) -> list[str]:
    command = [
        tshark_path,
        "-i",
        interface,
        "-c",
        str(packet_count),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
    ]

    for field in TSHARK_FIELDS:
        command.extend(["-e", field])

    return command


def build_tshark_list_interfaces_command(tshark_path: str) -> list[str]:
    return [tshark_path, "-D"]


def list_tshark_interfaces(tshark_path: str = "tshark") -> str:
    command = build_tshark_list_interfaces_command(tshark_path)

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    except FileNotFoundError as error:
        raise FlowDataError(f"tshark executable was not found: {tshark_path}") from error
    except subprocess.CalledProcessError as error:
        raise FlowDataError(
            f"tshark interface listing failed with exit code {error.returncode}"
        ) from error

    return result.stdout.strip()


def capture_tshark_csv(
    output_path: str | Path,
    interface: str,
    packet_count: int,
    tshark_path: str = "tshark",
) -> None:
    if packet_count <= 0:
        raise FlowDataError("Packet count must be greater than zero.")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    command = build_tshark_command(
        tshark_path=tshark_path,
        interface=interface,
        packet_count=packet_count,
    )

    try:
        with path.open("w", encoding="utf-8", newline="") as handle:
            subprocess.run(command, stdout=handle, check=True)
    except FileNotFoundError as error:
        raise FlowDataError(f"tshark executable was not found: {tshark_path}") from error
    except subprocess.CalledProcessError as error:
        raise FlowDataError(f"tshark capture failed with exit code {error.returncode}") from error
