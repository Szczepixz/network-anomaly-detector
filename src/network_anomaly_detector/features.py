from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FlowRecord:
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration_ms: float
    bytes_sent: float
    bytes_received: float
    packets: float
    failed_logins: int

    @property
    def total_bytes(self) -> float:
        return self.bytes_sent + self.bytes_received
