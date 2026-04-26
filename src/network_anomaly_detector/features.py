from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FlowRecord:
    timestamp: str
    local_ip: str
    remote_ip: str
    local_port: int
    remote_port: int
    protocol: str
    duration_ms: float
    bytes_sent: float
    bytes_received: float
    packets_sent: float
    packets_received: float
    failed_logins: int

    @property
    def total_bytes(self) -> float:
        return self.bytes_sent + self.bytes_received

    @property
    def total_packets(self) -> float:
        return self.packets_sent + self.packets_received

    @property
    def duration_seconds(self) -> float:
        return self.duration_ms / 1000.0

    @property
    def bytes_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.total_bytes / self.duration_seconds

    @property
    def packets_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.total_packets / self.duration_seconds

    @property
    def sent_received_ratio(self) -> float:
        return (self.bytes_sent + 1.0) / (self.bytes_received + 1.0)
