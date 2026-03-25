from dataclasses import dataclass
from .enums import Protocol

@dataclass(frozen=True)
class Packet:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: Protocol
