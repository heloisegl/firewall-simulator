from dataclasses import dataclass, field
from time import time
from .enums import Protocol

@dataclass
class ConnectionKey:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: Protocol

    def __hash__(self):
        return hash((self.source_ip, self.destination_ip, self.source_port, self.destination_port, self.protocol))

    def __eq__(self, other):
        return (
            self.source_ip == other.source_ip
            and self.destination_ip == other.destination_ip
            and self.source_port == other.source_port
            and self.destination_port == other.destination_port
            and self.protocol == other.protocol
        )

@dataclass
class ConnectionState:
    key: ConnectionKey
    created_at: float = field(default_factory=time)
    last_seen: float = field(default_factory=time)
    packet_count: int = 1

    def refresh(self):
        self.last_seen = time()
        self.packet_count += 1

    def is_expired(self, timeout: float) -> bool:
        return (time() - self.last_seen) > timeout
