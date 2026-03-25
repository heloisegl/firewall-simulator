# app/models/packet.py
# Defines the Packet data class: a network packet with its source and destination IP
# addresses, source port, destination port, and protocol.

from dataclasses import dataclass
from .enums import Protocol


@dataclass(frozen=True)
class Packet:
    source_ip: str
    destination_ip: str
    source_port: int        # NOVO: porta de origem (necessária para a 5-tupla)
    destination_port: int   # renomeado de 'port' para semântica correta
    protocol: Protocol