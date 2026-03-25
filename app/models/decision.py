# Defines the Decision data class, which represents the outcome of evaluating a packet against the firewall rules, including the action taken and the matched rule (if any).

from dataclasses import dataclass
from .enums import Action
from .packet import Packet
from .rule import Rule

@dataclass
class Decision:
    packet: Packet
    action: Action
    matched_rule: Rule | None = None