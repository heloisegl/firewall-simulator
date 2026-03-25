# Defines the Decision data class, which represents the outcome of evaluating
# a packet against the firewall rules, including the action taken, the matched
# rule (if any), and whether the result came from the fast or slow path.

from dataclasses import dataclass
from typing import Literal
from .enums import Action
from .packet import Packet
from .rule import Rule

@dataclass
class Decision:
    packet: Packet
    action: Action
    decision_source: Literal["fast_path", "slow_path"]
    matched_rule: Rule | None = None
