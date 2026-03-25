# Defines the Rule data class

from dataclasses import dataclass
from .enums import Action

@dataclass(frozen=True)
class Rule:
    action: Action
    source_ip: str = "any"
    destination_ip: str = "any"
    port: str | int = "any"
    protocol: str = "any"