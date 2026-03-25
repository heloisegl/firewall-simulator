# Pattern for defining enums in the application (protocol and action).

from enum import Enum

class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"

class Action(Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"