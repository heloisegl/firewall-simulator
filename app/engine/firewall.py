# app/engine/firewall.py
# Implements the Firewall class with Stateful Packet Inspection.
# For each packet, the firewall first checks the StateTable (O(1) hash lookup).
# Only on a cache miss does it fall back to sequential rule matching.
# Authorized connections are registered in the StateTable for fast future lookups.

from app.engine.matcher import RuleMatcher
from app.engine.state_table import StateTable
from app.models.decision import Decision
from app.models.enums import Action
from app.models.packet import Packet
from app.models.rule import Rule


class Firewall:
    def __init__(
        self,
        rules: list[Rule],
        default_action: Action = Action.BLOCK,
        connection_timeout: float = 60.0,
        stateful: bool = True,
    ):
        self.rules = rules
        self.default_action = default_action
        self.stateful = stateful
        self.state_table = StateTable(connection_timeout=connection_timeout)

    def process_packet(self, packet: Packet) -> Decision:
        # Fast path: allow packets from an already known active connection.
        if self.stateful:
            existing = self.state_table.lookup(
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                source_port=packet.source_port,
                destination_port=packet.destination_port,
                protocol=packet.protocol,
            )
            if existing is not None:
                existing.refresh()
                return Decision(
                    packet=packet,
                    action=Action.ALLOW,
                    decision_source="fast_path",
                )

        # Slow path: evaluate rules sequentially until the first match.
        for rule in self.rules:
            if RuleMatcher.matches(packet, rule):
                action = rule.action

                if self.stateful and action == Action.ALLOW:
                    self.state_table.register(
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        source_port=packet.source_port,
                        destination_port=packet.destination_port,
                        protocol=packet.protocol,
                    )

                return Decision(
                    packet=packet,
                    action=action,
                    decision_source="slow_path",
                    matched_rule=rule,
                )

        return Decision(
            packet=packet,
            action=self.default_action,
            decision_source="slow_path",
        )
