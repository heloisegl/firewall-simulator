# app/engine/firewall.py
# Implements the Firewall class with Stateful Packet Inspection.
# For each packet, the firewall first checks the StateTable (O(1) hash lookup).
# Only on a cache miss does it fall back to sequential rule matching.
# Authorized connections are registered in the StateTable for fast future lookups.

from models.packet import Packet
from models.rule import Rule
from models.enums import Action
from engine.matcher import RuleMatcher
from engine.state_table import StateTable


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

    def process_packet(self, packet: Packet) -> Action:
        # --- FAST PATH: consulta a tabela de estados ---
        if self.stateful:
            existing = self.state_table.lookup(
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                source_port=packet.source_port,
                destination_port=packet.destination_port,
                protocol=packet.protocol,
            )
            if existing is not None:
                # Conexão já conhecida e autorizada: libera sem re-avaliar regras
                existing.refresh()
                return Action.ALLOW

        # --- SLOW PATH: matching sequencial de regras ---
        for rule in self.rules:
            if RuleMatcher.matches(packet, rule):
                action = rule.action

                # Se foi ALLOW e stateful está ativo, registra a conexão
                if self.stateful and action == Action.ALLOW:
                    self.state_table.register(
                        source_ip=packet.source_ip,
                        destination_ip=packet.destination_ip,
                        source_port=packet.source_port,
                        destination_port=packet.destination_port,
                        protocol=packet.protocol,
                    )

                return action

        return self.default_action