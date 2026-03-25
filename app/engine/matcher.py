# app/engine/matcher.py
# Implements the RuleMatcher class, which contains methods to determine if a given
# network packet matches a firewall rule based on IP addresses, port, and protocol.

from app.models.packet import Packet
from app.models.rule import Rule


class RuleMatcher:
    @staticmethod
    def match_ip(packet_ip: str, rule_ip: str) -> bool:
        return rule_ip == "any" or packet_ip == rule_ip

    @staticmethod
    def match_port(packet_port: int, rule_port: str | int) -> bool:
        return rule_port == "any" or packet_port == rule_port

    @staticmethod
    def match_protocol(packet_protocol: str, rule_protocol: str) -> bool:
        return rule_protocol == "any" or packet_protocol == rule_protocol

    @classmethod
    def matches(cls, packet: Packet, rule: Rule) -> bool:
        return (
            cls.match_ip(packet.source_ip, rule.source_ip)
            and cls.match_ip(packet.destination_ip, rule.destination_ip)
            and cls.match_port(packet.destination_port, rule.port)  # atualizado
            and cls.match_protocol(packet.protocol.value, rule.protocol)
        )
