import json
import tempfile
import unittest
from pathlib import Path

from app.engine.firewall import Firewall
from app.models.enums import Action, Protocol
from app.models.packet import Packet
from app.models.rule import Rule
from app.parser.packets_parser import load_packets


class FirewallTestCase(unittest.TestCase):
    def setUp(self):
        self.rules = [
            Rule(action=Action.BLOCK, port=23, protocol="TCP"),
            Rule(action=Action.ALLOW, port=80, protocol="TCP"),
            Rule(action=Action.ALLOW, port=53, protocol="UDP"),
        ]
        self.firewall = Firewall(rules=self.rules, default_action=Action.BLOCK, stateful=True)

    def test_allows_packet_that_matches_allow_rule(self):
        packet = Packet(
            source_ip="10.0.0.10",
            destination_ip="192.168.0.1",
            source_port=54321,
            destination_port=80,
            protocol=Protocol.TCP,
        )

        result = self.firewall.process_packet(packet)

        self.assertEqual(result.action, Action.ALLOW)
        self.assertEqual(result.decision_source, "slow_path")
        self.assertEqual(result.matched_rule, self.rules[1])

    def test_blocks_packet_that_matches_block_rule(self):
        packet = Packet(
            source_ip="10.0.0.11",
            destination_ip="192.168.0.1",
            source_port=54322,
            destination_port=23,
            protocol=Protocol.TCP,
        )

        result = self.firewall.process_packet(packet)

        self.assertEqual(result.action, Action.BLOCK)
        self.assertEqual(result.decision_source, "slow_path")
        self.assertEqual(result.matched_rule, self.rules[0])

    def test_blocks_packet_when_no_rule_matches(self):
        packet = Packet(
            source_ip="10.0.0.13",
            destination_ip="192.168.0.1",
            source_port=54324,
            destination_port=22,
            protocol=Protocol.TCP,
        )

        result = self.firewall.process_packet(packet)

        self.assertEqual(result.action, Action.BLOCK)
        self.assertEqual(result.decision_source, "slow_path")
        self.assertIsNone(result.matched_rule)

    def test_registers_allowed_connection_in_state_table(self):
        packet = Packet(
            source_ip="10.0.0.12",
            destination_ip="8.8.8.8",
            source_port=54323,
            destination_port=53,
            protocol=Protocol.UDP,
        )

        decision = self.firewall.process_packet(packet)
        state = self.firewall.state_table.lookup(
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
        )

        self.assertIsNotNone(state)
        self.assertEqual(self.firewall.state_table.active_connections, 1)
        self.assertEqual(decision.action, Action.ALLOW)
        self.assertEqual(decision.decision_source, "slow_path")
        self.assertEqual(decision.matched_rule, self.rules[2])

    def test_reuses_state_table_for_repeated_allowed_packet(self):
        packet = Packet(
            source_ip="10.0.0.10",
            destination_ip="192.168.0.1",
            source_port=54321,
            destination_port=80,
            protocol=Protocol.TCP,
        )

        first_decision = self.firewall.process_packet(packet)
        second_decision = self.firewall.process_packet(packet)
        state = self.firewall.state_table.lookup(
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
        )

        self.assertIsNotNone(state)
        self.assertEqual(self.firewall.state_table.active_connections, 1)
        self.assertEqual(state.packet_count, 2)
        self.assertEqual(first_decision.decision_source, "slow_path")
        self.assertEqual(first_decision.matched_rule, self.rules[1])
        self.assertEqual(second_decision.action, Action.ALLOW)
        self.assertEqual(second_decision.decision_source, "fast_path")
        self.assertIsNone(second_decision.matched_rule)

    def test_rejects_invalid_packet_data_in_parser(self):
        invalid_packets = [
            {
                "source_ip": "10.0.0.999",
                "destination_ip": "192.168.0.1",
                "source_port": 54321,
                "destination_port": 80,
                "protocol": "TCP",
            }
        ]

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tmp:
            json.dump(invalid_packets, tmp)
            temp_path = tmp.name

        try:
            with self.assertRaises(ValueError):
                load_packets(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
