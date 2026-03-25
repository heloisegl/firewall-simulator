# app/main.py

from pathlib import Path
import sys

if __package__ is None or __package__ == "":
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

from app.engine.firewall import Firewall
from app.models.enums import Action
from app.parser.packets_parser import load_packets
from app.parser.rules_parser import load_rules


def main():
    data_dir = Path(__file__).resolve().parent / "data"
    rules = load_rules(str(data_dir / "rules.json"))
    packets = load_packets(str(data_dir / "packets.json"))

    firewall = Firewall(rules=rules, default_action=Action.BLOCK, stateful=True)

    print("=" * 65)
    print(f"{'PROTOCOLO':<6} {'ORIGEM':<22} {'DESTINO':<22} {'AÇÃO':<6} {'VIA'}")
    print("=" * 65)

    for packet in packets:
        decision = firewall.process_packet(packet)
        via = (
            "STATE TABLE (fast path)"
            if decision.decision_source == "fast_path"
            else "RULE MATCHING (slow path)"
        )
        origin = f"{packet.source_ip}:{packet.source_port}"
        dest = f"{packet.destination_ip}:{packet.destination_port}"

        print(
            f"{packet.protocol.value:<6} {origin:<22} {dest:<22} {decision.action.value:<6} {via}"
        )

    print("=" * 65)
    print(f"Conexões ativas na State Table: {firewall.state_table.active_connections}")


if __name__ == "__main__":
    main()
