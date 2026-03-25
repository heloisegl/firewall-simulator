from engine.firewall import Firewall
from models.enums import Action
from parser.rules_parser import load_rules
from parser.packets_parser import load_packets

def main():
    rules = load_rules("data/rules.json")
    packets = load_packets("data/packets.json")
    firewall = Firewall(rules=rules, default_action=Action.BLOCK, stateful=True)

    print("=" * 70)
    print(f"{'PROTO':<6} {'ORIGEM':<22} {'DESTINO':<22} {'AÇÃO':<6} {'VIA'}")
    print("=" * 70)

    for packet in packets:
        already_known = firewall.state_table.lookup(
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
        ) is not None

        result = firewall.process_packet(packet)
        via = "STATE TABLE (fast path)" if already_known else "RULE MATCHING (slow path)"
        origem = f"{packet.source_ip}:{packet.source_port}"
        destino = f"{packet.destination_ip}:{packet.destination_port}"
        print(f"{packet.protocol.value:<6} {origem:<22} {destino:<22} {result.value:<6} {via}")

    print("=" * 70)
    print(f"Conexões ativas na State Table: {firewall.state_table.active_connections}")

if __name__ == "__main__":
    main()
