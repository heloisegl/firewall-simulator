import json
from models.packet import Packet
from models.enums import Protocol
from parser.validators import validate_ip, validate_port, validate_protocol

def load_packets(file_path: str) -> list[Packet]:
    with open(file_path, "r", encoding="utf-8") as file:
        raw_packets = json.load(file)

    packets = []
    for raw_packet in raw_packets:
        source_ip = raw_packet["source_ip"]
        destination_ip = raw_packet["destination_ip"]
        source_port = raw_packet.get("source_port", 0)
        destination_port = raw_packet.get("destination_port", raw_packet.get("port"))
        protocol = raw_packet["protocol"]

        if not validate_ip(source_ip):
            raise ValueError(f"IP de origem inválido: {source_ip}")
        if not validate_ip(destination_ip):
            raise ValueError(f"IP de destino inválido: {destination_ip}")
        if not validate_port(source_port):
            raise ValueError(f"Porta de origem inválida: {source_port}")
        if not validate_port(destination_port):
            raise ValueError(f"Porta de destino inválida: {destination_port}")
        if not validate_protocol(protocol):
            raise ValueError(f"Protocolo inválido: {protocol}")

        packets.append(Packet(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=Protocol(protocol),
        ))

    return packets
