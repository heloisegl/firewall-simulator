import json

from models.rule import Rule
from models.enums import Action
from parser.validators import (
    validate_ip,
    validate_port,
    validate_protocol,
    validate_action,
)


def load_rules(file_path: str) -> list[Rule]:
    with open(file_path, "r", encoding="utf-8") as file:
        raw_rules = json.load(file)

    rules = []

    for raw_rule in raw_rules:
        action = raw_rule.get("action", "BLOCK")
        source_ip = raw_rule.get("source_ip", "any")
        destination_ip = raw_rule.get("destination_ip", "any")
        port = raw_rule.get("port", "any")
        protocol = raw_rule.get("protocol", "any")

        if not validate_action(action):
            raise ValueError(f"Ação inválida na regra: {action}")

        if not validate_ip(source_ip):
            raise ValueError(f"IP de origem inválido na regra: {source_ip}")

        if not validate_ip(destination_ip):
            raise ValueError(f"IP de destino inválido na regra: {destination_ip}")

        if not validate_port(port):
            raise ValueError(f"Porta inválida na regra: {port}")

        if not validate_protocol(protocol):
            raise ValueError(f"Protocolo inválido na regra: {protocol}")

        rules.append(
            Rule(
                action=Action(action),
                source_ip=source_ip,
                destination_ip=destination_ip,
                port=port,
                protocol=protocol,
            )
        )

    return rules