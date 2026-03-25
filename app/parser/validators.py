import ipaddress

def validate_ip(value: str) -> bool:
    if value == "any":
        return True

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_port(value) -> bool:
    if value == "any":
        return True

    if not isinstance(value, int):
        return False

    return 0 <= value <= 65535


def validate_protocol(value: str) -> bool:
    return value in {"TCP", "UDP", "any"}


def validate_action(value: str) -> bool:
    return value in {"ALLOW", "BLOCK"}