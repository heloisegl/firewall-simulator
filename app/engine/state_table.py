from models.connection import ConnectionKey, ConnectionState
from models.enums import Protocol

class StateTable:
    def __init__(self, connection_timeout: float = 60.0):
        self._table: dict[ConnectionKey, ConnectionState] = {}
        self.connection_timeout = connection_timeout

    def _make_key(self, source_ip, destination_ip, source_port, destination_port, protocol):
        return ConnectionKey(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
        )

    def lookup(self, source_ip, destination_ip, source_port, destination_port, protocol):
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        state = self._table.get(key)
        if state is None:
            return None
        if state.is_expired(self.connection_timeout):
            del self._table[key]
            return None
        return state

    def register(self, source_ip, destination_ip, source_port, destination_port, protocol):
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        state = ConnectionState(key=key)
        self._table[key] = state
        return state

    def refresh(self, source_ip, destination_ip, source_port, destination_port, protocol):
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        state = self._table.get(key)
        if state:
            state.refresh()
        return state

    def remove(self, source_ip, destination_ip, source_port, destination_port, protocol):
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        if key in self._table:
            del self._table[key]
            return True
        return False

    def purge_expired(self):
        expired = [k for k, v in self._table.items() if v.is_expired(self.connection_timeout)]
        for k in expired:
            del self._table[k]
        return len(expired)

    @property
    def active_connections(self):
        return len(self._table)

    def snapshot(self):
        return list(self._table.values())
