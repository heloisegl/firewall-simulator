# app/engine/state_table.py
# Implements the StateTable class: a hash-table-based connection tracker
# that stores active connections using the 5-tuple as a unique key,
# enabling fast O(1) lookup for established connections.

from models.connection import ConnectionKey, ConnectionState
from models.enums import Protocol


class StateTable:
    def __init__(self, connection_timeout: float = 60.0):
        # Hash table: ConnectionKey -> ConnectionState
        self._table: dict[ConnectionKey, ConnectionState] = {}
        self.connection_timeout = connection_timeout

    def _make_key(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: Protocol,
    ) -> ConnectionKey:
        return ConnectionKey(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
        )

    def lookup(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: Protocol,
    ) -> ConnectionState | None:
        """
        Consulta a tabela de estados.
        Retorna ConnectionState se a conexão existir e não tiver expirado,
        caso contrário retorna None.
        """
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        state = self._table.get(key)

        if state is None:
            return None

        if state.is_expired(self.connection_timeout):
            del self._table[key]
            return None

        return state

    def register(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: Protocol,
    ) -> ConnectionState:
        """
        Registra uma nova conexão autorizada na tabela de estados.
        """
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        state = ConnectionState(key=key)
        self._table[key] = state
        return state

    def refresh(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: Protocol,
    ) -> ConnectionState | None:
        """
        Atualiza o timestamp de uma conexão existente.
        """
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        state = self._table.get(key)
        if state:
            state.refresh()
        return state

    def remove(
        self,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: Protocol,
    ) -> bool:
        """
        Remove explicitamente uma conexão da tabela (ex: FIN/RST).
        """
        key = self._make_key(source_ip, destination_ip, source_port, destination_port, protocol)
        if key in self._table:
            del self._table[key]
            return True
        return False

    def purge_expired(self) -> int:
        """
        Remove todas as conexões expiradas. Retorna quantas foram removidas.
        """
        expired = [k for k, v in self._table.items() if v.is_expired(self.connection_timeout)]
        for k in expired:
            del self._table[k]
        return len(expired)

    @property
    def active_connections(self) -> int:
        return len(self._table)

    def snapshot(self) -> list[ConnectionState]:
        """Retorna uma lista com todas as conexões ativas (para logs/stats)."""
        return list(self._table.values())