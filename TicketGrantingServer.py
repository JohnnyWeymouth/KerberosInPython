from typing import NamedTuple

class TicketGrantingServer(NamedTuple):
    clients_id_to_authorized_services: dict[str, set[str]]
    key_TGS: bytes
    key_S: bytes

class ResponseOfTicketGrantingServer(NamedTuple):
    encrypted_service_ticket: bytes
    encrypted_key_for_next_conversation: bytes