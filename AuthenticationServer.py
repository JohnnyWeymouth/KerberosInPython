from typing import NamedTuple

class AuthenticationServer(NamedTuple):
    client_id_to_key_C: dict[str, bytes]
    key_TGS: bytes

class ResponseOfAuthServer(NamedTuple):
    encrypted_ticket_granting_ticket: bytes
    encrypted_key_for_next_conversation: bytes