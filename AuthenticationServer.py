from typing import NamedTuple

class AuthenticationServer(NamedTuple):
    client_id_to_key_C: dict[str, bytes]
    key_TGS: bytes

class ResponseOfAuthServer(NamedTuple):
    iv_tgt: bytes
    encrypted_ticket_granting_ticket: bytes
    iv_next_conversation: bytes
    encrypted_key_for_next_conversation: bytes