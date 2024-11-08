from typing import NamedTuple

class Client(NamedTuple):
    client_id: str
    ip_address: str
    client_key: str

class RequestToAuthenticationServer(NamedTuple):
    client_id: str
    ip_address: str

class RequestToTicketGrantingServer(NamedTuple):
    requested_service: str
    encrypted_ticket_granting_ticket: bytes
    encrypted_client_id_and_timestamp: bytes

class RequestToServiceServer(NamedTuple):
    encrypted_service_ticket: bytes
    encrypted_client_id_and_timestamp: bytes