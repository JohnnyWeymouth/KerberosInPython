from typing import NamedTuple

class TicketGrantingTicket(NamedTuple):
    next_communication_key: bytes
    client: str
    address: str
    validity: bool

class ServiceTicket(NamedTuple):
    next_communication_key: bytes
    client: str
    address: str
    validity: bool