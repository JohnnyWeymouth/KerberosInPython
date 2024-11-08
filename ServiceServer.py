from typing import NamedTuple

class ServiceServer(NamedTuple):
    key_S: str
    services: set[str]

class ResponseOfServiceServer(NamedTuple):
    encrypted_one_time_access_to_service: bytes
    encrypted_timestamp: bytes