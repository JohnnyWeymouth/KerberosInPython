import os

from Client import Client
from AuthenticationServer import AuthenticationServer
from TicketGrantingServer import TicketGrantingServer
from ServiceServer import ServiceServer

def create_infrastructure() -> tuple[Client, AuthenticationServer, TicketGrantingServer, ServiceServer]:
    # Create the clients
    client1 = Client('Advanced_Networking_Student1', '10.10.10.10', os.urandom(32))
    client2 = Client('Advanced_Networking_Student2', '10.10.10.11', os.urandom(32))
    client3 = Client('Advanced_Networking_Student3', '10.10.10.12', os.urandom(32))

    # Create the Authentication Server
    client_id_to_key_C = {
        client1.client_id: client1.client_key,
        client2.client_id: client2.client_key,
        client3.client_id: client3.client_key,
    }
    key_TGS = os.urandom(32)
    authentication_server = AuthenticationServer(client_id_to_key_C, key_TGS)
    
    # Create the Ticket Granting Server
    minecraft, wholesome_memes, clone_wars = 'Minecraft', 'Wholesome Memes', 'Star Wars the Clone Wars'
    clients_id_to_authorized_services = {
        client1.client_id: {minecraft, wholesome_memes},
        client2.client_id: {minecraft, clone_wars},
        client3.client_id: {minecraft},
    }
    key_S = os.urandom(32)
    ticket_granting_server = TicketGrantingServer(clients_id_to_authorized_services, key_TGS, key_S)

    # Create the Service Server
    services = {minecraft, wholesome_memes, clone_wars}
    service_server = ServiceServer(key_S, services)
    return client1, authentication_server, ticket_granting_server, service_server