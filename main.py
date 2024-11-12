from python_aes import generate_aes_key, encrypt_object, decrypt_object
from initial_infrastructure import create_infrastructure
from Client import RequestToAuthenticationServer, RequestToTicketGrantingServer, RequestToServiceServer
from AuthenticationServer import AuthenticationServer, ResponseOfAuthServer
from TicketGrantingServer import TicketGrantingServer, ResponseOfTicketGrantingServer
from Tickets import TicketGrantingTicket, ServiceTicket
from ServiceServer import ServiceServer, ResponseOfServiceServer

def main():
    # This creates the different parts of the infrastructure.
    """TODO Step 1: Take a look at this function to see how pre-shared keys work, along with the permissions.
    Your job in this lab will be to have client1 get access to Minecraft from the Service server"""
    client1, authentication_server, ticket_granting_server, service_server = create_infrastructure()

    # Communicate with the authentication server
    """TODO Step 2: Take a look at how authentication_server_logic works and compare it to the diagram. This 
    will help you understand how the authentication server communicates, and could help when writing the TGT server"""
    request = RequestToAuthenticationServer(client1.client_id, client1.ip_address)
    response = authentication_server_logic(request, authentication_server)
    next_conversation_key = decrypt_object(response.encrypted_key_for_next_conversation, client1.client_key)

    # Communicate with the ticket granting server
    """TODO Step 3: Now that you are starting to understand kerberos, it's time you wrote the next part of the
    kerberos communication process. Write the code for creating the client request to tgt, then write the tgt server
    logic to get the tgt response."""

    # Communicate with the service server
    """TODO Step 4: Now that you are starting to understand kerberos, it's time you wrote the next part of the
    kerberos communication process. Write the code for creating the client request to tgt, then write the tgt server
    logic to get the tgt response."""

def authentication_server_logic(request:RequestToAuthenticationServer, server:AuthenticationServer) -> ResponseOfAuthServer:
    # Generate the key for the next communication
    next_communication_key = generate_aes_key()

    # Unpack client and address
    client = request.client_id
    address = request.ip_address

    # Checks that the client's id is one of the ids that maps to a key on the Authentication Server.
    # If not there, create a random key for the imposter
    validity = True
    client_key = server.client_id_to_key_C.get(request.client_id)
    if client_key is None:
        validity = False
        client_key = generate_aes_key()

    # Create and encrypt the ticket granting ticket
    ticket_granting_ticket = TicketGrantingTicket(next_communication_key, client, address, validity)
    encrypted_ticket_granting_ticket = encrypt_object(ticket_granting_ticket, server.key_TGS)

    # Encrypt the next_communication_key for the client to use
    encrypted_key_for_next_conversation = encrypt_object(next_communication_key, client_key)
    
    # Return the response of the authentication server
    return ResponseOfAuthServer(encrypted_ticket_granting_ticket, encrypted_key_for_next_conversation)

def ticket_granting_server_logic(request:RequestToTicketGrantingServer, server:TicketGrantingServer) -> ResponseOfTicketGrantingServer:
    pass

def service_server_logic(request:RequestToServiceServer, server:ServiceServer) -> ResponseOfServiceServer:
    pass

if __name__ == '__main__':
    main()