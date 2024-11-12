from python_aes import generate_aes_key, encrypt_object, decrypt_object
from initial_infrastructure import create_infrastructure
from Client import RequestToAuthenticationServer, RequestToTicketGrantingServer, RequestToServiceServer
from AuthenticationServer import AuthenticationServer, ResponseOfAuthServer
from TicketGrantingServer import TicketGrantingServer, ResponseOfTicketGrantingServer
from ServiceServer import ServiceServer, ResponseOfServiceServer

def main():
    # This creates the different parts of the infrastructure.
    client1, authentication_server, ticket_granting_server, service_server = create_infrastructure()
    """TODO Step 1: Take a look at this function to see how preshared keys work, along with the permissions.
    Your job in this lab will be to have client1 get access to Minecraft from the Service server"""

    # Communicate with the authentication server
    request = RequestToAuthenticationServer(client1.client_id, client1.ip_address)
    response = authentication_server_logic(request, authentication_server)
    next_conversation_key = decrypt_object(response.encrypted_key_for_next_conversation, client1.client_key)
    """TODO Step 2: Take a look at how authentication_server_logic works and compare it to the diagram. This 
    will help you understand how the authentication server communicates, and could help when writing the TGT server"""

    # Communicate with the ticket_granting_ticket_server
    ticket_granting_ticket = decrypt_object(response.encrypted_ticket_granting_ticket, authentication_server.key_TGS)
    print(ticket_granting_ticket)

def authentication_server_logic(request:RequestToAuthenticationServer, server:AuthenticationServer) -> ResponseOfAuthServer:
    # Generate the key for the next communication
    next_communication_key = generate_aes_key()

    # Unpack client and address
    client = request.client_id
    address = request.ip_address

    # Checks that the client's id is one of the ids that maps to a key on the Authentication Server.
    # If not there, create a random key for the imposter
    client_key = server.client_id_to_key_C.get(request.client_id)
    validity = True
    if client_key is None:
        client_key = generate_aes_key()
        validity = False

    # Create and encrypt the ticket granting ticket
    ticket_granting_ticket = (next_communication_key, client, address, validity)
    encrypted_ticket_granting_ticket = encrypt_object(ticket_granting_ticket, server.key_TGS)

    # Encrypt the next_communication_key for the client to use
    encrypted_key_for_next_conversation = encrypt_object(next_communication_key, client_key)
    
    # Return the message
    return ResponseOfAuthServer(encrypted_ticket_granting_ticket, encrypted_key_for_next_conversation)

if __name__ == '__main__':
    main()