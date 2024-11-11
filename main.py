from symmetric import generate_aes_key, encrypt_message, decrypt_message
from initial_infrastructure import create_infrastructure
from Client import RequestToAuthenticationServer, RequestToTicketGrantingServer, RequestToServiceServer
from AuthenticationServer import AuthenticationServer, ResponseOfAuthServer
from TicketGrantingServer import TicketGrantingServer, ResponseOfTicketGrantingServer
from ServiceServer import ServiceServer, ResponseOfServiceServer

def main():
    # This creates the different parts of the infrastructure.
    client1, authentication_server, ticket_granting_server, service_server = create_infrastructure()
    # TODO Just take a look at this function to see how preshared keys work, along with the permissions.
    # Your job this lab will be to have client1 get access to Minecraft from the Service server

    # Communicate with the authentication server
    request = RequestToAuthenticationServer(client1.client_id, client1.ip_address)
    response = authentication_server_logic(request, authentication_server)
    next_conversation_key = decrypt_message(
        client1.client_key,
        response.iv_next_conversation,
        response.encrypted_key_for_next_conversation
    )

    tgt_key_as_string = decrypt_message(authentication_server.key_TGS, response.iv_next_conversation, response.encrypted_ticket_granting_ticket)
    print(tgt_key_as_string)
    
    # Communicate with the ticket_granting_ticket_server

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
    ticket_granting_ticket_as_string = str((
        next_communication_key,
        client,
        address,
        validity
    )).encode('utf-8')
    iv_tgt, encrypted_ticket_granting_ticket = encrypt_message(server.key_TGS, ticket_granting_ticket_as_string)

    # Encrypt the next_communication_key for the client to use
    iv_next_conversation, encrypted_key_for_next_conversation = encrypt_message(client_key, next_communication_key)
    
    # Return the message
    return ResponseOfAuthServer(
        iv_tgt,
        encrypted_ticket_granting_ticket,
        iv_next_conversation,
        encrypted_key_for_next_conversation
    )

if __name__ == '__main__':
    main()