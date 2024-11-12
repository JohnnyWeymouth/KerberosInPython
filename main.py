from python_aes import (
    generate_aes_key,
    encrypt_object,
    decrypt_object
)
from infrastructure import (
    AuthenticationServer,
    TicketGrantingServer,
    ServiceServer,
    create_infrastructure
)
from communication import (
    ResponseToBadRequest,
    RequestToAuthenticationServer,
    TicketGrantingTicket,
    ResponseOfAuthenticationServer,
    RequestToTicketGrantingServer,
    ServiceTicket,
    ResponseOfTicketGrantingServer,
    RequestToServiceServer,
    ResponseOfServiceServer
)
from operator import attrgetter
from uuid import uuid4

def main():
    # This creates the different parts of the infrastructure.
    """TODO Step 1: Take a look at the infrastructure to see how pre-shared keys work, along with the permissions.
    Your job in this lab will be to have client1 get access to Minecraft from the Service server"""
    possible_services, possible_clients, authentication_server, ticket_granting_server, service_server = create_infrastructure()

    # Client Selection
    sorted_clients = sorted(possible_clients, key=attrgetter('client_id'))
    print("\n".join(f"{i}: {item.client_id}" for i, item in enumerate(sorted_clients[:4])))
    while True:
        selection = input("Select a client by entering a number (0-3): ")
        if selection.isdigit() and int(selection) in range(4):
            break
    client = sorted_clients[int(selection)]

    # Desired Service Selection
    sorted_services = sorted(possible_services)
    print("\n".join(f"{i}: {item}" for i, item in enumerate(sorted_services)))
    while True:
        selection = input("Select a service to request by entering a number (0-3): ")
        if selection.isdigit() and int(selection) in range(4):
            break
    desired_service = sorted_services[int(selection)]

    # Communicate with the authentication server
    """TODO Step 2: Take a look at how authentication_server_logic works and compare it to the diagram. This 
    will help you understand how the authentication server communicates, and could help when writing the TGT server"""
    request = RequestToAuthenticationServer(client.client_id, client.ip_address)
    response = authentication_server_logic(request, authentication_server)
    if isinstance(response, ResponseToBadRequest):
        print(response.reasoning)
        return
    next_conversation_key = decrypt_object(response.encrypted_key_for_next_conversation, client.client_key)

    # Communicate with the ticket granting server
    """TODO Step 3: Now that you are starting to understand kerberos, it's time you wrote the next part of the
    kerberos communication process. Write the code for creating the client request to tgt, then write the tgt server
    logic to get the tgt response. Also get the next conversation key"""

    # Communicate with the service server
    """TODO Step 4: Now construct the request to the service server. Write the code for the service_server_logic, which
    returns the appropriate response. Decrypt the one time code, and print it to the console"""

def authentication_server_logic(request:RequestToAuthenticationServer, server:AuthenticationServer) -> ResponseOfAuthenticationServer | ResponseToBadRequest:
    # Generate the key for the next communication
    next_communication_key = generate_aes_key()

    # Unpack client and address
    client = request.client_id
    address = request.ip_address

    # Checks that the client's id is one of the ids that maps to a key on the Authentication Server.
    # If not there, create a random key for the imposter
    client_key = server.client_id_to_key_C.get(request.client_id)
    valid = client_key is not None
    if not valid:
        return ResponseToBadRequest('Client id is not mapped to a key in the Authentication Server')
    
    # Create and encrypt the ticket granting ticket
    ticket_granting_ticket = TicketGrantingTicket(next_communication_key, client, address, valid)
    encrypted_ticket_granting_ticket = encrypt_object(ticket_granting_ticket, server.key_TGS)

    # Encrypt the next_communication_key for the client to use
    encrypted_key_for_next_conversation = encrypt_object(next_communication_key, client_key)
    
    # Return the response of the authentication server
    return ResponseOfAuthenticationServer(encrypted_ticket_granting_ticket, encrypted_key_for_next_conversation)

def ticket_granting_server_logic(request:RequestToTicketGrantingServer, server:TicketGrantingServer) -> ResponseOfTicketGrantingServer | ResponseToBadRequest:
    pass

def service_server_logic(request:RequestToServiceServer, server:ServiceServer) -> ResponseOfServiceServer | ResponseToBadRequest:
    pass

if __name__ == '__main__':
    main()