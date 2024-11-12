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
import time
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
    next_communication_key_0 = decrypt_object(response.encrypted_key_for_next_communication, client.client_key)
    client_id_and_timestamp = (client.client_id, time.time())
    encrypted_client_id_and_timestamp = encrypt_object(client_id_and_timestamp, next_communication_key_0)
    encrypted_ticket_granting_ticket = response.encrypted_ticket_granting_ticket

    # Communicate with the ticket granting server
    """TODO Step 3: Now that you are starting to understand kerberos, it's time you wrote the next part of the
    kerberos communication process. Write the code for creating the client request to tgt, then write the tgt server
    logic to get the tgt response. Also get the next communication key"""
    request = RequestToTicketGrantingServer(desired_service, encrypted_ticket_granting_ticket, encrypted_client_id_and_timestamp)
    response = ticket_granting_server_logic(request, ticket_granting_server)
    if isinstance(response, ResponseToBadRequest):
        print(response.reasoning)
        return
    next_communication_key_1 = decrypt_object(response.encrypted_key_for_next_communication, next_communication_key_0)
    client_id_and_timestamp = (client.client_id, time.time())
    encrypted_client_id_and_timestamp = encrypt_object(client_id_and_timestamp, next_communication_key_1)
    encrypted_service_ticket = response.encrypted_service_ticket

    # Communicate with the service server
    """TODO Step 4: Now construct the request to the service server. Write the code for the service_server_logic, which
    returns the appropriate response. Decrypt the one time code, and print it to the console"""
    request = RequestToServiceServer(encrypted_service_ticket, encrypted_client_id_and_timestamp)
    response = service_server_logic(request, service_server)
    one_time_access = decrypt_object(response.encrypted_one_time_access_to_service, next_communication_key_1)
    timestamp = decrypt_object(response.encrypted_timestamp, next_communication_key_1)
    print(one_time_access, timestamp)

def authentication_server_logic(request:RequestToAuthenticationServer, server:AuthenticationServer) -> ResponseOfAuthenticationServer | ResponseToBadRequest:
    # Checks that the client's id is one of the ids that maps to a key on the Authentication Server.
    # If not there, create a random key for the imposter
    client_key = server.client_id_to_key_C.get(request.client_id)
    valid = client_key is not None
    if not valid:
        return ResponseToBadRequest('Client id is not mapped to a key in the Authentication Server')
    
    # Generate the key for the next communication and encrypt it so that only the client can read it
    next_communication_key = generate_aes_key()
    encrypted_key_for_next_communication = encrypt_object(next_communication_key, client_key)

    # Create and encrypt the ticket granting ticket
    ticket_granting_ticket = TicketGrantingTicket(next_communication_key, request.client_id, request.ip_address, valid)
    encrypted_ticket_granting_ticket = encrypt_object(ticket_granting_ticket, server.key_TGS)

    # Return the response of the authentication server
    return ResponseOfAuthenticationServer(encrypted_ticket_granting_ticket, encrypted_key_for_next_communication)

def ticket_granting_server_logic(request:RequestToTicketGrantingServer, server:TicketGrantingServer) -> ResponseOfTicketGrantingServer | ResponseToBadRequest:
    # Unpack the ticket granting ticket
    try:
        ticket_granting_ticket:TicketGrantingTicket = decrypt_object(request.encrypted_ticket_granting_ticket, server.key_TGS)
    except:
        return ResponseToBadRequest('could not unpack TGT')
    key_current_communication, tgt_client_id, ip_address, valid = ticket_granting_ticket

    # Unpack the client_id and timestamp
    try:
        client_id_and_timestamp = decrypt_object(request.encrypted_client_id_and_timestamp, key_current_communication)
        client_id, timestamp = client_id_and_timestamp
    except:
        return ResponseToBadRequest('could not unpack authenticator')

    # Respond with errors if things are not right
    if not valid:
        return ResponseToBadRequest('Authentication marked this as invalid')
    allowed_services_of_client = server.clients_id_to_authorized_services.get(tgt_client_id)
    if allowed_services_of_client is None:
        return ResponseToBadRequest('User is not authorised for any action')
    if request.requested_service not in allowed_services_of_client:
        return ResponseToBadRequest('User not authorised to access this specific service')
    if client_id != tgt_client_id:
        return ResponseToBadRequest('client id did not match client id of ticket')
    if time.time() - timestamp > 120:
        return ResponseToBadRequest('Request is older than 5 minutes')
    
    # Create and encrypt the next communication key with the current communicatin key
    next_communication_key = generate_aes_key()
    encrypted_key_for_next_communication= encrypt_object(next_communication_key, key_current_communication)

    # Create the service ticket and encrypt it so that only the service server can read it
    service_ticket = ServiceTicket(next_communication_key, tgt_client_id, ip_address, True, request.requested_service)
    encrypted_service_ticket = encrypt_object(service_ticket, server.key_S)

    # Return the response of the Ticket Granting server
    return ResponseOfTicketGrantingServer(encrypted_service_ticket, encrypted_key_for_next_communication)

def service_server_logic(request:RequestToServiceServer, server:ServiceServer) -> ResponseOfServiceServer | ResponseToBadRequest:
    # Unpack the ticket granting ticket
    try:
        service_ticket:ServiceTicket = decrypt_object(request.encrypted_service_ticket, server.key_S)
    except:
        return ResponseToBadRequest('could not unpack ST')
    key_current_communication, st_client_id, ip_address, valid, service = service_ticket

    # Unpack the client_id and timestamp
    try:
        client_id_and_timestamp = decrypt_object(request.encrypted_client_id_and_timestamp, key_current_communication)
        client_id, timestamp = client_id_and_timestamp
    except:
        return ResponseToBadRequest('could not unpack authenticator')
    
    # Respond with errors if things are not right
    if not valid:
        return ResponseToBadRequest('Authentication marked this as invalid')
    provideable_services = server.provideable_services
    if service not in provideable_services:
        return ResponseToBadRequest('This service server does not provide this service')
    if client_id != st_client_id:
        return ResponseToBadRequest('client id did not match client id of ticket')
    if time.time() - timestamp > 120:
        return ResponseToBadRequest('Request is older than 5 minutes')
    
    # Craft reply
    one_time_access_to_service = str(uuid4())
    encrypted_one_time_access_to_service = encrypt_object(one_time_access_to_service, key_current_communication)
    timestamp = time.time()
    encrypted_timestamp = encrypt_object(timestamp, key_current_communication)
    return ResponseOfServiceServer(encrypted_one_time_access_to_service, encrypted_timestamp)

if __name__ == '__main__':
    main()