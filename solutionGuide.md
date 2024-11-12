1. Great answers to the pre-lab questions:
    1. Kerberos uses mutual authentication, where both the client and server verify each other using encrypted tickets from a trusted Key Distribution Center (KDC). This ensures that an attacker cannot intercept and impersonate either party. Data should thus be incromprehendable to anyone listening.
    2. Kerberos includes timestamps in its tickets, ensuring they’re only valid within a narrow timeframe. Nonces (unique identifiers) and session keys are also used to prevent ticket reuse.
    3. Modern Kerberos primarily uses AES (Advanced Encryption Standard), especially AES-256, which is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption.
    4. Kerberos tickets can be intercepted through various methods, such as man-in-the-middle (MITM) attacks, where an attacker can eavesdrop on the communication between the client and the Key Distribution Center (KDC). This could happen if encryption is not properly configured or if attackers exploit vulnerabilities in the network or endpoint security. Additionally, ticket-granting tickets (TGTs) can be stolen through malware or by exploiting weak passwords to perform a Pass-the-Ticket (PTT) attack. To mitigate these risks, best practices include enforcing strong encryption (e.g., AES-256), using mutual authentication to ensure both client and server are verified, implementing secure network protocols (such as VPNs or TLS) to protect communication, regularly rotating service account keys, enabling two-factor authentication (2FA), and deploying endpoint protection measures to detect and prevent malware.
    5. As a single point of failure, securing the KDC involves restricting physical and network access, using strong authentication for KDC admins, keeping the system patched, and implementing redundancy. The initial distribution of keys, and further updates, must be taken very seriously.
    6. Kerberos requires synchronized clocks (within a 5-minute skew by default) to validate tickets. Unsynced clocks can cause authentication failures, opening potential denial-of-service vulnerabilities.
    7. The Kerberos Golden Ticket attack involves an attacker forging a Kerberos Ticket Granting Ticket (TGT) to gain unauthorized access to any service within a Windows domain. By compromising the Key Distribution Center (KDC) or obtaining the KRBTGT account hash (used for signing TGTs), the attacker can generate a valid TGT that allows them to impersonate any user, including administrators. To protect against this attack, organizations should implement strong password policies, ensure the KRBTGT account is regularly changed, employ network segmentation to limit the spread of compromises, and monitor for unusual authentication activity, especially involving TGT creation or requests.
    8. Microsoft's Kerberos implementation has flaws like weak default settings, potential backdoors, and compatibility issues that may reduce security. Admin access can completely undermine the separation of roles of kerberos.

2. The following code is an example of a completed project. As this lab is heavily code based, screenshots will NOT be provided as a solution. Instead, code snippets and heavy commenting is used.

This code snippet shows what main should look like. The code is commented to show each major section of the process of the client. The code is well commented to show the different sections.
```python
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
```

This code snippet shows what the ticket granting server logic should look like. The code is has checks for all possible improper requests. The code is well commented to show the different sections.
```python
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
```

This code snippet shows what the service server logic should look like. The code is has checks for all possible improper requests. The code is well commented to show the different sections.
```python
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
```

3. Screenshots
    1. Screenshot 1
    ![My Local Image](/images/screenshot1.png)
    2. Screenshot 2
    ![My Local Image](/images/screenshot2.png)
    3. Screenshot 3
    ![My Local Image](/images/screenshot3.png)

4. Great answers to the post-lab questions:
    1. Separating authentication and authorization into logically distinct components enhances security by allowing each to be managed independently. Authentication verifies identity, while authorization determines access levels. This separation makes it easier to update or replace one without affecting the other, improves scalability, and allows for more flexible and granular control over access.
    2. If authentication and authorization components become misaligned, it can lead to inconsistent user access, such as authorized users being denied access or unauthorized users gaining privileges. This misalignment can create security vulnerabilities, complicate troubleshooting, and require more effort to synchronize and maintain the two components effectively.