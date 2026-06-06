import socket
import sys

# optionally take in some positional args for the port
if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        print("Invalid port number. Using default port 12000.")
        PORT = 12000
else:
    PORT = 12000

# Define the server host and port
HOST = '0.0.0.0'  # Standard loopback interface address (localhost)

# Create a UDP socket
try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as err:
    print(f"Failed to create socket: {err}")
    sys.exit()

# Bind the socket to the address
try:
    server_socket.bind((HOST, PORT))
    print(f"UDP Server listening on {HOST}:{PORT}")
except socket.error as err:
    print(f"Bind failed: {err}")
    server_socket.close()
    sys.exit()

# Wait for and process incoming data
while True:
    try:
        # Receive data and the client's address (buffer size 1024 bytes)
        data, client_address = server_socket.recvfrom(1024)

        # Decode the data and print the message
        message = data.decode('utf-8')
        print("-" * 30)
        print(f"Received message from {client_address[0]}:{client_address[1]}:")
        print(f"-> Data: '{message}'")

        # Prepare the response message
        response_message = f"Hello client! Server received: '{message.upper()}'"

        # Send the response back to the client
        server_socket.sendto(response_message.encode('utf-8'), client_address)
        print(f"Sent response back to client.")

    except Exception as e:
        print(f"An error occurred: {e}")
        break

# Clean up (though usually unreachable in an infinite server loop)
server_socket.close()
print("Server stopped.")
