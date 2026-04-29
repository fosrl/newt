import socket
import sys

# Argument parsing: Check if IP and Port are provided
if len(sys.argv) != 3:
    print("Usage: python udp_client.py <HOST_IP> <HOST_PORT>")
    # Example: python udp_client.py 127.0.0.1 12000
    sys.exit(1)

HOST = sys.argv[1]
try:
    PORT = int(sys.argv[2])
except ValueError:
    print("Error: HOST_PORT must be an integer.")
    sys.exit(1)

# The message to send to the server
MESSAGE = "Hello UDP Server! How are you?"

# Create a UDP socket
try:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as err:
    print(f"Failed to create socket: {err}")
    sys.exit()

try:
    print(f"Sending message to {HOST}:{PORT}...")

    # Send the message (data must be encoded to bytes)
    client_socket.sendto(MESSAGE.encode('utf-8'), (HOST, PORT))

    # Wait for the server's response (buffer size 1024 bytes)
    data, server_address = client_socket.recvfrom(1024)

    # Decode and print the server's response
    response = data.decode('utf-8')
    print("-" * 30)
    print(f"Received response from server {server_address[0]}:{server_address[1]}:")
    print(f"-> Data: '{response}'")

except socket.error as err:
    print(f"Error during communication: {err}")

finally:
    # Close the socket
    client_socket.close()
    print("-" * 30)
    print("Client finished and socket closed.")
