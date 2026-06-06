import asyncio
import sys
import websockets

# Optionally take in a positional arg for the port
if len(sys.argv) > 1:
    try:
        PORT = int(sys.argv[1])
    except ValueError:
        print("Invalid port number. Using default port 8765.")
        PORT = 8765
else:
    PORT = 8765

# Define the server host
HOST = "0.0.0.0"


async def handle_client(websocket):
    client_address = websocket.remote_address
    print(f"Client connected: {client_address[0]}:{client_address[1]}")

    try:
        async for message in websocket:
            print("-" * 30)
            print(f"Received message from {client_address[0]}:{client_address[1]}:")
            print(f"-> Data: '{message}'")

            response = f"Hello client! Server received: '{message.upper()}'"

            await websocket.send(response)
            print(f"Sent response back to client.")

    except websockets.exceptions.ConnectionClosedOK:
        print(f"Client {client_address[0]}:{client_address[1]} disconnected cleanly.")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"Client {client_address[0]}:{client_address[1]} disconnected with error: {e}")


async def main():
    print(f"WebSocket Server listening on {HOST}:{PORT}")
    async with websockets.serve(handle_client, HOST, PORT):
        await asyncio.Future()  # Run forever


try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nServer stopped.")
