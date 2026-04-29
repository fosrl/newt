import asyncio
import sys
import websockets

# Argument parsing: Check if HOST and PORT are provided
if len(sys.argv) < 3 or len(sys.argv) > 4:
    print("Usage: python ws_client.py <HOST_IP> <HOST_PORT> [ws|wss]")
    # Example: python ws_client.py 127.0.0.1 8765
    # Example: python ws_client.py 127.0.0.1 8765 wss
    sys.exit(1)

HOST = sys.argv[1]
try:
    PORT = int(sys.argv[2])
except ValueError:
    print("Error: HOST_PORT must be an integer.")
    sys.exit(1)

if len(sys.argv) == 4:
    SCHEME = sys.argv[3].lower()
    if SCHEME not in ("ws", "wss"):
        print("Error: scheme must be 'ws' or 'wss'.")
        sys.exit(1)
else:
    SCHEME = "ws"

URI = f"{SCHEME}://{HOST}:{PORT}"

# The message to send to the server
MESSAGE = "Hello WebSocket Server! How are you?"


async def main():
    print(f"Connecting to {URI}...")

    try:
        async with websockets.connect(URI) as websocket:
            print(f"Connected to server.")
            print(f"Sending message: '{MESSAGE}'")

            await websocket.send(MESSAGE)

            response = await websocket.recv()

            print("-" * 30)
            print(f"Received response from server:")
            print(f"-> Data: '{response}'")

    except ConnectionRefusedError:
        print(f"Error: Connection to {URI} was refused. Is the server running?")
    except websockets.exceptions.InvalidMessage as e:
        print(f"Error: Server did not respond with a valid WebSocket handshake: {e}")
    except Exception as e:
        print(f"Error during communication: {e}")

    print("-" * 30)
    print("Client finished.")


asyncio.run(main())
