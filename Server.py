import asyncio
import websockets
import json

clients = set()

async def handler(ws):
    clients.add(ws)
    try:
        async for message in ws:
            # Expect JSON from clients
            data = json.loads(message)

            # Broadcast to all clients
            for client in clients:
                await client.send(json.dumps(data))

    except:
        pass
    finally:
        clients.remove(ws)

async def main():
    async with websockets.serve(handler, "0.0.0.0", 5000):
        print("Server running on port 5000")
        await asyncio.Future()

asyncio.run(main())