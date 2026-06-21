import asyncio
import websockets
import json
import os

clients = set()

async def handler(ws):
    clients.add(ws)
    try:
        async for message in ws:
            data = json.loads(message)
            for client in clients:
                await client.send(json.dumps(data))
    except:
        pass
    finally:
        clients.remove(ws)

async def main():
    PORT = int(os.environ.get("PORT", 5000))
    async with websockets.serve(handler, "0.0.0.0", PORT):
        print(f"Server running on port {PORT}")
        await asyncio.Future()

asyncio.run(main())
