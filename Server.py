import asyncio
import base64
import os
import json
import uuid

import websockets
from websockets import WebSocketServerProtocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


PASSWORD = b"SuperSecretPassword123"
SALT = b"fixed-salt"
PORT = int(os.environ.get("PORT", 5000))

connected_clients = {}  # websocket -> client_id


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    return kdf.derive(password)

KEY = derive_key(PASSWORD, SALT)


def decrypt_base64_message(b64: str) -> str:
    data = base64.b64decode(b64)
    iv = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(KEY)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


def encrypt_to_base64(text: str) -> str:
    aesgcm = AESGCM(KEY)
    iv = os.urandom(12)
    ciphertext = aesgcm.encrypt(iv, text.encode("utf-8"), None)
    return base64.b64encode(iv + ciphertext).decode("utf-8")


async def broadcast(json_message: dict):
    encrypted = encrypt_to_base64(json.dumps(json_message))
    dead = []

    for ws in connected_clients:
        try:
            await ws.send(encrypted)
        except:
            dead.append(ws)

    for ws in dead:
        del connected_clients[ws]


async def ws_handler(websocket: WebSocketServerProtocol):
    client_id = str(uuid.uuid4())
    connected_clients[websocket] = client_id
    print(f"[SERVER] Client connected: {client_id}")

    try:
        async for message in websocket:
            if message == "ping":
                await websocket.send("pong")
                continue

            try:
                plaintext = decrypt_base64_message(message)
                data = json.loads(plaintext)
            except:
                continue

            await broadcast(data)

    finally:
        print(f"[SERVER] Client disconnected: {client_id}")
        del connected_clients[websocket]


async def http_handler(path, headers):
    if headers.get("Upgrade", "").lower() == "websocket":
        return None

    return (
        200,
        [("Content-Type", "text/plain")],
        b"OK",
    )


async def main():
    print(f"[SERVER] Starting on port {PORT}")

    async with websockets.serve(
        ws_handler,
        "0.0.0.0",
        PORT,
        process_request=http_handler,
    ):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
