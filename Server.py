import asyncio
import base64
import os

import websockets
from websockets import WebSocketServerProtocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ============================
#  CONFIG
# ============================

PASSWORD = b"SuperSecretPassword123"
SALT = b"fixed-salt"

PORT = int(os.environ.get("PORT", 5000))

connected_clients = set()


# ============================
#  KEY DERIVATION
# ============================

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


# ============================
#  ENCRYPTION HELPERS
# ============================

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


# ============================
#  BROADCAST
# ============================

async def broadcast(text: str):
    encrypted = encrypt_to_base64(text)
    dead = []

    for ws in connected_clients:
        try:
            await ws.send(encrypted)
        except:
            dead.append(ws)

    for ws in dead:
        connected_clients.discard(ws)


# ============================
#  WEBSOCKET HANDLER
# ============================

async def ws_handler(websocket: WebSocketServerProtocol):
    print("[SERVER] Client connected")
    connected_clients.add(websocket)

    try:
        async for message in websocket:
            if message == "ping":
                await websocket.send("pong")
                continue

            try:
                plaintext = decrypt_base64_message(message)
                print(f"[SERVER] Decrypted: {plaintext}")
            except Exception as e:
                print(f"[SERVER] Decryption failed: {e}")
                continue

            await broadcast(plaintext)

    finally:
        connected_clients.discard(websocket)
        print("[SERVER] Client disconnected")


# ============================
#  HTTP FALLBACK (Render)
# ============================

async def http_handler(path, headers):
    if headers.get("Upgrade", "").lower() == "websocket":
        return None

    return (
        200,
        [("Content-Type", "text/plain")],
        b"OK",
    )


# ============================
#  MAIN ENTRY
# ============================

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
