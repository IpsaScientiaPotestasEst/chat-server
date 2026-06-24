
import asyncio
import base64
import os
import threading
import http.server
import socketserver

import websockets
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ============================
#  CONFIG
# ============================

PASSWORD = b"SuperSecretPassword123"
SALT = b"fixed-salt"

PORT = int(os.environ.get("PORT", 5000))   # Render exposes THIS port only


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
#  HTTP SERVER (Health Check)
# ============================

def start_http_server():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

        def log_message(self, *args):
            return  # silence logs

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()


# ============================
#  WEBSOCKET HANDLER
# ============================

async def ws_handler(websocket):
    print("[SERVER] Client connected")

    try:
        async for message in websocket:
            try:
                plaintext = decrypt_base64_message(message)
                print(f"[SERVER] Decrypted: {plaintext}")
            except Exception as e:
                print(f"[SERVER] Decryption failed: {e}")
                continue

            response = f"Server got: {plaintext}"
            encrypted = encrypt_to_base64(response)
            await websocket.send(encrypted)

    except (ConnectionClosedOK, ConnectionClosedError):
        pass

    finally:
        print("[SERVER] Client disconnected")


# ============================
#  MAIN ENTRY
# ============================

async def main():
    # Start HTTP server on same port
    threading.Thread(target=start_http_server, daemon=True).start()

    # Start WebSocket server on same port
    async with websockets.serve(ws_handler, "0.0.0.0", PORT):
        print(f"[SERVER] Running on port {PORT}")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
