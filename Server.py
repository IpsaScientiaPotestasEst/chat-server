import asyncio
import base64
import json
import os

import websockets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import http.server
import socketserver
import threading

PORT = int(os.environ.get("PORT", 5000))

def start_http_server():
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.end_headers()
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()

PASSWORD = b"SuperSecretPassword123"  # same as client
SALT = b"fixed-salt"                 # same as client


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a password using PBKDF2."""
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
    """Decode base64, split IV + ciphertext, decrypt with AES-GCM."""
    data = base64.b64decode(b64)
    iv = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(KEY)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


def encrypt_to_base64(text: str) -> str:
    """Encrypt text with AES-GCM, prepend IV, return base64 string."""
    aesgcm = AESGCM(KEY)
    iv = os.urandom(12) 
    ciphertext = aesgcm.encrypt(iv, text.encode("utf-8"), None)
    combined = iv + ciphertext
    return base64.b64encode(combined).decode("utf-8")


async def handler(websocket):
    print("[SERVER] Client connected")
    try:
        async for message in websocket:
            # message is base64-encoded encrypted data
            try:
                plaintext = decrypt_base64_message(message)
                print(f"[SERVER] Decrypted from client: {plaintext}")
            except Exception as e:
                print(f"[SERVER] Decryption failed: {e}")
                continue

            # Simple echo-style response
            response_text = f"Server got: {plaintext}"
            encrypted_response = encrypt_to_base64(response_text)

            await websocket.send(encrypted_response)
    finally:
        print("[SERVER] Client disconnected")

async def main():
    # Start HTTP server in background thread
    threading.Thread(target=start_http_server, daemon=True).start()

    # Start WebSocket server
    async with websockets.serve(handler, "0.0.0.0", PORT + 1):
        print(f"[SERVER] WebSocket on {PORT+1}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
