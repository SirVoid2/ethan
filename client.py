import asyncio
import websockets
import json
import base64
import os
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# AES 5-layer helpers
def generate_password(length=32):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return ''.join(secrets.choice(chars) for _ in range(length))

def aes_encrypt(plaintext, key):
    key_bytes = key.encode()[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    encryptor = cipher.encryptor()
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + chr(pad_len) * pad_len
    ct = encryptor.update(padded.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(ciphertext_b64, key):
    key_bytes = key.encode()[:32]
    data = base64.b64decode(ciphertext_b64)
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    return padded[:-pad_len].decode()

def combine_passwords(passwords):
    return "|".join(passwords).encode()

def split_passwords(universal_key_bytes):
    return universal_key_bytes.decode().split("|")

# RSA helpers
def load_or_generate_rsa(username):
    key_file = f"{username}_rsa.pem"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
    return private_key, private_key.public_key()

def rsa_public_key_to_pem(public_key):
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def rsa_encrypt(message_bytes, public_key_pem):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    return public_key.encrypt(
        message_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_decrypt(ciphertext_bytes, private_key):
    return private_key.decrypt(
        ciphertext_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

# Receiving loop
async def receive_messages(ws, private_key, public_keys):
    while True:
        try:
            msg = await ws.recv()
            msg_data = json.loads(msg)
            if msg_data.get("type") == "keys_update":
                public_keys.update(msg_data["keys"])
                continue

            encrypted_key_bytes = base64.b64decode(msg_data["universal_key"])
            universal_key_bytes = rsa_decrypt(encrypted_key_bytes, private_key)
            passwords = split_passwords(universal_key_bytes)

            ciphertext = msg_data["ciphertext"]
            decrypted = ciphertext
            for pwd in reversed(passwords):
                decrypted = aes_decrypt(decrypted, pwd)

            print(f"[{msg_data['from']}]: {decrypted}")
        except:
            continue

# Main client
async def run_client():
    ws_url = os.environ.get("WS_URL", "ws://localhost:8765")  # server URL
    username = os.environ.get("USERNAME", "headless_user")
    peer_username = os.environ.get("PEER", "peer_user")

    private_key, public_key = load_or_generate_rsa(username)
    public_key_pem = rsa_public_key_to_pem(public_key)
    public_keys = {}

    async with websockets.connect(ws_url) as ws:
        asyncio.create_task(receive_messages(ws, private_key, public_keys))

        # Register
        await ws.send(json.dumps({"type":"register","username":username,"public_key":public_key_pem}))

        # Wait for peer
        while peer_username not in public_keys:
            await asyncio.sleep(1)

        # Send messages automatically every 5 seconds
        while True:
            msg_text = "Hello from Render client!"
            passwords = [generate_password() for _ in range(5)]
            ciphertext = msg_text
            for pwd in passwords:
                ciphertext = aes_encrypt(ciphertext, pwd)

            universal_key_bytes = combine_passwords(passwords)
            peer_public_key_pem = public_keys[peer_username]

            encrypted_key = rsa_encrypt(universal_key_bytes, peer_public_key_pem)
            encrypted_key_b64 = base64.b64encode(encrypted_key).decode()

            msg_payload = json.dumps({
                "type":"message",
                "from": username,
                "to": peer_username,
                "universal_key": encrypted_key_b64,
                "ciphertext": ciphertext
            })
            await ws.send(msg_payload)
            await asyncio.sleep(5)

if __name__ == "__main__":
    asyncio.run(run_client())
