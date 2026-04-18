import base64
import hashlib
from cryptography.fernet import Fernet

SERVER_PROTECTION_KEY = "server_master_secret"

def generate_key(password: str) -> bytes:
    sha = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(sha)

def encrypt_message(message: str, password: str) -> str:
    key = generate_key(password)
    cipher = Fernet(key)
    encrypted = cipher.encrypt(message.encode())
    return encrypted.decode()

def decrypt_message(encrypted_message: str, password: str) -> str:
    key = generate_key(password)
    cipher = Fernet(key)
    decrypted = cipher.decrypt(encrypted_message.encode())
    return decrypted.decode()

# def hash_message(data: str) -> str:
#     return hashlib.sha256(data.encode()).hexdigest()

def hash_message(data):
    if data is None:
        raise ValueError("Cannot hash None value")

    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='ignore')

    return hashlib.sha256(str(data).encode('utf-8')).hexdigest()

def double_encrypt(message: str, client_key: str) -> tuple:
    first_layer = encrypt_message(message, client_key)
    second_layer = encrypt_message(first_layer, SERVER_PROTECTION_KEY)
    return first_layer, second_layer

def double_decrypt(encrypted_message: str, client_key: str) -> tuple:
    first_decrypt = decrypt_message(encrypted_message, SERVER_PROTECTION_KEY)
    original_message = decrypt_message(first_decrypt, client_key)
    return first_decrypt, original_message


# ── File encryption (works on raw bytes) ──────────────────────────────────────

def encrypt_file_bytes(file_bytes: bytes, pin: str) -> bytes:
    """Encrypt raw file bytes using the sender's PIN. Returns encrypted bytes."""
    key = generate_key(pin)
    cipher = Fernet(key)
    return cipher.encrypt(file_bytes)


def decrypt_file_bytes(encrypted_bytes: bytes, pin: str) -> bytes:
    """Decrypt file bytes using the receiver's PIN. Returns original file bytes."""
    key = generate_key(pin)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_bytes)