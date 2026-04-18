# secure_messaging.py

import sqlite3
import hashlib
from datetime import datetime

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# -----------------------------
# 🔑 KEY MANAGEMENT
# -----------------------------

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def load_private_key(key_data):
    return RSA.import_key(key_data)


def load_public_key(key_data):
    return RSA.import_key(key_data)


# -----------------------------
# 🧮 HASHING
# -----------------------------

def generate_hash(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()


# -----------------------------
# ✍️ DIGITAL SIGNATURE
# -----------------------------

def sign_data(data_bytes, private_key):
    h = SHA256.new(data_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_signature(data_bytes, signature, public_key):
    h = SHA256.new(data_bytes)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except:
        return False


# -----------------------------
# 🔐 ENCRYPTION / DECRYPTION
# -----------------------------

def encrypt_message(message_bytes, receiver_public_key):
    cipher = PKCS1_OAEP.new(receiver_public_key)
    return cipher.encrypt(message_bytes)


def decrypt_message(encrypted_bytes, receiver_private_key):
    cipher = PKCS1_OAEP.new(receiver_private_key)
    return cipher.decrypt(encrypted_bytes)


# -----------------------------
# 💾 DATABASE SETUP
# -----------------------------

def init_secure_messages_table():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS secure_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        encrypted_message BLOB,
        signature BLOB,
        hash TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


# -----------------------------
# 📤 SEND SECURE MESSAGE
# -----------------------------

def send_secure_message(sender, receiver, message,
                        sender_private_key,
                        receiver_public_key):

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    message_bytes = message.encode()

    # 1. Hash
    hash_value = generate_hash(message_bytes)

    # 2. Sign
    signature = sign_data(message_bytes, sender_private_key)

    # 3. Encrypt
    encrypted_message = encrypt_message(message_bytes, receiver_public_key)

    # Store
    cursor.execute("""
    INSERT INTO secure_messages 
    (sender, receiver, encrypted_message, signature, hash, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        sender,
        receiver,
        encrypted_message,
        signature,
        hash_value,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# -----------------------------
# 📥 RECEIVE + VERIFY
# -----------------------------

def receive_secure_messages(user, user_private_key, get_public_key_func):
    """
    get_public_key_func(username) -> returns public key
    """

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT sender, encrypted_message, signature, hash, timestamp
    FROM secure_messages
    WHERE receiver = ?
    """, (user,))

    messages = cursor.fetchall()
    conn.close()

    results = []

    for sender, enc_msg, signature, stored_hash, timestamp in messages:

        try:
            # Decrypt
            decrypted = decrypt_message(enc_msg, user_private_key)

            # New hash
            new_hash = generate_hash(decrypted)

            # Get sender public key
            sender_public_key = get_public_key_func(sender)

            # Verify signature
            is_valid_signature = verify_signature(
                decrypted,
                signature,
                sender_public_key
            )

            # Integrity check
            integrity_ok = (new_hash == stored_hash)

            results.append({
                "sender": sender,
                "message": decrypted.decode(),
                "timestamp": timestamp,
                "signature_valid": is_valid_signature,
                "integrity_ok": integrity_ok
            })

        except Exception as e:
            results.append({
                "sender": sender,
                "message": "DECRYPTION FAILED",
                "timestamp": timestamp,
                "signature_valid": False,
                "integrity_ok": False
            })

    return results