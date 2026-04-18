from crypto_utils import hash_message

def verify_integrity(encrypted_message, stored_hash):
    current_hash = hash_message(encrypted_message)
    return current_hash == stored_hash