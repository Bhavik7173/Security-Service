import bcrypt
from database import get_connection

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

def register_user(username, password, personal_key, role, pin, public_key, private_key):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if username exists
    cursor.execute("SELECT username FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        return False  # User exists
    
    # Insert user with PIN
    cursor.execute("""
        INSERT INTO users (username, password, personal_key, role, pin, public_key, private_key)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (username, password, personal_key, role, pin, public_key, private_key))
    
    conn.commit()
    conn.close()
    return True

def login_user(username, password):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, personal_key, role, pin FROM users WHERE username=? AND password=?", (username, password))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "username": row[0],
            "personal_key": row[1],
            "role": row[2],
            "pin": row[3]
        }
    return None

import re

def is_strong_password(password):
    """Validate password strength."""
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True
def change_password(username, old_password, new_password):
    """Change password after verifying old one. Returns True on success."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return False, "User not found."
    if row[0] != old_password:
        return False, "Current password is incorrect."
    if not is_strong_password(new_password):
        return False, "New password too weak."
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
    conn.commit()
    conn.close()
    return True, "Password changed successfully."
