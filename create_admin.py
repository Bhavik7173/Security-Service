"""
╔══════════════════════════════════════════════════════════════╗
║           ADMIN ACCOUNT SETUP — Run this ONCE only          ║
║  python create_admin.py                                      ║
║  This creates the single admin account for the system.      ║
║  Running it again will NOT create a duplicate.              ║
╚══════════════════════════════════════════════════════════════╝
"""

import sys
import getpass
from database import *
from secure_messaging import generate_keys

# ─────────────────────────────────────────────
# ✏️  SET YOUR ADMIN CREDENTIALS HERE
# ─────────────────────────────────────────────
ADMIN_USERNAME       = "admin"          # Change to your desired username
ADMIN_PASSWORD       = "Admin@1234"     # Must be strong (8+ chars, upper, lower, digit, symbol)
ADMIN_PIN            = "1234"           # Must be exactly 4 digits
ADMIN_PERSONAL_KEY   = "mySecretKey99"  # Your personal encryption key (keep this safe!)
# ─────────────────────────────────────────────

def create_admin():
    init_db()

    conn = get_connection()
    cursor = conn.cursor()

    # Check if admin already exists
    cursor.execute("SELECT username FROM users WHERE role='admin'")
    existing = cursor.fetchone()
    if existing:
        print(f"\n⚠️  An admin account already exists: '{existing[0]}'")
        print("    Only ONE admin is allowed. No changes made.")
        conn.close()
        return

    # Check if username is already taken
    cursor.execute("SELECT username FROM users WHERE username=?", (ADMIN_USERNAME,))
    if cursor.fetchone():
        print(f"\n❌ Username '{ADMIN_USERNAME}' is already taken by another account.")
        print("   Change ADMIN_USERNAME in this script and try again.")
        conn.close()
        return

    # Validate PIN
    if not ADMIN_PIN.isdigit() or len(ADMIN_PIN) != 4:
        print("\n❌ PIN must be exactly 4 digits.")
        conn.close()
        return

    # Generate RSA keys
    print("\n🔑 Generating RSA key pair for admin...")
    private_key, public_key = generate_keys()

    # Insert admin user
    cursor.execute("""
        INSERT INTO users (username, password, personal_key, role, pin,
                           public_key, private_key, status, unfreeze_requested, freeze_reason)
        VALUES (?, ?, ?, 'admin', ?, ?, ?, 'active', 0, '')
    """, (
        ADMIN_USERNAME,
        ADMIN_PASSWORD,
        ADMIN_PERSONAL_KEY,
        ADMIN_PIN,
        public_key,
        private_key
    ))

    conn.commit()
    conn.close()

    print("\n✅ Admin account created successfully!")
    print(f"   Username      : {ADMIN_USERNAME}")
    print(f"   Password      : {'*' * len(ADMIN_PASSWORD)}")
    print(f"   PIN           : {'*' * len(ADMIN_PIN)}")
    print(f"   Personal Key  : {'*' * len(ADMIN_PERSONAL_KEY)}")
    print(f"   Role          : admin")
    print("\n⚠️  Keep these credentials safe. Delete this script after setup if needed.")

if __name__ == "__main__":
    create_admin()
