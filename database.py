import sqlite3

DB_NAME = "secure_chat.db"

def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # -------------------------
    # USERS TABLE
    # -------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password BLOB,
            personal_key TEXT,
            role TEXT,
            pin TEXT,
            public_key BLOB,
            private_key BLOB,
            status TEXT DEFAULT 'active',
            unfreeze_requested INTEGER DEFAULT 0,
            freeze_reason TEXT DEFAULT ''
        )
    """)

    # Migrate existing DB: add columns if missing
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN unfreeze_requested INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN freeze_reason TEXT DEFAULT ''")
    except Exception:
        pass

    # -------------------------
    # MESSAGES TABLE
    # -------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        encrypted_for TEXT NOT NULL,
        encrypted_message TEXT NOT NULL,
        hash_value TEXT NOT NULL,
        plaintext_hash TEXT,
        timestamp TEXT NOT NULL,
        status TEXT DEFAULT 'sent',
        delivered_at TEXT,
        read_at TEXT,
        attachment_name TEXT,
        attachment_data TEXT,
        attachment_hash TEXT,
        decrypted_message TEXT
    )
    """)

    # -------------------------
    # LOGS TABLE
    # -------------------------
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        severity TEXT DEFAULT 'INFO',
        timestamp TEXT
    )
    """)



    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_integrity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            file_name TEXT,
            file_path TEXT,
            original_hash TEXT,
            last_checked_hash TEXT,
            status TEXT,
            upload_time TEXT,
            last_checked_time TEXT
        )
    """)

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

def get_all_other_users(current_user):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users WHERE username != ?", (current_user,))
    users = [row[0] for row in cursor.fetchall()]

    conn.close()
    return users
def freeze_user(username, reason="Duress alert triggered"):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET status='frozen', freeze_reason=?, unfreeze_requested=0 WHERE username=?",
        (reason, username)
    )
    conn.commit()
    conn.close()

def unfreeze_user(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET status='active', freeze_reason='', unfreeze_requested=0 WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()

def request_unfreeze(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET unfreeze_requested=1 WHERE username=?",
        (username,)
    )
    conn.commit()
    conn.close()

def get_user_status(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT status, unfreeze_requested, freeze_reason FROM users WHERE username=?",
        (username,)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"status": row[0], "unfreeze_requested": row[1], "freeze_reason": row[2]}
    return {"status": "active", "unfreeze_requested": 0, "freeze_reason": ""}

def get_frozen_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, freeze_reason, unfreeze_requested FROM users WHERE status='frozen'"
    )
    rows = cursor.fetchall()
    conn.close()
    return rows

# ── Broadcast alerts ──────────────────────────────────────────────────────────
def create_broadcast(admin_user, message):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS broadcasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user TEXT,
            message TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(
        "INSERT INTO broadcasts (admin_user, message, timestamp) VALUES (?,?,?)",
        (admin_user, message, __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_broadcasts():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS broadcasts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user TEXT,
            message TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute("SELECT admin_user, message, timestamp FROM broadcasts ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return rows

# ── User preferences (dark mode, session timeout) ────────────────────────────
def get_user_pref(username, key, default=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_prefs (
            username TEXT,
            key TEXT,
            value TEXT,
            PRIMARY KEY (username, key)
        )
    """)
    cursor.execute("SELECT value FROM user_prefs WHERE username=? AND key=?", (username, key))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default

def set_user_pref(username, key, value):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_prefs (
            username TEXT,
            key TEXT,
            value TEXT,
            PRIMARY KEY (username, key)
        )
    """)
    cursor.execute(
        "INSERT OR REPLACE INTO user_prefs (username, key, value) VALUES (?,?,?)",
        (username, key, str(value))
    )
    conn.commit()
    conn.close()

# ── Login attempt lockout ─────────────────────────────────────────────────────
def record_failed_login(username):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN lockout_until TEXT DEFAULT ''")
    except Exception:
        pass
    cursor.execute(
        "UPDATE users SET failed_attempts = COALESCE(failed_attempts,0)+1 WHERE username=?",
        (username,)
    )
    cursor.execute("SELECT failed_attempts FROM users WHERE username=?", (username,))
    row = cursor.fetchone()
    locked = False
    if row and row[0] >= 5:
        from datetime import datetime, timedelta
        lockout_time = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("UPDATE users SET lockout_until=?, failed_attempts=0 WHERE username=?",
                       (lockout_time, username))
        locked = True
    conn.commit()
    conn.close()
    return locked

def reset_failed_logins(username):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET failed_attempts=0, lockout_until='' WHERE username=?", (username,))
        conn.commit()
    except Exception:
        pass
    conn.close()

def check_lockout(username):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT lockout_until FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row and row[0]:
            from datetime import datetime
            lockout_until = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
            if datetime.now() < lockout_until:
                remaining = int((lockout_until - datetime.now()).total_seconds() / 60)
                return True, remaining
        return False, 0
    except Exception:
        conn.close()
        return False, 0

# ── Message reactions ─────────────────────────────────────────────────────────
def add_reaction(message_id, username, emoji):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER,
            username TEXT,
            emoji TEXT,
            timestamp TEXT,
            UNIQUE(message_id, username)
        )
    """)
    cursor.execute("""
        INSERT OR REPLACE INTO reactions (message_id, username, emoji, timestamp)
        VALUES (?,?,?,?)
    """, (message_id, username, emoji,
          __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_reactions(message_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER,
            username TEXT,
            emoji TEXT,
            timestamp TEXT,
            UNIQUE(message_id, username)
        )
    """)
    cursor.execute(
        "SELECT emoji, username FROM reactions WHERE message_id=?", (message_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows

# ── Admin notes on users ──────────────────────────────────────────────────────
def save_admin_note(admin_user, target_user, note):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user TEXT,
            target_user TEXT,
            note TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(
        "INSERT INTO admin_notes (admin_user, target_user, note, timestamp) VALUES (?,?,?,?)",
        (admin_user, target_user, note,
         __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_admin_notes(target_user):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_user TEXT,
            target_user TEXT,
            note TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(
        "SELECT admin_user, note, timestamp FROM admin_notes WHERE target_user=? ORDER BY id DESC",
        (target_user,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows

# ── IP / device logging ───────────────────────────────────────────────────────
def log_login_device(username, ip, user_agent):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            user_agent TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(
        "INSERT INTO login_devices (username, ip, user_agent, timestamp) VALUES (?,?,?,?)",
        (username, ip, user_agent,
         __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_login_devices(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            user_agent TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute(
        "SELECT ip, user_agent, timestamp FROM login_devices WHERE username=? ORDER BY id DESC LIMIT 20",
        (username,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows
