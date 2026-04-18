from database import get_connection
from datetime import datetime

def log_action(username, action, severity="INFO"):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO logs (username, action, severity, timestamp) VALUES (?, ?, ?, ?)",
        (username, action, severity, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    conn.commit()
    conn.close()

    # Auto-freeze account when a duress alert is raised
    if "[DURESS ALERT]" in action:
        from database import freeze_user
        freeze_user(username, reason="Duress PIN entered — possible coercion")

def get_logs():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username, action, severity, timestamp FROM logs ORDER BY id DESC")
    logs = cursor.fetchall()
    conn.close()

    return logs

def get_user_logs(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT username, action, severity, timestamp
        FROM logs
        WHERE username = ? OR action LIKE ?
        ORDER BY id DESC
    """, (username, f"%{username}%"))
    logs = cursor.fetchall()
    conn.close()
    return logs