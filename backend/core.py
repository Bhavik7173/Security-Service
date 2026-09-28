"""
Shared plumbing for the REST API: paths, auth tokens, request dependencies and PIN checks.

The API reuses the original project modules (database, auth, crypto_utils, logger, ...),
which open SQLite files relative to the working directory. We therefore run from the
repository root so the API and the Streamlit app share the same database.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time

from fastapi import Depends, Header, HTTPException, status

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from database import get_connection, get_user_status  # noqa: E402
from logger import log_action  # noqa: E402

# Set SECURITY_API_SECRET in production so tokens survive restarts.
SECRET = os.environ.get("SECURITY_API_SECRET") or secrets.token_hex(32)
TOKEN_TTL_SECONDS = int(os.environ.get("SECURITY_API_TOKEN_TTL", 8 * 3600))


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_token(username: str) -> str:
    payload = _b64(json.dumps({"sub": username, "exp": int(time.time()) + TOKEN_TTL_SECONDS}).encode())
    sig = _b64(hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify_token(token: str):
    try:
        payload, sig = token.split(".")
        expected = _b64(hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        data = json.loads(_unb64(payload))
        if data["exp"] < time.time():
            return None
        return data["sub"]
    except Exception:
        return None


def load_user(username: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, role, pin, personal_key FROM users WHERE username=?", (username,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {"username": row[0], "role": row[1], "pin": str(row[2]), "personal_key": row[3]}


def public_user(user: dict) -> dict:
    """User fields that are safe to send to the browser."""
    st = get_user_status(user["username"])
    return {
        "username": user["username"],
        "role": user["role"],
        "status": st["status"],
        "freeze_reason": st["freeze_reason"],
        "unfreeze_requested": bool(st["unfreeze_requested"]),
    }


def current_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    username = verify_token(token) if token else None
    user = load_user(username) if username else None
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    return user


def active_user(user=Depends(current_user)):
    if get_user_status(user["username"])["status"] == "frozen":
        raise HTTPException(status.HTTP_423_LOCKED, "Account is frozen")
    return user


def admin_user(user=Depends(active_user)):
    if user["role"] != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrator access required")
    return user


def check_pin(entered_pin: str, user: dict, context: str) -> str:
    """
    Same rules as the Streamlit app:
      'ok'     - correct PIN
      'duress' - reversed PIN: silent CRITICAL alert (auto-freezes the account), behave normally
      'wrong'  - anything else
    """
    real_pin = user["pin"]
    entered_pin = (entered_pin or "").strip()
    if entered_pin == real_pin:
        return "ok"
    if entered_pin == real_pin[::-1] and entered_pin != real_pin:
        log_action(user["username"], f"[DURESS ALERT] User entered reversed PIN during: {context}", "CRITICAL")
        return "duress"
    return "wrong"


def query(sql: str, params=()):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()
    return rows


def execute(sql: str, params=()):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(sql, params)
    conn.commit()
    last_id = cursor.lastrowid
    conn.close()
    return last_id
