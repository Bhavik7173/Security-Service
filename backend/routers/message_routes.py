from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from crypto_utils import double_decrypt, double_encrypt, hash_message
from logger import log_action
from tamper_detection import verify_integrity

from backend.core import active_user, check_pin, execute, query

router = APIRouter(prefix="/api/messages", tags=["messages"])

NOW = lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731


class SendBody(BaseModel):
    receiver: str
    message: str


class PinBody(BaseModel):
    pin: str


def _row_to_message(row, me):
    msg_id, sender, receiver, encrypted, decrypted, timestamp, status, read_at = row
    return {
        "id": msg_id,
        "sender": sender,
        "receiver": receiver,
        "outgoing": sender == me,
        # Only the receiver ever decrypts; senders see ciphertext until then.
        "text": decrypted if (decrypted and receiver == me) else None,
        "ciphertext_preview": (encrypted or "")[:64],
        "timestamp": timestamp,
        "status": status,
        "read_at": read_at,
    }


@router.get("/conversation/{other}")
def conversation(other: str, user=Depends(active_user)):
    me = user["username"]
    rows = query(
        """SELECT id, sender, receiver, encrypted_message, decrypted_message, timestamp, status, read_at
           FROM messages
           WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
           ORDER BY id ASC""",
        (me, other, other, me),
    )
    return [_row_to_message(r, me) for r in rows]


@router.post("", status_code=201)
def send(body: SendBody, user=Depends(active_user)):
    me = user["username"]
    text = body.message.strip()
    if not text:
        raise HTTPException(422, "Message cannot be empty.")
    row = query("SELECT personal_key FROM users WHERE username=?", (body.receiver,))
    if not row or body.receiver == me:
        raise HTTPException(404, "Receiver not found.")

    plaintext_hash = hash_message(text)
    _, second_layer = double_encrypt(text, row[0][0])
    msg_id = execute(
        """INSERT INTO messages (sender, receiver, encrypted_for, encrypted_message,
                                 hash_value, plaintext_hash, timestamp, status)
           VALUES (?, ?, ?, ?, ?, ?, ?, 'sent')""",
        (me, body.receiver, body.receiver, second_layer, hash_message(second_layer), plaintext_hash, NOW()),
    )
    log_action(me, f"Sent message/file to {body.receiver}", "INFO")
    return {"id": msg_id}


@router.get("/inbox")
def inbox(user=Depends(active_user)):
    me = user["username"]
    # Fetching the inbox marks messages as delivered (same as the Streamlit app).
    execute("UPDATE messages SET status='delivered', delivered_at=? WHERE receiver=? AND status='sent'", (NOW(), me))
    rows = query(
        """SELECT id, sender, receiver, encrypted_message, decrypted_message, timestamp, status, read_at
           FROM messages WHERE receiver=? ORDER BY id DESC""",
        (me,),
    )
    return [_row_to_message(r, me) for r in rows]


@router.post("/{msg_id}/decrypt")
def decrypt(msg_id: int, body: PinBody, user=Depends(active_user)):
    me = user["username"]
    rows = query(
        "SELECT sender, encrypted_message, hash_value, plaintext_hash FROM messages WHERE id=? AND receiver=?",
        (msg_id, me),
    )
    if not rows:
        raise HTTPException(404, "Message not found.")
    sender, encrypted, stored_hash, stored_plain_hash = rows[0]

    pin_result = check_pin(body.pin, user, f"decrypt message {msg_id}")
    if pin_result == "wrong":
        log_action(me, f"Incorrect PIN attempt for message {msg_id}", "WARNING")
        raise HTTPException(403, "Incorrect PIN. Access denied.")

    # Step 1: ciphertext integrity
    if not verify_integrity(encrypted, stored_hash):
        log_action(me, f"Tampering detected on encrypted message {msg_id}", "ALERT")
        return {"verdict": "tampered", "detail": "Encrypted message failed its integrity check."}

    # Step 2: decrypt both layers
    try:
        server_layer, original = double_decrypt(encrypted, user["personal_key"])
    except Exception:
        log_action(me, f"Failed decryption attempt on message {msg_id}", "WARNING")
        return {"verdict": "failed", "detail": "Decryption failed. Wrong key or corrupted data."}

    # Step 3: plaintext hash must match what the sender recorded
    receiver_hash = hash_message(original)
    if receiver_hash != stored_plain_hash:
        log_action(me, f"Plaintext hash mismatch detected on message {msg_id}", "ALERT")
        return {
            "verdict": "mismatch",
            "detail": "Sender and receiver plaintext hashes do not match.",
            "sender_hash": stored_plain_hash,
            "receiver_hash": receiver_hash,
        }

    execute(
        "UPDATE messages SET decrypted_message=?, status='read', read_at=? WHERE id=?",
        (original, NOW(), msg_id),
    )
    log_action(me, f"Decrypted and verified message {msg_id} from {sender}", "INFO")
    return {
        "verdict": "verified",
        "message": original,
        "sender_hash": stored_plain_hash,
        "receiver_hash": receiver_hash,
    }
