import hashlib
import os
from datetime import datetime
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel

from crypto_utils import decrypt_file_bytes, encrypt_file_bytes
from file_integrity import get_received_files, get_sent_files, save_file_record, update_file_status
from logger import log_action

from backend.core import active_user, check_pin, query

router = APIRouter(prefix="/api/files", tags=["files"])

UPLOAD_DIR = "uploaded_files"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


class PinBody(BaseModel):
    pin: str


def _file_row(row, direction):
    file_id, other, name, _path, original_hash, last_hash, status, uploaded, checked = row
    return {
        "id": file_id,
        "direction": direction,
        "counterpart": other,
        "name": name,
        "original_hash": original_hash,
        "last_checked_hash": last_hash,
        "status": status,
        "uploaded_at": uploaded,
        "last_checked_at": checked,
    }


@router.get("")
def list_files(user=Depends(active_user)):
    me = user["username"]
    return {
        "received": [_file_row(r, "received") for r in get_received_files(me)],
        "sent": [_file_row(r, "sent") for r in get_sent_files(me)],
    }


@router.post("", status_code=201)
async def send_file(
    receiver: str = Form(...),
    pin: str = Form(...),
    file: UploadFile = File(...),
    user=Depends(active_user),
):
    me = user["username"]
    pin_result = check_pin(pin, user, f"send file {file.filename}")
    if pin_result == "wrong":
        log_action(me, f"Wrong PIN on file send: {file.filename}", "WARNING")
        raise HTTPException(403, "Incorrect PIN. File not sent.")

    rows = query("SELECT pin FROM users WHERE username=?", (receiver,))
    if not rows or receiver == me:
        raise HTTPException(404, "Receiver not found.")

    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File is larger than 25 MB.")

    # Encrypt with the receiver's PIN so only they can open it; keep a hash of the original.
    safe_name = os.path.basename(file.filename or "upload.bin")
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    path = os.path.join(UPLOAD_DIR, f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{safe_name}")
    with open(path, "wb") as fh:
        fh.write(encrypt_file_bytes(raw, str(rows[0][0])))

    original_hash = hashlib.sha256(raw).hexdigest()
    save_file_record(me, receiver, safe_name, path, original_hash)
    log_action(me, f"Sent encrypted file '{safe_name}' to {receiver}", "INFO")
    return {"ok": True, "sha256": original_hash}


@router.post("/{file_id}/decrypt")
def decrypt_file(file_id: int, body: PinBody, user=Depends(active_user)):
    me = user["username"]
    rows = query(
        "SELECT file_name, file_path, original_hash FROM file_integrity WHERE id=? AND receiver=?",
        (file_id, me),
    )
    if not rows:
        raise HTTPException(404, "File not found.")
    name, path, original_hash = rows[0]

    pin_result = check_pin(body.pin, user, f"decrypt file {name}")
    if pin_result == "wrong":
        log_action(me, f"Wrong PIN attempt for file: {name}", "WARNING")
        raise HTTPException(403, "Incorrect PIN. File access denied.")

    if not os.path.exists(path):
        log_action(me, f"File missing on server: {name}", "ALERT")
        raise HTTPException(410, "File not found on server. It may have been moved or deleted.")

    try:
        with open(path, "rb") as fh:
            # Use the stored PIN so a duress PIN still "works" while the silent alert fires.
            decrypted = decrypt_file_bytes(fh.read(), user["pin"])
    except Exception:
        update_file_status(file_id, "decryption-failed", "tampered")
        log_action(me, f"Tampering detected on file {name}: decryption failed", "ALERT")
        raise HTTPException(409, "File failed to decrypt. It may have been tampered with.")

    decrypted_hash = hashlib.sha256(decrypted).hexdigest()
    if decrypted_hash != original_hash:
        update_file_status(file_id, decrypted_hash, "tampered")
        log_action(me, f"Tampering detected on file {name}: hash mismatch", "ALERT")
        raise HTTPException(409, "Integrity check failed: the file's hash has changed.")

    update_file_status(file_id, decrypted_hash, "safe")
    log_action(me, f"Successfully decrypted & downloaded: {name}", "INFO")
    return Response(
        decrypted,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quote(name)}",
            "X-File-SHA256": decrypted_hash,
            "Access-Control-Expose-Headers": "Content-Disposition, X-File-SHA256",
        },
    )
