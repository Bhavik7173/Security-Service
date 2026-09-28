import csv
import io
import os
import platform
import shutil

import numpy as np
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth import change_password
from database import create_broadcast, freeze_user, get_login_devices, unfreeze_user
from logger import log_action
from network_analysis import (
    add_anomaly_labels,
    clean_network_data,
    get_summary_stats,
    load_network_data,
    run_anomaly_detection,
    select_features,
)

from backend.core import active_user, admin_user, query
from backend.routers.dashboard_routes import _log_scope, daily_severity

router = APIRouter(prefix="/api", tags=["security"])


# ── Security overview ──────────────────────────────────────────────────────────
@router.get("/security/overview")
def overview(user=Depends(active_user)):
    me = user["username"]
    status_rows = query("SELECT status, COUNT(*) FROM messages WHERE sender=? OR receiver=? GROUP BY status", (me, me))
    where, params = _log_scope(user)
    sev_rows = query(f"SELECT severity, COUNT(*) FROM logs WHERE {where} GROUP BY severity", params)
    signals = {
        "failed_logins": "%Failed login attempt%",
        "failed_decryptions": "%Failed decryption%",
        "wrong_pins": "%PIN%",
        "tamper_events": "%Tampering detected%",
        "duress_alerts": "%DURESS ALERT%",
    }
    counts = {
        key: query(f"SELECT COUNT(*) FROM logs WHERE {where} AND action LIKE ?", params + (pattern,))[0][0]
        for key, pattern in signals.items()
    }
    file_rows = query(
        "SELECT status, COUNT(*) FROM file_integrity WHERE sender=? OR receiver=? GROUP BY status", (me, me)
    )
    return {
        "message_status": dict(status_rows),
        "severity": dict(sev_rows),
        "signals": counts,
        "files": dict(file_rows),
        "events": daily_severity(user, days=30),
    }


# ── Audit logs ─────────────────────────────────────────────────────────────────
def _logs(user, severity=None, q=None, limit=500):
    where, params = _log_scope(user)
    if severity:
        where += " AND severity = ?"
        params += (severity,)
    if q:
        where += " AND (action LIKE ? OR username LIKE ?)"
        params += (f"%{q}%", f"%{q}%")
    rows = query(
        f"SELECT id, username, action, severity, timestamp FROM logs WHERE {where} ORDER BY id DESC LIMIT ?",
        params + (limit,),
    )
    return [{"id": i, "username": u, "action": a, "severity": s, "timestamp": t} for i, u, a, s, t in rows]


@router.get("/logs")
def logs(severity: str | None = None, q: str | None = None, user=Depends(active_user)):
    return _logs(user, severity, q)


@router.get("/logs/export.csv")
def export_logs(severity: str | None = None, q: str | None = None, user=Depends(active_user)):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "username", "severity", "action"])
    for row in _logs(user, severity, q, limit=100000):
        writer.writerow([row["timestamp"], row["username"], row["severity"], row["action"]])
    log_action(user["username"], "Exported audit logs as CSV", "INFO")
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-logs.csv"},
    )


# ── Network traffic analysis ───────────────────────────────────────────────────
SCATTER_X, SCATTER_Y = "Flow Bytes/s", "Flow Packets/s"


@router.post("/network/analyze")
async def analyze(file: UploadFile = File(...), user=Depends(admin_user)):
    try:
        df = clean_network_data(load_network_data(io.BytesIO(await file.read())))
    except Exception:
        raise HTTPException(422, "Could not read that file as CSV.")
    features_df, features = select_features(df)
    if not features:
        raise HTTPException(422, "None of the expected CIC-IDS2017 feature columns were found.")
    if len(features_df) < 10:
        raise HTTPException(422, "Need at least 10 clean rows to run anomaly detection.")

    df = add_anomaly_labels(df, run_anomaly_detection(features_df))
    summary = get_summary_stats(df)

    # Down-sample for the scatter plot, but always keep every suspicious flow.
    x_col = SCATTER_X if SCATTER_X in df.columns else features[0]
    y_col = SCATTER_Y if SCATTER_Y in df.columns else features[min(1, len(features) - 1)]
    suspicious = df[df["Anomaly_Label"] == "Suspicious"]
    normal = df[df["Anomaly_Label"] == "Normal"]
    normal = normal.sample(min(len(normal), 1500), random_state=0)
    points = [
        {"x": float(r[x_col]), "y": float(r[y_col]), "suspicious": label == "Suspicious"}
        for label, frame in (("Normal", normal), ("Suspicious", suspicious))
        for _, r in frame.iterrows()
    ]
    top = suspicious.head(50)
    columns = (["Label"] if "Label" in df.columns else []) + features
    log_action(user["username"], f"Ran network anomaly detection on {file.filename} ({summary['Total Flows']} flows)", "INFO")
    return {
        "summary": {
            "total": summary["Total Flows"],
            "suspicious": summary["Suspicious Flows"],
            "normal": summary["Normal Flows"],
        },
        "features": features,
        "axes": {"x": x_col, "y": y_col},
        "points": points,
        "suspicious_rows": {
            "columns": columns,
            "rows": [[(None if (isinstance(v, float) and np.isnan(v)) else v) for v in r]
                     for r in top[columns].round(3).values.tolist()],
        },
    }


# ── Administration ─────────────────────────────────────────────────────────────
class BroadcastBody(BaseModel):
    message: str


class FreezeBody(BaseModel):
    reason: str = "Frozen by administrator"


@router.get("/admin/users")
def admin_users(user=Depends(admin_user)):
    rows = query("SELECT username, role, status, unfreeze_requested, freeze_reason FROM users ORDER BY username")
    result = []
    for username, role, status, requested, reason in rows:
        risk = query(
            "SELECT COUNT(*) FROM logs WHERE username=? AND severity IN ('WARNING','ALERT','CRITICAL')", (username,)
        )[0][0]
        last = query("SELECT MAX(timestamp) FROM logs WHERE username=? AND action LIKE 'Logged in%'", (username,))[0][0]
        result.append({
            "username": username, "role": role, "status": status or "active",
            "unfreeze_requested": bool(requested), "freeze_reason": reason or "",
            "risk_events": risk, "last_login": last,
        })
    return result


@router.post("/admin/users/{username}/freeze")
def admin_freeze(username: str, body: FreezeBody, user=Depends(admin_user)):
    if username == user["username"]:
        raise HTTPException(422, "You cannot freeze your own account.")
    freeze_user(username, reason=body.reason)
    log_action(user["username"], f"Froze account {username}: {body.reason}", "WARNING")
    return {"ok": True}


@router.post("/admin/users/{username}/unfreeze")
def admin_unfreeze(username: str, user=Depends(admin_user)):
    unfreeze_user(username)
    log_action(user["username"], f"Unfroze account {username}", "INFO")
    return {"ok": True}


@router.post("/admin/broadcast", status_code=201)
def admin_broadcast(body: BroadcastBody, user=Depends(admin_user)):
    if not body.message.strip():
        raise HTTPException(422, "Broadcast message cannot be empty.")
    create_broadcast(user["username"], body.message.strip())
    log_action(user["username"], "Sent admin broadcast", "INFO")
    return {"ok": True}


@router.get("/admin/system")
def admin_system(user=Depends(admin_user)):
    disk = shutil.disk_usage(".")
    db_size = os.path.getsize("secure_chat.db") if os.path.exists("secure_chat.db") else 0
    uploads = sum(
        os.path.getsize(os.path.join("uploaded_files", f))
        for f in (os.listdir("uploaded_files") if os.path.isdir("uploaded_files") else [])
        if os.path.isfile(os.path.join("uploaded_files", f))
    )
    return {
        "users": query("SELECT COUNT(*) FROM users")[0][0],
        "messages": query("SELECT COUNT(*) FROM messages")[0][0],
        "log_entries": query("SELECT COUNT(*) FROM logs")[0][0],
        "files": query("SELECT COUNT(*) FROM file_integrity")[0][0],
        "db_bytes": db_size,
        "uploads_bytes": uploads,
        "disk_used_pct": round(disk.used / disk.total * 100, 1),
        "python": platform.python_version(),
        "os": f"{platform.system()} {platform.release()}",
    }


# ── Profile ────────────────────────────────────────────────────────────────────
class PasswordBody(BaseModel):
    current_password: str
    new_password: str


@router.get("/profile")
def profile(user=Depends(active_user)):
    me = user["username"]
    count = lambda pattern: query(  # noqa: E731
        "SELECT COUNT(*) FROM logs WHERE username=? AND action LIKE ?", (me, pattern)
    )[0][0]
    failed_logins, failed_decrypt = count("%Failed login attempt%"), count("%Failed decryption%")
    tamper = query(
        "SELECT COUNT(*) FROM logs WHERE (username=? OR action LIKE ?) AND action LIKE '%Tampering detected%'",
        (me, f"%{me}%"),
    )[0][0]
    return {
        "username": me,
        "role": user["role"],
        # Same weighting as the Streamlit Profile page.
        "risk_score": failed_logins * 2 + failed_decrypt * 3 + tamper * 5,
        "risk_breakdown": {"failed_logins": failed_logins, "failed_decryptions": failed_decrypt, "tamper_events": tamper},
        "devices": [{"ip": ip, "agent": ua, "timestamp": ts} for ip, ua, ts in get_login_devices(me)],
    }


@router.post("/profile/password")
def update_password(body: PasswordBody, user=Depends(active_user)):
    ok, message = change_password(user["username"], body.current_password, body.new_password)
    if not ok:
        raise HTTPException(422, message)
    log_action(user["username"], "Changed account password", "INFO")
    return {"ok": True}
