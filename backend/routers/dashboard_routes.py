from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends

from database import get_all_other_users, get_broadcasts

from backend.core import active_user, query

router = APIRouter(prefix="/api", tags=["dashboard"])

# ALERT and CRITICAL share one band: they are both "act now", and keeping the
# chart to three severity bands keeps the colours distinguishable.
SEVERITY_BAND = {"INFO": "info", "WARNING": "warning", "ALERT": "high", "CRITICAL": "high"}


def _log_scope(user):
    """Admins see every event; clients see events they caused or that mention them."""
    if user["role"] == "admin":
        return "1=1", ()
    return "(username = ? OR action LIKE ?)", (user["username"], f"%{user['username']}%")


def daily_severity(user, days=14):
    where, params = _log_scope(user)
    since = (datetime.now() - timedelta(days=days - 1)).strftime("%Y-%m-%d")
    rows = query(
        f"SELECT substr(timestamp, 1, 10), severity, COUNT(*) FROM logs "
        f"WHERE {where} AND timestamp >= ? GROUP BY 1, 2",
        params + (since,),
    )
    buckets = defaultdict(lambda: {"info": 0, "warning": 0, "high": 0})
    for day, sev, count in rows:
        buckets[day][SEVERITY_BAND.get(sev, "info")] += count
    start = datetime.now() - timedelta(days=days - 1)
    series = []
    for i in range(days):
        day = (start + timedelta(days=i)).strftime("%Y-%m-%d")
        series.append({"date": day, **buckets[day]})
    return series


@router.get("/users")
def users(user=Depends(active_user)):
    return get_all_other_users(user["username"])


@router.get("/dashboard")
def dashboard(user=Depends(active_user)):
    me = user["username"]
    sent = query("SELECT COUNT(*) FROM messages WHERE sender=?", (me,))[0][0]
    received = query("SELECT COUNT(*) FROM messages WHERE receiver=?", (me,))[0][0]
    unread = query("SELECT COUNT(*) FROM messages WHERE receiver=? AND status!='read'", (me,))[0][0]
    tamper = query(
        "SELECT COUNT(*) FROM logs WHERE (username=? OR action LIKE ?) AND "
        "(action LIKE '%Tampering detected%' OR action LIKE '%hash mismatch%')",
        (me, f"%{me}%"),
    )[0][0]
    failed_decrypt = query(
        "SELECT COUNT(*) FROM logs WHERE username=? AND action LIKE '%Failed decryption%'", (me,)
    )[0][0]
    files_flagged = query(
        "SELECT COUNT(*) FROM file_integrity WHERE (sender=? OR receiver=?) AND status!='safe'", (me, me)
    )[0][0]

    where, params = _log_scope(user)
    recent = query(
        f"SELECT username, action, severity, timestamp FROM logs "
        f"WHERE {where} AND severity IN ('WARNING','ALERT','CRITICAL') ORDER BY id DESC LIMIT 8",
        params,
    )
    broadcasts = get_broadcasts()
    return {
        "kpis": {
            "sent": sent,
            "received": received,
            "unread": unread,
            "tamper_alerts": tamper,
            "failed_decryptions": failed_decrypt,
            "files_flagged": files_flagged,
        },
        "events": daily_severity(user),
        "recent_alerts": [
            {"username": u, "action": a, "severity": s, "timestamp": t} for u, a, s, t in recent
        ],
        "broadcast": (
            {"admin": broadcasts[0][0], "message": broadcasts[0][1], "timestamp": broadcasts[0][2]}
            if broadcasts else None
        ),
    }
