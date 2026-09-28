import { useState } from "react";
import { LogOut, Send, Snowflake } from "lucide-react";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { Alert, Button } from "../components/ui";

export default function Frozen() {
  const { user, logout, refresh } = useAuth();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const request = async () => {
    setBusy(true);
    try {
      await api("/api/auth/unfreeze-request", { method: "POST" });
      await refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-panel" style={{ minHeight: "100%" }}>
      <div className="card auth-card" style={{ maxWidth: 480 }}>
        <div className="card-body stack">
          <div className="stat-icon danger" aria-hidden="true"><Snowflake size={20} /></div>
          <h2 style={{ fontSize: "1.35rem" }}>Your account is frozen</h2>
          <p className="muted">
            For your protection, access has been suspended{user.freeze_reason ? `: ${user.freeze_reason}` : "."} An administrator must review the account before it can be used again.
          </p>
          {error && <Alert tone="danger">{error}</Alert>}
          {user.unfreeze_requested ? (
            <Alert tone="info" title="Request sent">An administrator will review your account shortly.</Alert>
          ) : (
            <Button variant="primary" icon={Send} loading={busy} onClick={request}>Request unfreeze</Button>
          )}
          <Button variant="ghost" icon={LogOut} onClick={logout}>Sign out</Button>
        </div>
      </div>
    </div>
  );
}
