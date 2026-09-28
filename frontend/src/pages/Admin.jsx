import { useState } from "react";
import { Database, HardDrive, Megaphone, MessageSquare, ScrollText, Snowflake, Sun, Users } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { fmtBytes, fmtDateTime, useApi } from "../lib/useApi";
import { useToast } from "../lib/toast";
import { Badge, Button, Card, ErrorState, Field, Modal, PageHead, SkeletonRows, StatTile } from "../components/ui";

function FreezeDialog({ username, onClose, onDone }) {
  const [reason, setReason] = useState("Suspicious activity under review");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    try {
      await api(`/api/admin/users/${encodeURIComponent(username)}/freeze`, { method: "POST", body: { reason } });
      onDone();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Freeze ${username}?`}
      description="The user is signed out of every action until you unfreeze the account."
      icon={Snowflake}
      onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} onClick={submit}>Freeze account</Button></>}
    >
      <Field label="Reason" hint="Shown to the user on their locked screen.">
        {(p) => <input {...p} className="input" value={reason} onChange={(e) => setReason(e.target.value)} />}
      </Field>
    </Modal>
  );
}

export default function Admin() {
  const { user } = useAuth();
  const users = useApi("/api/admin/users");
  const system = useApi("/api/admin/system");
  const [freezing, setFreezing] = useState(null);
  const [broadcast, setBroadcast] = useState("");
  const [sending, setSending] = useState(false);
  const notify = useToast();

  const unfreeze = async (name) => {
    try {
      await api(`/api/admin/users/${encodeURIComponent(name)}/unfreeze`, { method: "POST" });
      notify(`${name} can sign in again.`);
      users.reload();
    } catch (e) {
      notify(e.message, "error");
    }
  };

  const sendBroadcast = async (e) => {
    e.preventDefault();
    setSending(true);
    try {
      await api("/api/admin/broadcast", { method: "POST", body: { message: broadcast } });
      setBroadcast("");
      notify("Broadcast published to all users.");
    } catch (err) {
      notify(err.message, "error");
    } finally {
      setSending(false);
    }
  };

  const s = system.data;
  const pending = users.data?.filter((u) => u.unfreeze_requested).length || 0;

  return (
    <>
      <PageHead title="Administration" description="Manage accounts, respond to unfreeze requests and publish alerts." />

      <div className="grid grid-kpi">
        <StatTile icon={Users} label="Users" value={s?.users} hint={pending ? `${pending} unfreeze request${pending > 1 ? "s" : ""}` : null} loading={system.loading} />
        <StatTile icon={MessageSquare} label="Messages" value={s?.messages} loading={system.loading} />
        <StatTile icon={ScrollText} label="Log entries" value={s?.log_entries?.toLocaleString()} loading={system.loading} />
        <StatTile icon={Database} label="Database" value={s ? fmtBytes(s.db_bytes) : null} hint={s ? `${fmtBytes(s.uploads_bytes)} of encrypted uploads` : null} loading={system.loading} />
        <StatTile icon={HardDrive} label="Disk used" value={s ? `${s.disk_used_pct}%` : null} hint={s ? `Python ${s.python}` : null} loading={system.loading} />
      </div>

      <div className="stack mt">
        <Card title="Accounts" subtitle="Risk events = warnings, alerts and critical entries caused by the user" flush>
          {users.loading ? <SkeletonRows /> : users.error ? <ErrorState error={users.error} onRetry={users.reload} /> : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>User</th><th>Role</th><th>Status</th><th className="num">Risk events</th><th>Last sign-in</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {users.data.map((u) => (
                    <tr key={u.username}>
                      <td>
                        <div className="row" style={{ gap: 10, flexWrap: "nowrap" }}>
                          <span className="avatar" aria-hidden="true">{u.username.slice(0, 2).toUpperCase()}</span>
                          <strong>{u.username}</strong>
                        </div>
                      </td>
                      <td><Badge tone={u.role === "admin" ? "info" : "neutral"}>{u.role === "admin" ? "Administrator" : "Client"}</Badge></td>
                      <td>
                        {u.status === "frozen" ? (
                          <span className="stack" style={{ gap: 2 }}>
                            <Badge tone="danger" icon={Snowflake}>Frozen</Badge>
                            {u.unfreeze_requested && <span className="small" style={{ color: "var(--warning-ink)" }}>Unfreeze requested</span>}
                          </span>
                        ) : <Badge tone="success">Active</Badge>}
                      </td>
                      <td className="num">{u.risk_events}</td>
                      <td className="nowrap small">{fmtDateTime(u.last_login)}</td>
                      <td className="num">
                        {u.username === user.username ? null : u.status === "frozen" ? (
                          <Button size="sm" icon={Sun} onClick={() => unfreeze(u.username)}>Unfreeze</Button>
                        ) : (
                          <Button size="sm" variant="danger" icon={Snowflake} onClick={() => setFreezing(u.username)}>Freeze</Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Broadcast alert" subtitle="Shown on every user's overview page">
          <form className="stack" onSubmit={sendBroadcast}>
            <Field label="Message">
              {(p) => <textarea {...p} className="textarea" rows={4} maxLength={280} value={broadcast} onChange={(e) => setBroadcast(e.target.value)} placeholder="e.g. Scheduled key rotation on Sunday at 02:00 UTC." />}
            </Field>
            <div className="row">
              <span className="small muted">{broadcast.length}/280</span>
              <div className="spacer" />
              <Button type="submit" variant="primary" icon={Megaphone} loading={sending} disabled={!broadcast.trim()}>Publish</Button>
            </div>
          </form>
        </Card>
      </div>

      {freezing && (
        <FreezeDialog
          username={freezing}
          onClose={() => setFreezing(null)}
          onDone={() => { notify(`${freezing} has been frozen.`); setFreezing(null); users.reload(); }}
        />
      )}
    </>
  );
}
