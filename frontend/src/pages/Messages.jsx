import { useEffect, useRef, useState } from "react";
import { Check, CheckCheck, Lock, LockOpen, MessagesSquare, SendHorizontal, ShieldAlert, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { fmtDateTime, useApi } from "../lib/useApi";
import { useToast } from "../lib/toast";
import { Alert, Button, Card, EmptyState, ErrorState, Modal, PageHead, PinDialog, SkeletonRows } from "../components/ui";

const VERDICTS = {
  verified: { tone: "success", title: "Integrity verified", icon: ShieldCheck },
  mismatch: { tone: "danger", title: "Threat detected: hash mismatch", icon: ShieldAlert },
  tampered: { tone: "danger", title: "Breach detected: ciphertext altered", icon: ShieldAlert },
  failed: { tone: "warning", title: "Decryption failed", icon: ShieldAlert },
};

function Receipt({ m }) {
  if (!m.outgoing) return null;
  if (m.status === "read") return <span className="row" style={{ gap: 3 }}><CheckCheck size={13} aria-hidden="true" />Read</span>;
  if (m.status === "delivered") return <span className="row" style={{ gap: 3 }}><Check size={13} aria-hidden="true" />Delivered</span>;
  return <span>Sent</span>;
}

function Thread({ other }) {
  const { data, error, loading, reload } = useApi(`/api/messages/conversation/${encodeURIComponent(other)}`);
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [decrypting, setDecrypting] = useState(null);
  const [result, setResult] = useState(null);
  const notify = useToast();
  const end = useRef(null);

  useEffect(() => end.current?.scrollIntoView({ block: "end" }), [data]);

  const send = async (e) => {
    e.preventDefault();
    if (!text.trim()) return;
    setSending(true);
    try {
      await api("/api/messages", { method: "POST", body: { receiver: other, message: text } });
      setText("");
      await reload();
    } catch (err) {
      notify(err.message, "error");
    } finally {
      setSending(false);
    }
  };

  const decrypt = async (pin) => {
    const res = await api(`/api/messages/${decrypting.id}/decrypt`, { method: "POST", body: { pin } });
    setDecrypting(null);
    setResult(res);
    reload();
  };

  return (
    <div className="thread">
      <div className="thread-head">
        <span className="avatar" aria-hidden="true">{other.slice(0, 2).toUpperCase()}</span>
        <div>
          <strong>{other}</strong>
          <div className="small muted row" style={{ gap: 4 }}><Lock size={12} aria-hidden="true" />Double-layer AES encryption</div>
        </div>
      </div>

      <div className="messages" aria-live="polite">
        {loading && !data ? <SkeletonRows /> : error ? <ErrorState error={error} onRetry={reload} /> : data.length === 0 ? (
          <EmptyState icon={MessagesSquare} title="No messages yet">Messages you send are encrypted with {other}'s personal key.</EmptyState>
        ) : (
          data.map((m) => (
            <div key={m.id} className={`bubble ${m.outgoing ? "out" : "in"}`}>
              {m.text ? (
                <div>{m.text}</div>
              ) : (
                <div className="cipher"><Lock size={12} aria-hidden="true" />{m.ciphertext_preview}…</div>
              )}
              <div className="meta">
                {fmtDateTime(m.timestamp)}
                <Receipt m={m} />
              </div>
              {!m.outgoing && !m.text && (
                <Button size="sm" variant="primary" icon={LockOpen} className="mt" style={{ marginTop: 8 }} onClick={() => setDecrypting(m)}>
                  Verify &amp; decrypt
                </Button>
              )}
            </div>
          ))
        )}
        <div ref={end} />
      </div>

      <form className="composer" onSubmit={send}>
        <label htmlFor="composer" className="sr-only">Message to {other}</label>
        <textarea
          id="composer"
          className="textarea"
          rows={1}
          placeholder={`Write an encrypted message to ${other}`}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) send(e); }}
        />
        <Button type="submit" variant="primary" icon={SendHorizontal} loading={sending} disabled={!text.trim()}>Send</Button>
      </form>

      {decrypting && (
        <PinDialog
          title="Verify and decrypt"
          description={`Message from ${decrypting.sender}. The ciphertext hash is checked before decryption, and the plaintext hash after.`}
          confirmLabel="Decrypt"
          onSubmit={decrypt}
          onClose={() => setDecrypting(null)}
        />
      )}
      {result && <VerdictModal result={result} onClose={() => setResult(null)} />}
    </div>
  );
}

function VerdictModal({ result, onClose }) {
  const v = VERDICTS[result.verdict];
  return (
    <Modal title={v.title} icon={v.icon} onClose={onClose} footer={<Button variant="primary" onClick={onClose}>Done</Button>}>
      <div className="stack">
        <Alert tone={v.tone}>{result.verdict === "verified" ? "Sender and receiver hashes match. The message was not modified in transit." : result.detail}</Alert>
        {result.message && <div className="card" style={{ padding: 14, boxShadow: "none" }}>{result.message}</div>}
        {result.sender_hash && (
          <div className="stack" style={{ gap: 8 }}>
            <div><div className="small muted">Sender SHA-256</div><div className="hash" style={{ overflowWrap: "anywhere" }}>{result.sender_hash}</div></div>
            <div><div className="small muted">Receiver SHA-256</div><div className="hash" style={{ overflowWrap: "anywhere" }}>{result.receiver_hash}</div></div>
          </div>
        )}
      </div>
    </Modal>
  );
}

export default function Messages() {
  const users = useApi("/api/users");
  const [selected, setSelected] = useState(null);

  // Opening the inbox marks incoming messages as delivered.
  useEffect(() => { api("/api/messages/inbox").catch(() => {}); }, []);
  useEffect(() => {
    if (!selected && users.data?.length) setSelected(users.data[0]);
  }, [users.data, selected]);

  return (
    <>
      <PageHead title="Secure messages" description="End-to-end encrypted conversations with integrity verification on every message." />
      <Card flush>
        {users.loading ? <SkeletonRows /> : users.error ? <ErrorState error={users.error} onRetry={users.reload} /> : !users.data.length ? (
          <EmptyState icon={MessagesSquare} title="No other users yet">Invite a colleague to register to start a conversation.</EmptyState>
        ) : (
          <div className="chat">
            <nav className="contacts" aria-label="Conversations">
              {users.data.map((u) => (
                <button key={u} className="contact" aria-current={u === selected} onClick={() => setSelected(u)}>
                  <span className="avatar" aria-hidden="true">{u.slice(0, 2).toUpperCase()}</span>
                  <span><strong>{u}</strong><br /><span className="small muted">Encrypted channel</span></span>
                </button>
              ))}
            </nav>
            {selected && <Thread key={selected} other={selected} />}
          </div>
        )}
      </Card>
    </>
  );
}
