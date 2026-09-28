import { useRef, useState } from "react";
import { Download, FileCheck2, FileLock2, FileWarning, Inbox, Send, UploadCloud } from "lucide-react";
import { api, downloadResponse } from "../lib/api";
import { fmtBytes, fmtDateTime, useApi } from "../lib/useApi";
import { useToast } from "../lib/toast";
import { Badge, Button, Card, EmptyState, ErrorState, Field, PageHead, PinDialog, SkeletonRows } from "../components/ui";

function IntegrityBadge({ status }) {
  return status === "safe"
    ? <Badge tone="success" icon={FileCheck2}>Verified</Badge>
    : <Badge tone="danger" icon={FileWarning}>Tampered</Badge>;
}

function SendFile({ onSent }) {
  const users = useApi("/api/users");
  const [receiver, setReceiver] = useState("");
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const input = useRef(null);
  const notify = useToast();

  const send = async (pin) => {
    const form = new FormData();
    form.append("receiver", receiver || users.data[0]);
    form.append("pin", pin);
    form.append("file", file);
    await api("/api/files", { method: "POST", form });
    setConfirm(false);
    setFile(null);
    notify(`${file.name} encrypted and sent.`);
    onSent();
  };

  return (
    <Card title="Send an encrypted file" subtitle="Encrypted with the receiver's PIN; a SHA-256 baseline is recorded">
      <div className="stack">
        <Field label="Receiver">
          {(p) => (
            <select {...p} className="select" value={receiver} onChange={(e) => setReceiver(e.target.value)} disabled={!users.data?.length}>
              {(users.data || []).map((u) => <option key={u}>{u}</option>)}
            </select>
          )}
        </Field>
        <div
          className={`dropzone ${drag ? "drag" : ""}`}
          role="button"
          tabIndex={0}
          onClick={() => input.current.click()}
          onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current.click()}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); setFile(e.dataTransfer.files[0]); }}
        >
          <UploadCloud size={26} aria-hidden="true" />
          {file ? <><strong>{file.name}</strong><span className="small">{fmtBytes(file.size)} · click to change</span></> : <><strong>Drop a file or click to browse</strong><span className="small">Up to 25 MB</span></>}
          <input ref={input} type="file" hidden onChange={(e) => setFile(e.target.files[0])} />
        </div>
        <Button variant="primary" icon={Send} disabled={!file || !users.data?.length} onClick={() => setConfirm(true)}>Encrypt &amp; send</Button>
      </div>
      {confirm && (
        <PinDialog title="Confirm with your PIN" description={`Sending ${file.name} to ${receiver || users.data[0]}.`} confirmLabel="Send file" onSubmit={send} onClose={() => setConfirm(false)} />
      )}
    </Card>
  );
}

export default function Files() {
  const { data, error, loading, reload } = useApi("/api/files");
  const [opening, setOpening] = useState(null);
  const notify = useToast();

  const decrypt = async (pin) => {
    try {
      const res = await api(`/api/files/${opening.id}/decrypt`, { method: "POST", body: { pin }, raw: true });
      const saved = await downloadResponse(res, opening.name);
      notify(saved ? "Integrity verified. Download started." : "Integrity verified. Downloads are turned off in this preview.");
      setOpening(null);
    } catch (err) {
      if (err.status === 409) {
        setOpening(null);
        notify(err.message, "error");
      } else throw err;
    } finally {
      reload();
    }
  };

  return (
    <>
      <PageHead title="File integrity" description="Files are encrypted at rest and re-verified against their original SHA-256 hash on every download." />
      <div className="grid grid-main">
        <Card title="Received files" subtitle="Enter your PIN to decrypt, verify and download" flush>
          {loading ? <SkeletonRows /> : error ? <ErrorState error={error} onRetry={reload} /> : !data.received.length ? (
            <EmptyState icon={Inbox} title="No files received">Files sent to you will appear here.</EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>File</th><th>From</th><th>Integrity</th><th>Last checked</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {data.received.map((f) => (
                    <tr key={f.id}>
                      <td><strong>{f.name}</strong><div className="hash" title={f.original_hash}>{f.original_hash.slice(0, 16)}…</div></td>
                      <td>{f.counterpart}</td>
                      <td><IntegrityBadge status={f.status} /></td>
                      <td className="nowrap small">{fmtDateTime(f.last_checked_at)}</td>
                      <td className="num"><Button size="sm" icon={Download} onClick={() => setOpening(f)}>Decrypt</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <SendFile onSent={reload} />
      </div>

      <Card title="Sent files" flush className="mt">
        {loading ? <SkeletonRows /> : error ? null : !data.sent.length ? (
          <EmptyState icon={FileLock2} title="No files sent yet" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>File</th><th>To</th><th>Integrity</th><th>Sent</th><th>Original SHA-256</th></tr></thead>
              <tbody>
                {data.sent.map((f) => (
                  <tr key={f.id}>
                    <td><strong>{f.name}</strong></td>
                    <td>{f.counterpart}</td>
                    <td><IntegrityBadge status={f.status} /></td>
                    <td className="nowrap small">{fmtDateTime(f.uploaded_at)}</td>
                    <td className="hash" title={f.original_hash}>{f.original_hash.slice(0, 24)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {opening && (
        <PinDialog
          title="Decrypt and download"
          description={`${opening.name} from ${opening.counterpart}. Its hash is compared with the original before download.`}
          confirmLabel="Decrypt & download"
          onSubmit={decrypt}
          onClose={() => setOpening(null)}
        />
      )}
    </>
  );
}
