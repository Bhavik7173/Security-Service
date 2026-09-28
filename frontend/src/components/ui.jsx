import { useEffect, useId, useRef, useState } from "react";
import { AlertOctagon, AlertTriangle, CheckCircle2, Info, KeyRound, Loader2, RefreshCw, ShieldAlert } from "lucide-react";

export function Card({ title, subtitle, actions, children, flush, className = "" }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <div className="sub">{subtitle}</div>}
          </div>
          {actions && <div className="row" style={{ marginLeft: "auto" }}>{actions}</div>}
        </header>
      )}
      <div className={`card-body ${flush ? "flush" : ""}`}>{children}</div>
    </section>
  );
}

export function StatTile({ icon: Icon, label, value, hint, tone = "", loading }) {
  return (
    <div className="card stat">
      <div className={`stat-icon ${tone}`} aria-hidden="true"><Icon size={19} /></div>
      <div style={{ minWidth: 0 }}>
        <div className="stat-label">{label}</div>
        {loading ? <div className="skeleton" style={{ height: 30, width: 60, marginTop: 6 }} /> : <div className="stat-value">{value}</div>}
        {hint && <div className="stat-hint">{hint}</div>}
      </div>
    </div>
  );
}

// Severity always ships with an icon + label, never colour alone.
const SEVERITY = {
  INFO: { cls: "badge-info", icon: Info, label: "Info" },
  WARNING: { cls: "badge-warning", icon: AlertTriangle, label: "Warning" },
  ALERT: { cls: "badge-danger", icon: ShieldAlert, label: "Alert" },
  CRITICAL: { cls: "badge-danger", icon: AlertOctagon, label: "Critical" },
};

export function SeverityBadge({ severity }) {
  const s = SEVERITY[severity] || { cls: "badge-neutral", icon: Info, label: severity };
  const Icon = s.icon;
  return (
    <span className={`badge ${s.cls}`}>
      <Icon size={12} aria-hidden="true" />
      {s.label}
    </span>
  );
}

export function Badge({ tone = "neutral", icon: Icon, children }) {
  return (
    <span className={`badge badge-${tone}`}>
      {Icon && <Icon size={12} aria-hidden="true" />}
      {children}
    </span>
  );
}

export function Button({ loading, children, variant = "", size = "", icon: Icon, className = "", ...props }) {
  return (
    <button
      className={`btn ${variant && `btn-${variant}`} ${size && `btn-${size}`} ${className}`}
      disabled={loading || props.disabled}
      aria-busy={loading || undefined}
      {...props}
    >
      {loading ? <Loader2 size={16} className="spin" aria-hidden="true" /> : Icon && <Icon size={16} aria-hidden="true" />}
      {children}
    </button>
  );
}

export function Field({ label, hint, error, children, id }) {
  const autoId = useId();
  const fieldId = id || autoId;
  const child = typeof children === "function" ? children({ id: fieldId, "aria-invalid": !!error, "aria-describedby": error ? `${fieldId}-err` : hint ? `${fieldId}-hint` : undefined }) : children;
  return (
    <div className="field">
      {label && <label htmlFor={fieldId}>{label}</label>}
      {child}
      {error ? (
        <div className="error" id={`${fieldId}-err`} role="alert"><AlertTriangle size={14} aria-hidden="true" />{error}</div>
      ) : hint ? (
        <div className="hint" id={`${fieldId}-hint`}>{hint}</div>
      ) : null}
    </div>
  );
}

export function Alert({ tone = "info", title, children }) {
  const Icon = { info: Info, success: CheckCircle2, warning: AlertTriangle, danger: ShieldAlert }[tone];
  return (
    <div className={`alert alert-${tone}`} role={tone === "danger" ? "alert" : undefined}>
      <Icon size={18} aria-hidden="true" />
      <div>
        {title && <strong style={{ display: "block" }}>{title}</strong>}
        {children}
      </div>
    </div>
  );
}

export function EmptyState({ icon: Icon = Info, title, children }) {
  return (
    <div className="empty">
      <div className="empty-icon" aria-hidden="true"><Icon size={22} /></div>
      <strong style={{ color: "var(--text)" }}>{title}</strong>
      {children && <div className="small">{children}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="empty">
      <div className="empty-icon" aria-hidden="true" style={{ color: "var(--danger)" }}><AlertTriangle size={22} /></div>
      <strong style={{ color: "var(--text)" }}>Couldn't load this section</strong>
      <div className="small">{error?.message}</div>
      {onRetry && <Button size="sm" icon={RefreshCw} onClick={onRetry}>Try again</Button>}
    </div>
  );
}

export function SkeletonRows({ rows = 4 }) {
  return (
    <div style={{ padding: 20, display: "grid", gap: 12 }} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton" style={{ height: 18, width: `${90 - i * 12}%` }} />)}
    </div>
  );
}

export function Modal({ title, description, icon: Icon, onClose, children, footer }) {
  const ref = useRef(null);
  const titleId = useId();
  useEffect(() => {
    const prev = document.activeElement;
    const first = ref.current?.querySelector("input, button, select, textarea");
    first?.focus();
    const onKey = (e) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && ref.current) {
        const items = ref.current.querySelectorAll("input, button, select, textarea, a[href]");
        const [firstEl, lastEl] = [items[0], items[items.length - 1]];
        if (e.shiftKey && document.activeElement === firstEl) { e.preventDefault(); lastEl.focus(); }
        else if (!e.shiftKey && document.activeElement === lastEl) { e.preventDefault(); firstEl.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [onClose]);

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref}>
        <div className="modal-head">
          {Icon && <div className="stat-icon" aria-hidden="true"><Icon size={19} /></div>}
          <div>
            <h2 id={titleId}>{title}</h2>
            {description && <p className="muted small" style={{ marginTop: 4 }}>{description}</p>}
          </div>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

/** Ask for the 4-digit PIN, then run `onSubmit(pin)`; errors are shown inline. */
export function PinDialog({ title, description, confirmLabel = "Verify", onSubmit, onClose }) {
  const [pin, setPin] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    if (!/^\d{4}$/.test(pin)) return setError("Enter your 4-digit PIN.");
    setBusy(true);
    setError("");
    try {
      await onSubmit(pin);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  };

  return (
    <Modal title={title} description={description} icon={KeyRound} onClose={onClose}>
      <form onSubmit={submit} className="stack">
        <Field label="PIN" error={error} hint="Your PIN never leaves this request and is checked on the server.">
          {(p) => (
            <input
              {...p}
              className="input pin"
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={4}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, ""))}
            />
          )}
        </Field>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button type="button" variant="ghost" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" loading={busy}>{confirmLabel}</Button>
        </div>
      </form>
    </Modal>
  );
}

export function PageHead({ title, description, children }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children && <div className="row">{children}</div>}
    </div>
  );
}
