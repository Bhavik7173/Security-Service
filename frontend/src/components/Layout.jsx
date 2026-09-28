import { Suspense, useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import {
  Activity, FileLock2, LayoutDashboard, LogOut, Menu, MessagesSquare, Moon, Network,
  ScrollText, ShieldCheck, Sun, UserCog, UserRound,
} from "lucide-react";
import { useAuth } from "../lib/auth";

export const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, section: "Workspace" },
  { to: "/messages", label: "Secure Messages", icon: MessagesSquare, section: "Workspace" },
  { to: "/files", label: "File Integrity", icon: FileLock2, section: "Workspace" },
  { to: "/security", label: "Security Center", icon: ShieldCheck, section: "Monitoring" },
  { to: "/logs", label: "Audit Logs", icon: ScrollText, section: "Monitoring" },
  { to: "/network", label: "Network Analysis", icon: Network, section: "Monitoring", admin: true },
  { to: "/admin", label: "Administration", icon: UserCog, section: "Monitoring", admin: true },
  { to: "/profile", label: "Profile", icon: UserRound, section: "Account" },
];

function useTheme() {
  const [theme, setTheme] = useState(() => {
    const saved = document.documentElement.dataset.theme;
    if (saved) return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("theme", theme); } catch { /* per-viewer convenience only */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))];
}

export default function Layout({ fallback = null }) {
  const { user, isAdmin, logout } = useAuth();
  const [theme, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  const items = NAV.filter((n) => !n.admin || isAdmin);
  const current = NAV.find((n) => (n.to === "/" ? location.pathname === "/" : location.pathname.startsWith(n.to)));

  useEffect(() => setOpen(false), [location.pathname]);
  useEffect(() => {
    document.title = `${current?.label ?? "Console"} · SecureChat`;
  }, [current]);

  let lastSection = null;
  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "open" : ""}`} aria-label="Main navigation">
        <NavLink to="/" className="brand">
          <span className="brand-logo" aria-hidden="true"><ShieldCheck size={18} color="#fff" /></span>
          <span>
            <span className="brand-name">SecureChat</span>
            <br />
            <span className="brand-tag">Breach Detection Console</span>
          </span>
        </NavLink>
        <nav>
          {items.map((item) => {
            const header = item.section !== lastSection ? <div className="nav-section">{item.section}</div> : null;
            lastSection = item.section;
            const Icon = item.icon;
            return (
              <div key={item.to}>
                {header}
                <NavLink to={item.to} end={item.to === "/"} className={({ isActive }) => `nav-link ${isActive ? "active" : ""}`}>
                  <Icon size={18} aria-hidden="true" />
                  {item.label}
                </NavLink>
              </div>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          <div className="row" style={{ gap: 6 }}><Activity size={14} aria-hidden="true" /> {import.meta.env.VITE_DEMO === "1" ? "Demo · simulated data" : "API connected"}</div>
        </div>
      </aside>
      <div className={`scrim ${open ? "open" : ""}`} onClick={() => setOpen(false)} aria-hidden="true" />

      <div className="main">
        <header className="topbar">
          <button className="btn btn-ghost btn-icon menu-btn" onClick={() => setOpen(true)} aria-label="Open navigation">
            <Menu size={20} />
          </button>
          <div className="topbar-title">
            <span className="crumb">{current?.section ?? "Workspace"}</span>
            <strong>{current?.label ?? "Console"}</strong>
          </div>
          <div className="topbar-actions">
            <button className="btn btn-ghost btn-icon" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}>
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <div className="user-chip">
              <span className="avatar" aria-hidden="true">{user.username.slice(0, 2).toUpperCase()}</span>
              <span className="who">
                <div className="name">{user.username}</div>
                <div className="role">{isAdmin ? "Administrator" : "Client"}</div>
              </span>
            </div>
            <button className="btn btn-ghost btn-icon" onClick={logout} aria-label="Sign out" title="Sign out">
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main className="content" id="main">
          <Suspense fallback={fallback}>
            <Outlet />
          </Suspense>
        </main>
      </div>
    </div>
  );
}
