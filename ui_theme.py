"""
Shared visual theme for the Streamlit app.

Design system: "Minimalism & Swiss" enterprise style.
  - Navy primary (#0F172A), blue accent (#0369A1), slate neutrals
  - Plus Jakarta Sans for UI text, JetBrains Mono for hashes / keys / code
  - Material Symbols icons (via Streamlit's :material/name: syntax) instead of emoji
All colours are CSS custom properties so light and dark mode share one stylesheet.
"""

import html

import streamlit as st

LIGHT_TOKENS = """
    --color-primary: #0F172A;
    --color-accent: #0369A1;
    --color-accent-hover: #075985;
    --color-on-accent: #FFFFFF;
    --color-background: #F8FAFC;
    --color-foreground: #0F172A;
    --color-card: #FFFFFF;
    --color-muted: #E8ECF1;
    --color-muted-foreground: #475569;
    --color-border: #E2E8F0;
    --color-success: #15803D;
    --color-warning: #B45309;
    --color-destructive: #DC2626;
    --color-ring: #0369A1;
    --bubble-out: #E0F2FE;
    --bubble-in: #FFFFFF;
    --shadow-card: 0 1px 2px rgba(15, 23, 42, 0.04), 0 1px 3px rgba(15, 23, 42, 0.06);
"""

DARK_TOKENS = """
    --color-primary: #E2E8F0;
    --color-accent: #38BDF8;
    --color-accent-hover: #7DD3FC;
    --color-on-accent: #0F172A;
    --color-background: #0B1220;
    --color-foreground: #E2E8F0;
    --color-card: #111A2E;
    --color-muted: #1E293B;
    --color-muted-foreground: #94A3B8;
    --color-border: #1F2A40;
    --color-success: #4ADE80;
    --color-warning: #FBBF24;
    --color-destructive: #F87171;
    --color-ring: #38BDF8;
    --bubble-out: #0C3A5B;
    --bubble-in: #1E293B;
    --shadow-card: 0 1px 2px rgba(0, 0, 0, 0.3);
"""

# Sidebar stays navy in both modes so the app shell reads as one product.
BASE_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
    __TOKENS__
    --sidebar-bg: #0F172A;
    --sidebar-fg: #CBD5E1;
    --sidebar-fg-strong: #F8FAFC;
    --sidebar-muted: #1E293B;
    --sidebar-border: #1E293B;
    --radius-sm: 8px;
    --radius-md: 12px;
    --font-sans: 'Plus Jakarta Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
    --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
}

/* ── Base ─────────────────────────────────────────────── */
html, body, .stApp, .stMarkdown, .stApp button, .stApp input, .stApp textarea {
    font-family: var(--font-sans);
}
.stApp { background: var(--color-background); color: var(--color-foreground); }
.stApp p, .stApp li, .stApp label, .stApp span { color: inherit; }
code, pre, .stCode, kbd { font-family: var(--font-mono) !important; }
.block-container { padding-top: 2rem; padding-bottom: 4rem; max-width: 1280px; }

h1, h2, h3, h4 { font-family: var(--font-sans); color: var(--color-foreground) !important;
                 letter-spacing: -0.01em; }
h2 { font-weight: 700; font-size: 1.5rem; }
h3 { font-weight: 650; font-size: 1.15rem; }
.stApp [data-testid="stHeading"] h3 { margin-top: 0.5rem; }
hr { border-color: var(--color-border) !important; margin: 1.5rem 0 !important; }

/* Hide Streamlit developer chrome; keep the sidebar toggle. */
[data-testid="stAppDeployButton"], #MainMenu, footer { display: none !important; }
header[data-testid="stHeader"] { background: transparent; }

/* ── App header ───────────────────────────────────────── */
.app-header { display: flex; align-items: center; gap: 14px; padding: 4px 0 20px;
              border-bottom: 1px solid var(--color-border); margin-bottom: 24px; }
.app-header .logo { width: 44px; height: 44px; border-radius: 10px; flex-shrink: 0;
                    background: var(--color-accent); display: grid; place-items: center; }
.app-header .logo svg { width: 24px; height: 24px; stroke: #fff; }
.app-header .title { font-size: 1.35rem; font-weight: 750; line-height: 1.2;
                     color: var(--color-foreground); margin: 0; }
.app-header .subtitle { font-size: 0.9rem; color: var(--color-muted-foreground); margin: 2px 0 0; }
.app-header .user-chip { margin-left: auto; display: flex; align-items: center; gap: 10px;
                         background: var(--color-card); border: 1px solid var(--color-border);
                         border-radius: 999px; padding: 6px 14px 6px 6px; }
.user-chip .avatar { width: 30px; height: 30px; border-radius: 50%; background: var(--color-muted);
                     color: var(--color-foreground); display: grid; place-items: center;
                     font-weight: 700; font-size: 0.85rem; }
.user-chip .name { font-weight: 600; font-size: 0.9rem; color: var(--color-foreground); }
.user-chip .role { font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .06em;
                   color: var(--color-accent); }
@media (max-width: 640px) { .app-header .user-chip { display: none; } }

/* ── Metric cards ─────────────────────────────────────── */
[data-testid="stMetric"] {
    background: var(--color-card); border: 1px solid var(--color-border);
    border-radius: var(--radius-md); padding: 16px 18px; box-shadow: var(--shadow-card);
    transition: border-color .2s ease;
}
[data-testid="stMetric"]:hover { border-color: var(--color-accent); }
[data-testid="stMetricLabel"] p { font-size: 0.8rem !important; font-weight: 600 !important;
    color: var(--color-muted-foreground) !important; text-transform: uppercase; letter-spacing: .04em; }
[data-testid="stMetricValue"] { font-weight: 700; font-size: 1.9rem !important;
    color: var(--color-foreground) !important; font-variant-numeric: tabular-nums; }

/* ── Buttons ──────────────────────────────────────────── */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
    border-radius: var(--radius-sm); font-weight: 600; min-height: 42px;
    border: 1px solid var(--color-border); background: var(--color-card);
    color: var(--color-foreground); cursor: pointer;
    transition: background-color .15s ease, border-color .15s ease, color .15s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--color-accent); color: var(--color-accent);
}
.stButton > button[kind="primary"], .stFormSubmitButton > button {
    background: var(--color-accent); border-color: var(--color-accent); color: var(--color-on-accent);
}
.stButton > button[kind="primary"]:hover, .stFormSubmitButton > button:hover {
    background: var(--color-accent-hover); border-color: var(--color-accent-hover); color: var(--color-on-accent);
}
button:focus-visible, input:focus-visible, textarea:focus-visible, [role="radio"]:focus-visible {
    outline: 2px solid var(--color-ring) !important; outline-offset: 2px;
}

/* ── Inputs ───────────────────────────────────────────── */
.stApp [data-baseweb="input"], .stApp [data-baseweb="textarea"], .stApp [data-baseweb="select"] > div {
    border-radius: var(--radius-sm) !important; border-color: var(--color-border) !important;
    background: var(--color-card) !important;
}
.stApp [data-baseweb="input"] input, .stApp textarea { color: var(--color-foreground) !important; }
.stApp [data-baseweb="input"]:focus-within, .stApp [data-baseweb="textarea"]:focus-within {
    border-color: var(--color-ring) !important; box-shadow: 0 0 0 3px rgba(3, 105, 161, .15);
}
.stApp label p { font-weight: 600; font-size: 0.875rem; }

/* ── Alerts, expanders, tables, tabs ─────────────────── */
[data-testid="stAlert"] > div { border-radius: var(--radius-sm); border: 1px solid transparent; }
[data-testid="stExpander"] details { border-radius: var(--radius-md); border-color: var(--color-border);
                                     background: var(--color-card); }
[data-testid="stDataFrame"], [data-testid="stTable"] { border: 1px solid var(--color-border);
                                                      border-radius: var(--radius-md); overflow: hidden; }
[data-testid="stFileUploaderDropzone"] { border-radius: var(--radius-md); background: var(--color-card);
                                         border: 1px dashed var(--color-border); }
.stTabs [data-baseweb="tab"] { font-weight: 600; }
.stTabs [aria-selected="true"] { color: var(--color-accent) !important; }
[data-testid="stPlotlyChart"], [data-testid="stVegaLiteChart"] {
    background: var(--color-card); border: 1px solid var(--color-border);
    border-radius: var(--radius-md); padding: 8px;
}

/* ── Chat bubbles ─────────────────────────────────────── */
.chat-bubble { max-width: 72%; padding: 10px 14px; border-radius: 14px; margin: 6px 0;
               border: 1px solid var(--color-border); color: var(--color-foreground);
               line-height: 1.5; overflow-wrap: anywhere; }
.chat-bubble.out { margin-left: auto; background: var(--bubble-out); border-bottom-right-radius: 4px; }
.chat-bubble.in  { margin-right: auto; background: var(--bubble-in); border-bottom-left-radius: 4px; }
.chat-bubble .meta { display: block; margin-top: 4px; font-size: 0.75rem;
                     color: var(--color-muted-foreground); }
.chat-bubble .reactions { display: block; margin-top: 4px; font-size: 1rem; }

/* ── Sidebar (navy shell) ─────────────────────────────── */
[data-testid="stSidebar"] { background: var(--sidebar-bg); border-right: 1px solid var(--sidebar-border); }
[data-testid="stSidebar"] * { color: var(--sidebar-fg); }
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
    color: var(--sidebar-fg-strong) !important; font-size: 0.75rem !important; font-weight: 700 !important;
    text-transform: uppercase; letter-spacing: .1em; margin: 1rem 0 .25rem !important; padding: 0 !important;
}
[data-testid="stSidebar"] hr { border-color: var(--sidebar-border) !important; margin: 1rem 0 !important; }
[data-testid="stSidebar"] [data-baseweb="input"], [data-testid="stSidebar"] [data-baseweb="select"] > div {
    background: var(--sidebar-muted) !important; border-color: #334155 !important;
}
[data-testid="stSidebar"] input { color: var(--sidebar-fg-strong) !important; }
[data-testid="stSidebar"] .stButton > button {
    width: 100%; background: var(--color-accent); border-color: var(--color-accent); color: #fff;
}
[data-testid="stSidebar"] .stButton > button * { color: #fff; }
[data-testid="stSidebar"] .stButton > button:hover { background: #075985; border-color: #075985; }
.sidebar-brand { display: flex; align-items: center; gap: 10px; padding: 4px 0 12px; }
.sidebar-brand .logo { width: 34px; height: 34px; border-radius: 8px; background: #0369A1;
                       display: grid; place-items: center; }
.sidebar-brand .logo svg { width: 18px; height: 18px; stroke: #fff; }
.sidebar-brand .name { font-weight: 750; font-size: 1rem; color: #F8FAFC; line-height: 1.1; }
.sidebar-brand .tag { font-size: 0.72rem; color: #94A3B8; }

/* Sidebar radios render as a navigation list rather than radio buttons. */
.st-key-nav [role="radiogroup"] { gap: 2px; }
.st-key-nav [role="radiogroup"] label {
    width: 100%; padding: 9px 12px; border-radius: var(--radius-sm); margin: 0;
    cursor: pointer; transition: background-color .15s ease;
}
.st-key-nav label[data-testid="stRadioOption"] > div > div:first-child:not([data-testid="stMarkdownContainer"]) { display: none; }
.st-key-nav, .st-key-nav > div, .st-key-nav [role="radiogroup"] { width: 100%; }
.st-key-nav [role="radiogroup"] { align-items: stretch; }
.st-key-nav [role="radiogroup"] label { box-sizing: border-box; display: flex; }
.st-key-nav [role="radiogroup"] label:hover { background: var(--sidebar-muted); }
.st-key-nav [role="radiogroup"] label:has(input:checked) {
    background: #0369A1;
}
.st-key-nav [role="radiogroup"] label:has(input:checked) * { color: #FFFFFF !important; }
.st-key-nav [role="radiogroup"] label p { font-weight: 550; font-size: 0.92rem; }
[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {
    font-size: 0.75rem; color: #94A3B8 !important; text-transform: uppercase; letter-spacing: .08em;
}
[data-testid="stSidebar"] [data-testid="stAlert"] * { color: inherit; }

/* Login / Register segmented control */
.st-key-auth_mode [role="radiogroup"] { background: var(--sidebar-muted); border-radius: var(--radius-sm);
                                        padding: 4px; gap: 4px; flex-wrap: nowrap; }
.st-key-auth_mode [role="radiogroup"] label { flex: 1 1 0; justify-content: center; margin: 0;
    padding: 7px 12px; border-radius: 6px; cursor: pointer; }
.st-key-auth_mode label[data-testid="stRadioOption"] > div > div:first-child:not([data-testid="stMarkdownContainer"]) { display: none; }
.st-key-auth_mode, .st-key-auth_mode > div, .st-key-auth_mode [role="radiogroup"] { width: 100%; }
.st-key-auth_mode [role="radiogroup"] label:has(input:checked) { background: #0369A1; }
.st-key-auth_mode [role="radiogroup"] label:has(input:checked) * { color: #fff !important; }

/* Sign out is a secondary action */
[data-testid="stSidebar"] .st-key-logout button { background: transparent; border-color: #334155; }
[data-testid="stSidebar"] .st-key-logout button:hover { background: var(--sidebar-muted); border-color: #475569; }

@media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { transition: none !important; animation: none !important; }
}
"""

# Lucide "shield-check" icon.
SHIELD_SVG = (
    '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" '
    'stroke-linejoin="round" aria-hidden="true">'
    '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 '
    '1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>'
    '<path d="m9 12 2 2 4-4"/></svg>'
)


def apply_theme(dark: bool = False):
    """Inject the global stylesheet. Call once per run, after st.set_page_config."""
    css = BASE_CSS.replace("__TOKENS__", DARK_TOKENS if dark else LIGHT_TOKENS)
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def apply_dark_tokens():
    """Override colour tokens for dark mode (the rest of the stylesheet is shared)."""
    st.markdown(
        f"<style>:root {{ {DARK_TOKENS} }}"
        # Streamlit's alert palette is tuned for light backgrounds; lift text for 4.5:1 contrast.
        "[data-testid='stAlert'] > div { background: var(--color-muted) !important;"
        " border-color: var(--color-border) !important; }"
        "[data-testid='stAlert'] p, [data-testid='stAlert'] strong { color: var(--color-foreground) !important; }"
        "</style>",
        unsafe_allow_html=True,
    )


def app_header(user=None, role=None):
    """Branded header row with an optional signed-in user chip."""
    chip = ""
    if user:
        user = html.escape(user)
        initials = user[:2].upper()
        chip = (
            f'<div class="user-chip"><div class="avatar">{initials}</div>'
            f'<div><div class="name">{user}</div><div class="role">{html.escape(role or "")}</div></div></div>'
        )
    st.markdown(
        f'<div class="app-header"><div class="logo">{SHIELD_SVG}</div>'
        '<div><p class="title">Secure Chat System</p>'
        '<p class="subtitle">End-to-end encryption, tamper detection and breach monitoring</p></div>'
        f"{chip}</div>",
        unsafe_allow_html=True,
    )


def sidebar_brand():
    st.sidebar.markdown(
        f'<div class="sidebar-brand"><div class="logo">{SHIELD_SVG}</div>'
        '<div><div class="name">SecureChat</div><div class="tag">Breach Detection Console</div></div></div>',
        unsafe_allow_html=True,
    )
