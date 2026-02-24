"""
Meridian CCM — Streamlit Dashboard (Stage 2)
=============================================
Dark-themed, trust-envelope-centric design.

Pages:
  Overview    — KPI cards + all Trust Envelope cards
  By Product  — envelopes grouped by P1 / P2
  Deviations  — open failing controls with ticket links
  Evidence    — filterable evidence table with Merkle proof verification

Filters (contextual per page):
  Product, Control, Trust Level, Date range

Cache TTL = 30 s; use the REFRESH button to force-reload immediately.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime, timezone

import pandas as pd
import psycopg2
import psycopg2.extras
import streamlit as st
import yaml

# ── Environment ───────────────────────────────────────────────────────────────

POSTGRES_DSN  = os.getenv("POSTGRES_DSN",  "postgresql://meridian:meridian@localhost:5432/meridian")
CONFIG_PATH   = os.getenv("CONFIG_PATH",   "/config/controls.yaml")
PRODUCTS_PATH = os.getenv("PRODUCTS_PATH", "/config/products.yaml")

# ── Page setup (must be first Streamlit call) ─────────────────────────────────

st.set_page_config(
    page_title="Meridian CCM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Colour palette ────────────────────────────────────────────────────────────

C_BG      = "#0d1117"
C_SURFACE = "#161b22"
C_BORDER  = "#30363d"
C_TEXT    = "#e6edf3"
C_MUTED   = "#8b949e"
C_DIM     = "#7d8590"
C_TEAL    = "#00d4aa"
C_GREEN   = "#3fb950"
C_YELLOW  = "#d29922"
C_ORANGE  = "#f0883e"
C_RED     = "#f85149"

# ── CSS injection ─────────────────────────────────────────────────────────────

st.markdown(f"""
<style>
  html, body,
  [data-testid="stAppViewContainer"],
  [data-testid="stMain"] {{
    background: {C_BG};
    color: {C_TEXT};
  }}
  [data-testid="stSidebar"] {{
    background: {C_SURFACE};
    border-right: 1px solid {C_BORDER};
  }}
  #MainMenu, footer, [data-testid="stHeader"] {{
    visibility: hidden;
  }}
  .mono-label {{
    font-family: monospace;
    text-transform: uppercase;
    font-size: 12px;
    color: {C_MUTED};
    letter-spacing: 1.2px;
  }}
  .env-card {{
    background: {C_SURFACE};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 16px;
  }}
  .kpi-card {{
    background: {C_SURFACE};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
    padding: 16px 20px;
    text-align: center;
  }}
  .fw-badge {{
    display: inline-block;
    background: rgba(0,212,170,0.1);
    border: 1px solid rgba(0,212,170,0.3);
    border-radius: 4px;
    padding: 2px 7px;
    font-family: monospace;
    font-size: 13px;
    color: {C_TEAL};
    margin-right: 4px;
    margin-bottom: 3px;
  }}
  .trust-badge {{
    display: inline-block;
    border-radius: 4px;
    padding: 4px 12px;
    font-size: 13px;
    font-weight: 700;
    font-family: monospace;
    letter-spacing: .5px;
  }}
  .claim-badge {{
    display: inline-block;
    border-radius: 4px;
    padding: 3px 10px;
    font-size: 12px;
    font-weight: 700;
    font-family: monospace;
    letter-spacing: .5px;
  }}
  .prod-badge {{
    display: inline-block;
    border: 1px solid {C_TEAL};
    border-radius: 4px;
    padding: 2px 8px;
    font-family: monospace;
    font-size: 11px;
    color: {C_TEAL};
  }}
  .rec-block {{
    border-left: 3px solid {C_ORANGE};
    background: rgba(240,136,62,0.08);
    padding: 12px 16px;
    border-radius: 0 4px 4px 0;
    margin: 14px 0;
  }}
  .merkle-hash {{
    font-family: monospace;
    font-size: 13px;
    color: {C_MUTED};
    word-break: break-all;
  }}
  [data-testid="stExpander"] {{
    background: {C_SURFACE};
    border: 1px solid {C_BORDER};
  }}
  [data-testid="stExpander"] summary {{
    color: {C_TEXT};
  }}
</style>
""", unsafe_allow_html=True)

# ── Static lookup tables ──────────────────────────────────────────────────────

TRUST_COLORS = {
    "VERIFIED": C_TEAL,
    "HIGH":     C_GREEN,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_ORANGE,
    "CRITICAL": C_RED,
}

CLAIM_COLORS = {
    "SATISFIED":      C_TEAL,
    "PARTIAL":        C_ORANGE,
    "NOT_SATISFIED":  C_RED,
    "INDETERMINATE":  C_MUTED,
    "NOT_APPLICABLE": C_MUTED,
}

FRAMEWORK_DESCRIPTIONS = {
    "CC6.1": "Logical and physical access controls",
    "CC6.2": "Access provisioning and deprovisioning",
    "CC6.3": "Role-based access control reviews",
    "CC6.5": "Logical access removal upon termination",
    "A.9.2.1": "User registration and de-registration",
    "A.9.2.3": "Management of privileged access rights",
    "A.9.2.5": "Review of user access rights",
    "A.9.2.6": "Removal or adjustment of access rights",
    "A.9.4.4": "Use of privileged utility programs",
}

CONTROL_DOMAINS = {
    "LA.01": "new_access",
    "LA.02": "terminations",
    "LA.03": "user_access_review",
    "LA.04": "admin_access",
}

# ── Inlined Merkle functions (mirrored from services/agent/crypto/merkle.py) ──
# The dashboard is a separate container and cannot import from the agent package.

def _m_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _m_hash_leaf(item: dict) -> str:
    """SHA-256 of 0x00 prefix + canonical JSON of evidence item."""
    canonical = json.dumps(
        item, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    return _m_sha256(b"\x00" + canonical)


def _m_hash_pair(left: str, right: str) -> str:
    """SHA-256 of 0x01 prefix + left hex string + right hex string."""
    return _m_sha256(b"\x01" + left.encode() + right.encode())


def _m_build_tree(leaves: list[str]) -> list[list[str]]:
    """Build full Merkle tree; returns list of levels, leaves first."""
    if not leaves:
        return []
    levels: list[list[str]] = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        if len(current) % 2 != 0:
            current = current + [current[-1]]
        parents = [
            _m_hash_pair(current[i], current[i + 1])
            for i in range(0, len(current), 2)
        ]
        levels.append(parents)
    return levels


def merkle_get_proof(leaves: list[str], index: int) -> dict:
    levels = _m_build_tree(leaves)
    proof_hashes: list[dict] = []
    idx = index
    for level in levels[:-1]:
        padded = level + ([level[-1]] if len(level) % 2 != 0 else [])
        if idx % 2 == 0:
            sibling_idx = idx + 1
            position = "right"
        else:
            sibling_idx = idx - 1
            position = "left"
        proof_hashes.append({"hash": padded[sibling_idx], "position": position})
        idx //= 2
    return {
        "leaf_hash":    leaves[index],
        "index":        index,
        "proof_hashes": proof_hashes,
        "root_hash":    levels[-1][0],
    }


def merkle_verify_proof(
    leaf_hash: str,
    proof_hashes: list[dict],
    root_hash: str,
) -> bool:
    current = leaf_hash
    for step in proof_hashes:
        sibling = step["hash"]
        if step["position"] == "right":
            current = _m_hash_pair(current, sibling)
        else:
            current = _m_hash_pair(sibling, current)
    return current == root_hash


# ── HTML rendering helpers ────────────────────────────────────────────────────

def _hex_to_rgb(hex_color: str) -> str:
    """Convert #rrggbb to 'r,g,b' for use in rgba()."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"{r},{g},{b}"


def trust_badge(level: str) -> str:
    color = TRUST_COLORS.get(level, C_MUTED)
    rgb = _hex_to_rgb(color)
    return (
        f'<span class="trust-badge" style="'
        f'background:rgba({rgb},0.15);'
        f'border:1px solid rgba({rgb},0.4);'
        f'color:{color}">{level}</span>'
    )


def claim_badge(result: str) -> str:
    color = CLAIM_COLORS.get(result, C_MUTED)
    rgb = _hex_to_rgb(color)
    label = result.replace("_", " ")
    return (
        f'<span class="claim-badge" style="'
        f'background:rgba({rgb},0.15);'
        f'border:1px solid rgba({rgb},0.4);'
        f'color:{color}">{label}</span>'
    )


def prod_badge(pid: str) -> str:
    return f'<span class="prod-badge">{pid}</span>'


def fw_badges(mappings: dict) -> str:
    """Render all framework codes as .fw-badge spans."""
    parts = []
    for codes in mappings.values():
        for code in (codes or []):
            parts.append(f'<span class="fw-badge">{code}</span>')
    return "".join(parts)


def circular_gauge(confidence: float, color: str, size: int = 150) -> str:
    """Inline SVG circular confidence gauge."""
    stroke_w = 10
    r = size // 2 - stroke_w - 4
    cx = cy = size // 2
    circumference = 2 * math.pi * r
    pct = max(0, min(100, round(confidence * 100)))
    arc_len = (pct / 100) * circumference
    gap_len = circumference - arc_len
    font_size = 28
    label_size = 11
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" '
        f'style="display:inline-block;vertical-align:middle">'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
        f'stroke="{C_BORDER}" stroke-width="{stroke_w}"/>'
        f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
        f'stroke="{color}" stroke-width="{stroke_w}" stroke-linecap="round" '
        f'stroke-dasharray="{arc_len:.2f} {gap_len:.2f}" '
        f'transform="rotate(-90 {cx} {cy})"/>'
        f'<text x="{cx}" y="{cy - 6}" text-anchor="middle" dominant-baseline="middle" '
        f'font-size="{font_size}" font-family="monospace" '
        f'fill="{color}" font-weight="bold">{pct}%</text>'
        f'<text x="{cx}" y="{cy + font_size // 2 + 4}" text-anchor="middle" '
        f'font-size="{label_size}" font-family="monospace" '
        f'fill="{C_MUTED}" letter-spacing="1">CONFIDENCE</text>'
        f'</svg>'
    )


def confidence_bar(confidence: float, color: str) -> str:
    """Labelled horizontal confidence bar."""
    pct = max(0, min(100, round(confidence * 100)))
    return (
        f'<div style="margin:8px 0">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
        f'<span class="mono-label">CONFIDENCE</span>'
        f'<span style="font-family:monospace;font-size:13px;color:{color}">{pct}%</span>'
        f'</div>'
        f'<div style="background:{C_BORDER};border-radius:3px;height:6px">'
        f'<div style="background:{color};width:{pct}%;height:100%;border-radius:3px"></div>'
        f'</div></div>'
    )


def fmt_ts(ts) -> str:
    if ts is None:
        return "—"
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return ts
    try:
        return ts.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return str(ts)


# ── Data loading ──────────────────────────────────────────────────────────────

def _connect():
    return psycopg2.connect(POSTGRES_DSN)


@st.cache_data(ttl=30)
def load_config() -> tuple[dict, dict]:
    with open(CONFIG_PATH) as fh:
        controls = yaml.safe_load(fh)
    try:
        with open(PRODUCTS_PATH) as fh:
            products = yaml.safe_load(fh)
    except FileNotFoundError:
        products = {"products": []}
    return controls, products


@st.cache_data(ttl=30)
def load_envelopes() -> pd.DataFrame:
    try:
        conn = _connect()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT ON (control_id, product_id)
                    id, envelope_id, control_id, product_id, created_at,
                    trust_level, composite_confidence, merkle_root,
                    envelope_data, signature
                FROM trust_envelopes
                ORDER BY control_id, product_id, created_at DESC
            """)
            rows = cur.fetchall()
        conn.close()
    except Exception:
        return pd.DataFrame()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame([dict(r) for r in rows])
    df["created_at"] = pd.to_datetime(df["created_at"], utc=True, errors="coerce")

    def _parse_ed(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except Exception:
                return {}
        return v or {}

    df["envelope_data"] = df["envelope_data"].apply(_parse_ed)
    return df


@st.cache_data(ttl=30)
def load_evidence() -> pd.DataFrame:
    try:
        conn = _connect()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT id, control_id, check_name, collected_at, raw_data,
                       signature, merkle_leaf_hash, merkle_index
                FROM evidence
                ORDER BY merkle_index ASC NULLS LAST, collected_at ASC
            """)
            rows = cur.fetchall()
        conn.close()
    except Exception:
        return pd.DataFrame()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame([dict(r) for r in rows])
    df["collected_at"] = pd.to_datetime(df["collected_at"], utc=True, errors="coerce")
    return df


@st.cache_data(ttl=30)
def load_runs() -> pd.DataFrame:
    try:
        conn = _connect()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("""
                SELECT control_id, run_at, status, summary, ticket_number, ticket_sys_id
                FROM control_runs
                ORDER BY run_at DESC
                LIMIT 2000
            """)
            rows = cur.fetchall()
        conn.close()
    except Exception:
        return pd.DataFrame()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame([dict(r) for r in rows])
    df["run_at"] = pd.to_datetime(df["run_at"], utc=True, errors="coerce")
    return df


def compute_kpis(
    df_env: pd.DataFrame,
    df_ev: pd.DataFrame,
    df_runs: pd.DataFrame,
) -> dict:
    total_envelopes = len(df_env)
    total_evidence  = len(df_ev)

    all_claims: list[dict] = []
    if not df_env.empty:
        for ed in df_env["envelope_data"]:
            all_claims.extend(ed.get("claims", []))

    claims_evaluated = len(all_claims)
    claims_satisfied = sum(1 for c in all_claims if c.get("result") == "SATISFIED")

    deviations = 0
    if not df_env.empty:
        for _, row in df_env.iterrows():
            ed = row["envelope_data"]
            claims = ed.get("claims", [])
            if any(c.get("result") in {"NOT_SATISFIED", "PARTIAL"} for c in claims):
                deviations += 1

    open_tickets = 0
    if not df_runs.empty:
        latest_per_ctrl = (
            df_runs.sort_values("run_at")
                   .groupby("control_id", as_index=False)
                   .last()
        )
        open_tickets = int(latest_per_ctrl["ticket_number"].notna().sum())

    return {
        "total_envelopes":  total_envelopes,
        "total_evidence":   total_evidence,
        "claims_evaluated": claims_evaluated,
        "claims_satisfied": claims_satisfied,
        "deviations":       deviations,
        "open_tickets":     open_tickets,
    }


# ── Module-level data loading ─────────────────────────────────────────────────

controls_cfg, products_cfg = load_config()
ctrl_meta    = {c["id"]: c for c in controls_cfg["controls"]}
all_products = products_cfg.get("products", [])
all_prod_ids = [p["id"] for p in all_products]
prod_by_id   = {p["id"]: p for p in all_products}

df_env  = load_envelopes()
df_ev   = load_evidence()
df_runs = load_runs()
kpis    = compute_kpis(df_env, df_ev, df_runs)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown(
        f'<div style="font-family:monospace;font-size:16px;color:{C_TEAL};'
        f'font-weight:700;letter-spacing:2px;padding:12px 0 2px 0">MERIDIAN CCM</div>'
        f'<div class="mono-label" style="padding-bottom:12px">'
        f'CONTINUOUS CONTROL MONITORING</div>',
        unsafe_allow_html=True,
    )
    st.divider()

    page = st.radio(
        "PAGE",
        ["Overview", "By Product", "Deviations", "Evidence"],
        label_visibility="collapsed",
    )
    st.divider()

    st.markdown(
        f'<span class="mono-label">FILTERS</span>',
        unsafe_allow_html=True,
    )

    sel_products = st.multiselect(
        "Product",
        options=all_prod_ids,
        default=all_prod_ids,
        format_func=lambda pid: f"{pid} — {prod_by_id[pid]['name']}",
    )
    if not sel_products:
        sel_products = all_prod_ids

    avail_ctrls = sorted({
        c
        for p in all_products
        if p["id"] in sel_products
        for c in p.get("controls", [])
    })
    sel_controls = st.multiselect(
        "Control",
        options=avail_ctrls,
        default=avail_ctrls,
    )
    if not sel_controls:
        sel_controls = avail_ctrls

    if page != "Evidence":
        trust_opts = ["VERIFIED", "HIGH", "MEDIUM", "LOW", "CRITICAL"]
        sel_trust = st.multiselect(
            "Trust Level",
            options=trust_opts,
            default=trust_opts,
        )
        if not sel_trust:
            sel_trust = trust_opts
    else:
        sel_trust = ["VERIFIED", "HIGH", "MEDIUM", "LOW", "CRITICAL"]

    date_opts = {
        "Last 24 h":    1,
        "Last 7 days":  7,
        "Last 30 days": 30,
        "All time":     3650,
    }
    days_back = date_opts[
        st.selectbox("Date range", list(date_opts.keys()), index=2)
    ]

    st.divider()

    if st.button("REFRESH", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

    st.markdown(
        f'<div class="mono-label" style="margin-top:8px">'
        f'{datetime.now(timezone.utc).strftime("%H:%M:%S")} UTC</div>',
        unsafe_allow_html=True,
    )


# ── Apply filters ─────────────────────────────────────────────────────────────

cutoff_dt = pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=days_back)

if not df_env.empty:
    df_env_f = df_env[
        df_env["control_id"].isin(sel_controls) &
        df_env["product_id"].isin(sel_products) &
        df_env["trust_level"].isin(sel_trust) &
        (df_env["created_at"] >= cutoff_dt)
    ].copy()
else:
    df_env_f = pd.DataFrame()

if not df_ev.empty:
    df_ev_f = df_ev[df_ev["control_id"].isin(sel_controls)].copy()
else:
    df_ev_f = pd.DataFrame()


# ── Render helpers ────────────────────────────────────────────────────────────

def render_kpi_row(kpis: dict) -> None:
    cols = st.columns(6)
    items = [
        ("ENVELOPES",    kpis["total_envelopes"],  C_TEXT,
         "Total Trust Envelopes"),
        ("EVIDENCE",     kpis["total_evidence"],   C_TEXT,
         "Total Evidence Items"),
        ("CLAIMS",       kpis["claims_evaluated"], C_TEXT,
         "Claims Evaluated"),
        ("SATISFIED",    kpis["claims_satisfied"], C_TEAL,
         "Claims Satisfied"),
        ("DEVIATIONS",   kpis["deviations"],
         C_RED if kpis["deviations"] > 0 else C_TEXT,
         "Open Deviations"),
        ("OPEN TICKETS", kpis["open_tickets"],
         C_ORANGE if kpis["open_tickets"] > 0 else C_TEXT,
         "Open Tickets"),
    ]
    for col, (label, value, color, title) in zip(cols, items):
        col.markdown(
            f'<div class="kpi-card">'
            f'<div class="mono-label">{label}</div>'
            f'<div style="font-size:28px;font-weight:700;color:{color};'
            f'line-height:1.2;margin:6px 0">{value}</div>'
            f'<div style="font-size:11px;color:{C_DIM}">{title}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


def render_explainer() -> None:
    with st.expander("HOW TO READ THIS DASHBOARD", expanded=False):
        st.markdown(f"""
**1. TRUST ENVELOPE**

A Trust Envelope is the machine-generated equivalent of an audit report finding.
Instead of a human auditor writing up a control test, the Meridian agent continuously
collects evidence, evaluates claims, and packages everything into a
cryptographically-signed envelope that auditors can verify independently.

---

**2. CONFIDENCE %**

The confidence score reflects **actual population coverage** — not a sample.
A 100% confidence on LA.02 means every termination event in the collection window
was tested. A 67% confidence means roughly 1 in 3 terminations had a residual-access
issue that lowered the score. This is more informative than a binary pass/fail or a
sampled audit test.

---

**3. TRUST LEVELS**

| Level | Threshold | Meaning |
|-------|-----------|---------|
| <span class="trust-badge" style="background:rgba(0,212,170,0.15);border:1px solid rgba(0,212,170,0.4);color:{C_TEAL}">VERIFIED</span> | ≥ 95% | Effectively no deviations |
| <span class="trust-badge" style="background:rgba(63,185,80,0.15);border:1px solid rgba(63,185,80,0.4);color:{C_GREEN}">HIGH</span> | 75–94% | Minor issues, no systemic failure |
| <span class="trust-badge" style="background:rgba(210,153,34,0.15);border:1px solid rgba(210,153,34,0.4);color:{C_YELLOW}">MEDIUM</span> | 55–74% | Noticeable deviations, needs attention |
| <span class="trust-badge" style="background:rgba(240,136,62,0.15);border:1px solid rgba(240,136,62,0.4);color:{C_ORANGE}">LOW</span> | 30–54% | Significant control failures |
| <span class="trust-badge" style="background:rgba(248,81,73,0.15);border:1px solid rgba(248,81,73,0.4);color:{C_RED}">CRITICAL</span> | < 30% | Control has broken down |

---

**4. CLAIM RESULTS**

- **SATISFIED** — The claim assertion was fully met
- **PARTIAL** — Some but not all instances met the assertion
- **NOT SATISFIED** — The claim assertion was not met
- **INDETERMINATE** — Insufficient data to evaluate
- **NOT APPLICABLE** — Claim does not apply in this context

---

**5. FRAMEWORK BADGES**

Framework codes appear on each envelope to show which compliance requirements
the control addresses:
- **CC6.x** codes = SOC 2 Trust Services Criteria (Common Criteria)
- **A.9.x** codes = ISO 27001 Annex A controls

---

**6. CRYPTOGRAPHIC VERIFICATION**

Every evidence item is signed with an **Ed25519 private key** held only by the
Meridian agent. Each signed item is hashed and appended to an **append-only
Merkle tree** — the same technique used in certificate transparency logs and
blockchains. The Merkle root in each envelope means you can independently verify
that any single evidence item was part of the exact tree that produced the root
hash, without downloading all evidence.

---

**7. WHAT MAKES THIS DIFFERENT FROM A TRADITIONAL SOC 2 REPORT**

A SOC 2 Type II report is a point-in-time assessment covering a 6–12 month period.
Meridian runs every 60 seconds and produces a new Trust Envelope each cycle.
Deviations are detected and ticketed **within minutes**, not discovered months later
during an annual audit. The cryptographic chain makes every envelope independently
auditable long after the agent has moved on.
""", unsafe_allow_html=True)


def render_envelope_card(row: pd.Series, ctrl_meta: dict) -> None:
    ed         = row["envelope_data"] if isinstance(row["envelope_data"], dict) else {}
    ctrl_id    = row.get("control_id", "")
    prod_id    = row.get("product_id", "")
    meta       = ctrl_meta.get(ctrl_id, {})
    ctrl_name  = meta.get("name", ctrl_id)
    desc       = meta.get("description", "").strip()
    fw_maps    = meta.get("framework_mappings", {})
    trust_lvl  = row.get("trust_level", "INDETERMINATE")
    confidence = float(row.get("composite_confidence") or 0)
    env_id     = str(row.get("envelope_id", ""))[:16]
    ts         = fmt_ts(row.get("created_at"))
    merkle_rt  = row.get("merkle_root", "")
    claims     = ed.get("claims", [])
    ev_summary = ed.get("evidence_summary", {})

    t_color = TRUST_COLORS.get(trust_lvl, C_MUTED)
    gauge   = circular_gauge(confidence, t_color)
    badge_t = trust_badge(trust_lvl)
    badge_p = prod_badge(prod_id)
    fw_html = fw_badges(fw_maps)

    # Mini KPI counts
    n_ev = ev_summary.get(
        "total_items",
        len(df_ev[df_ev["control_id"] == ctrl_id]) if not df_ev.empty else 0,
    )
    n_claims    = len(claims)
    n_satisfied = sum(1 for c in claims if c.get("result") == "SATISFIED")
    n_partial   = sum(1 for c in claims if c.get("result") == "PARTIAL")
    n_failed    = sum(1 for c in claims if c.get("result") == "NOT_SATISFIED")

    # Framework mapping rows
    fw_rows_html = ""
    for framework, codes in fw_maps.items():
        for code in (codes or []):
            fdesc = FRAMEWORK_DESCRIPTIONS.get(code, "")
            fw_rows_html += (
                f'<div style="display:flex;align-items:center;gap:8px;margin:3px 0">'
                f'<span class="fw-badge">{code}</span>'
                f'<span style="font-size:14px;color:{C_MUTED}">{fdesc}</span>'
                f'</div>'
            )

    # Findings (claim opinions)
    opinions = [c.get("opinion", "") for c in claims if c.get("opinion")]
    if opinions:
        items_html = "".join(
            f"<li style='margin:6px 0;color:{C_TEXT};font-size:14px'>{op}</li>"
            for op in opinions
        )
        findings_html = f'<ul style="margin:4px 0 0 0;padding-left:20px">{items_html}</ul>'
    else:
        findings_html = (
            f'<span style="color:{C_MUTED};font-size:14px">No findings recorded.</span>'
        )

    # Recommendations
    recs = [r for c in claims for r in (c.get("recommendations") or []) if r]
    recs_html = ""
    if recs:
        recs_list = "".join(
            f"<li style='margin:5px 0;font-size:14px;color:{C_TEXT}'>{r}</li>"
            for r in recs[:5]
        )
        recs_html = (
            f'<div class="rec-block" style="margin-top:14px">'
            f'<div class="mono-label" style="margin-bottom:6px">RECOMMENDATIONS</div>'
            f'<ul style="margin:0;padding-left:18px">{recs_list}</ul>'
            f'</div>'
        )

    conf_bar = confidence_bar(confidence, t_color)

    merkle_html = (
        f'<div style="margin-top:20px;padding-top:14px;border-top:1px solid {C_BORDER}">'
        f'<span class="mono-label">MERKLE ROOT</span>'
        f'<div class="merkle-hash">{merkle_rt or "—"}</div>'
        f'</div>'
    )

    st.markdown(f"""
<div class="env-card" style="border-left:3px solid {t_color}">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px">
    <div>
      <span class="mono-label">TRUST ENVELOPE</span>&nbsp;&nbsp;{fw_html}
    </div>
    <div style="text-align:right;display:flex;flex-direction:column;align-items:flex-end;gap:4px">
      {gauge}
      {badge_t}
    </div>
  </div>

  <div style="font-size:21px;font-weight:700;color:{C_TEXT};margin-bottom:8px">
    {ctrl_id} — {ctrl_name}
  </div>

  <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px">
    {badge_p}
    <span style="font-family:monospace;font-size:12px;color:{C_DIM}">{env_id}…</span>
    <span style="font-size:12px;color:{C_DIM}">{ts}</span>
  </div>

  <div style="font-size:14px;color:{C_MUTED};margin-bottom:14px">{desc}</div>

  {fw_rows_html}

  <div style="display:flex;gap:20px;margin:18px 0;padding:14px 0;
    border-top:1px solid {C_BORDER};border-bottom:1px solid {C_BORDER}">
    <div style="text-align:center">
      <div class="mono-label">EVIDENCE</div>
      <div style="font-size:24px;font-weight:700;color:{C_TEXT};margin-top:4px">{n_ev}</div>
    </div>
    <div style="text-align:center">
      <div class="mono-label">CLAIMS</div>
      <div style="font-size:24px;font-weight:700;color:{C_TEXT};margin-top:4px">{n_claims}</div>
    </div>
    <div style="text-align:center">
      <div class="mono-label">SATISFIED</div>
      <div style="font-size:24px;font-weight:700;color:{C_TEAL};margin-top:4px">{n_satisfied}</div>
    </div>
    <div style="text-align:center">
      <div class="mono-label">PARTIAL</div>
      <div style="font-size:24px;font-weight:700;color:{C_ORANGE};margin-top:4px">{n_partial}</div>
    </div>
    <div style="text-align:center">
      <div class="mono-label">FAILED</div>
      <div style="font-size:24px;font-weight:700;color:{C_RED};margin-top:4px">{n_failed}</div>
    </div>
  </div>

  <div style="margin-bottom:12px">
    <div class="mono-label" style="margin-bottom:8px">FINDINGS</div>
    {findings_html}
  </div>

  {conf_bar}
  {recs_html}
  {merkle_html}
</div>
""", unsafe_allow_html=True)

    # Claims expander — sibling element, not nested inside HTML
    if claims:
        with st.expander(f"CLAIMS ({len(claims)})", expanded=False):
            for claim in claims:
                c_result  = claim.get("result", "INDETERMINATE")
                c_conf    = float(claim.get("confidence", 0))
                c_color   = CLAIM_COLORS.get(c_result, C_MUTED)
                c_badge   = claim_badge(c_result)
                c_domain  = claim.get("domain", "")
                c_assert  = claim.get("assertion", "")
                c_opinion = claim.get("opinion", "")
                c_caveats = claim.get("caveats") or []
                c_recs    = claim.get("recommendations") or []
                c_bar     = confidence_bar(c_conf, c_color)

                caveat_html = ""
                if c_caveats:
                    items = "".join(
                        f"<li style='color:{C_ORANGE};font-size:13px'>{cv}</li>"
                        for cv in c_caveats
                    )
                    caveat_html = (
                        f'<div style="margin-top:6px">'
                        f'<span class="mono-label">CAVEATS</span>'
                        f'<ul style="margin:4px 0;padding-left:18px">{items}</ul>'
                        f'</div>'
                    )

                rec_html = ""
                if c_recs:
                    items = "".join(
                        f"<li style='font-size:13px;color:{C_TEXT}'>{r}</li>"
                        for r in c_recs
                    )
                    rec_html = (
                        f'<div style="margin-top:6px">'
                        f'<span class="mono-label">RECOMMENDATIONS</span>'
                        f'<ul style="margin:4px 0;padding-left:18px">{items}</ul>'
                        f'</div>'
                    )

                st.markdown(f"""
<div style="border:1px solid {C_BORDER};border-radius:6px;padding:12px 16px;
  margin-bottom:10px;background:{C_BG}">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
    {c_badge}
    <div style="flex:1"></div>
    <div style="width:160px">{c_bar}</div>
  </div>
  <div style="font-family:monospace;font-size:11px;color:{C_DIM};margin-bottom:6px">
    {c_domain}
  </div>
  <div style="font-size:14px;font-weight:600;color:{C_TEXT};margin-bottom:6px">
    {c_assert}
  </div>
  <div style="font-size:14px;color:{C_MUTED}">{c_opinion}</div>
  {caveat_html}
  {rec_html}
</div>""", unsafe_allow_html=True)


def render_fallback(df_runs: pd.DataFrame, ctrl_meta: dict) -> None:
    st.warning(
        "No Trust Envelopes found. Showing control run status from `control_runs` table."
    )
    if df_runs.empty:
        st.info("No run data available yet. Start the agent to begin collecting evidence.")
        return
    latest = (
        df_runs.sort_values("run_at")
               .groupby("control_id", as_index=False)
               .last()
    )
    col_count = min(4, max(1, len(latest)))
    cols = st.columns(col_count)
    for idx, (_, row) in enumerate(latest.iterrows()):
        cid    = row["control_id"]
        meta   = ctrl_meta.get(cid, {})
        status = row.get("status", "unknown")
        color  = C_GREEN if status == "pass" else C_RED if status == "fail" else C_ORANGE
        cols[idx % col_count].markdown(
            f'<div class="env-card">'
            f'<div class="mono-label">{cid}</div>'
            f'<div style="font-size:14px;font-weight:600;margin:4px 0">{meta.get("name", cid)}</div>'
            f'<div style="font-family:monospace;font-size:14px;color:{color};font-weight:700">'
            f'{status.upper()}</div>'
            f'<div style="font-size:11px;color:{C_DIM};margin-top:4px">'
            f'{fmt_ts(row.get("run_at"))}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════

if page == "Overview":
    render_kpi_row(kpis)
    render_explainer()
    st.divider()

    if df_env_f.empty:
        render_fallback(df_runs, ctrl_meta)
        st.stop()

    rows_list = list(
        df_env_f.sort_values(["control_id", "product_id"]).iterrows()
    )
    for i in range(0, len(rows_list), 2):
        cols = st.columns(2)
        for j, col in enumerate(cols):
            if i + j < len(rows_list):
                _, row = rows_list[i + j]
                with col:
                    render_envelope_card(row, ctrl_meta)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: BY PRODUCT
# ══════════════════════════════════════════════════════════════════════════════

elif page == "By Product":
    render_kpi_row(kpis)
    st.divider()

    visible_products = [p for p in all_products if p["id"] in sel_products]
    if not visible_products:
        st.info("No products match the current filter.")
        st.stop()

    for product in visible_products:
        pid     = product["id"]
        p_name  = product["name"]
        p_owner = product.get("owner", "—")
        p_ctrls = product.get("controls", [])
        ctrl_list = ", ".join(p_ctrls)

        st.markdown(
            f'<div style="border-left:3px solid {C_TEAL};padding:10px 16px;'
            f'margin:16px 0 10px 0;background:{C_SURFACE};border-radius:0 6px 6px 0">'
            f'<div style="display:flex;gap:12px;align-items:center">'
            f'{prod_badge(pid)}'
            f'<span style="font-size:16px;font-weight:700;color:{C_TEXT}">{p_name}</span>'
            f'<span style="font-size:12px;color:{C_MUTED}">Owner: {p_owner}</span>'
            f'<span style="font-size:12px;color:{C_DIM};font-family:monospace">'
            f'{ctrl_list}</span>'
            f'</div></div>',
            unsafe_allow_html=True,
        )

        prod_envs = df_env_f[df_env_f["product_id"] == pid].sort_values("control_id")
        if prod_envs.empty:
            st.markdown(
                f'<div style="color:{C_MUTED};font-size:13px;padding:8px 0">'
                f'No envelopes for {pid} in the selected filters.</div>',
                unsafe_allow_html=True,
            )
            continue

        rows_list = list(prod_envs.iterrows())
        for i in range(0, len(rows_list), 2):
            cols = st.columns(2)
            for j, col in enumerate(cols):
                if i + j < len(rows_list):
                    _, row = rows_list[i + j]
                    with col:
                        render_envelope_card(row, ctrl_meta)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DEVIATIONS
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Deviations":
    render_kpi_row(kpis)
    st.divider()

    # Use all envelopes without date filter to show current state
    dev_env = (
        df_env[
            df_env["control_id"].isin(sel_controls) &
            df_env["product_id"].isin(sel_products)
        ]
        if not df_env.empty
        else pd.DataFrame()
    )

    deviations: list[pd.Series] = []
    if not dev_env.empty:
        for _, row in dev_env.iterrows():
            ed = row["envelope_data"]
            claims = ed.get("claims", [])
            if any(c.get("result") in {"NOT_SATISFIED", "PARTIAL"} for c in claims):
                deviations.append(row)

    if not deviations:
        st.markdown(
            f'<div style="background:{C_SURFACE};border:1px solid {C_BORDER};'
            f'border-radius:8px;padding:32px;text-align:center">'
            f'<div style="font-size:28px;margin-bottom:8px">✓</div>'
            f'<div style="color:{C_TEAL};font-family:monospace;font-weight:700;font-size:14px">'
            f'NO OPEN DEVIATIONS</div>'
            f'<div style="color:{C_MUTED};font-size:13px;margin-top:4px">'
            f'All controls within acceptable trust levels.</div>'
            f'</div>',
            unsafe_allow_html=True,
        )
        st.stop()

    # Build ticket and open_since maps from control_runs
    ticket_map:     dict[str, str] = {}
    open_since_map: dict[str, pd.Timestamp] = {}
    if not df_runs.empty:
        for ctrl_id, grp in df_runs.groupby("control_id"):
            failing = grp[grp["status"] == "fail"].sort_values("run_at")
            if not failing.empty:
                open_since_map[ctrl_id] = failing.iloc[0]["run_at"]
            latest_run = grp.sort_values("run_at").iloc[-1]
            if latest_run.get("ticket_number"):
                ticket_map[ctrl_id] = latest_run["ticket_number"]

    st.markdown(
        f'<div class="mono-label" style="margin-bottom:12px">'
        f'{len(deviations)} OPEN DEVIATION(S)</div>',
        unsafe_allow_html=True,
    )

    for row in deviations:
        ctrl_id   = row.get("control_id", "")
        prod_id   = row.get("product_id", "")
        meta      = ctrl_meta.get(ctrl_id, {})
        ctrl_name = meta.get("name", ctrl_id)
        trust_lvl = row.get("trust_level", "INDETERMINATE")
        t_color   = TRUST_COLORS.get(trust_lvl, C_MUTED)
        ed        = row["envelope_data"]
        claims    = ed.get("claims", [])

        # Days open
        open_since = open_since_map.get(ctrl_id)
        if open_since:
            delta    = pd.Timestamp.now(tz="UTC") - open_since
            days_open = delta.days
            open_str = f"{days_open}d" if days_open > 0 else "< 1d"
        else:
            open_str = "—"

        ticket = ticket_map.get(ctrl_id, "—")

        # Failing claim details
        failing_claims = [
            c for c in claims
            if c.get("result") in {"NOT_SATISFIED", "PARTIAL"}
        ]
        fail_opinions = [c.get("opinion", "") for c in failing_claims if c.get("opinion")]
        fail_items = "".join(
            f"<li style='margin:6px 0;font-size:14px;color:{C_TEXT}'>{op}</li>"
            for op in fail_opinions
        )

        recs = [r for c in failing_claims for r in (c.get("recommendations") or []) if r]
        recs_html = ""
        if recs:
            recs_list = "".join(
                f"<li style='font-size:14px;color:{C_TEXT}'>{r}</li>"
                for r in recs[:5]
            )
            recs_html = (
                f'<div class="rec-block" style="margin-top:14px">'
                f'<div class="mono-label" style="margin-bottom:6px">RECOMMENDED ACTIONS</div>'
                f'<ul style="margin:0;padding-left:18px">{recs_list}</ul>'
                f'</div>'
            )

        st.markdown(f"""
<div class="env-card" style="border-left:3px solid {t_color};margin-bottom:16px">
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px">
    <div>
      <div style="font-size:16px;font-weight:700;color:{C_TEXT}">{ctrl_id} — {ctrl_name}</div>
      <div style="display:flex;gap:8px;margin-top:6px">
        {prod_badge(prod_id)}&nbsp;{trust_badge(trust_lvl)}
      </div>
    </div>
    <div style="text-align:right">
      <div class="mono-label">OPEN FOR</div>
      <div style="font-size:26px;font-weight:700;color:{t_color};line-height:1">{open_str}</div>
    </div>
  </div>

  <div style="margin-bottom:10px">
    <div class="mono-label" style="margin-bottom:6px">WHAT FAILED</div>
    <ul style="margin:0;padding-left:18px">
      {fail_items or f'<li style="color:{C_MUTED}">See claims for details.</li>'}
    </ul>
  </div>

  <div>
    <span class="mono-label">TICKET</span>&nbsp;
    <span style="font-family:monospace;font-size:13px;color:{C_TEAL}">{ticket}</span>
  </div>

  {recs_html}
</div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: EVIDENCE
# ══════════════════════════════════════════════════════════════════════════════

elif page == "Evidence":
    render_kpi_row(kpis)
    st.divider()

    if df_ev_f.empty:
        st.info("No evidence records match the current filters.")
        st.stop()

    # Build global Merkle tree state from all evidence ordered by merkle_index
    valid_ev = (
        df_ev.dropna(subset=["merkle_leaf_hash"])
        if not df_ev.empty
        else pd.DataFrame()
    )
    all_leaves: list[str] = []
    leaf_to_index: dict[str, int] = {}
    if not valid_ev.empty:
        sorted_ev = valid_ev.sort_values("merkle_index")
        all_leaves = list(sorted_ev["merkle_leaf_hash"])
        leaf_to_index = {
            h: int(i)
            for i, h in zip(sorted_ev["merkle_index"], sorted_ev["merkle_leaf_hash"])
        }

    # Latest merkle_root per control from df_env
    root_by_control: dict[str, str] = {}
    if not df_env.empty:
        for ctrl_id, grp in df_env.groupby("control_id"):
            latest_env = grp.sort_values("created_at").iloc[-1]
            root_by_control[ctrl_id] = latest_env.get("merkle_root", "") or ""

    st.markdown(
        f'<div style="color:{C_MUTED};font-size:13px;margin-bottom:16px">'
        f'Showing <strong style="color:{C_TEXT}">{len(df_ev_f)}</strong> evidence record(s). '
        f'Displayed latest first. Expand a row to verify its Merkle inclusion proof.</div>',
        unsafe_allow_html=True,
    )

    # Display latest first
    display_ev = df_ev_f.sort_values("collected_at", ascending=False)

    for _, ev_row in display_ev.iterrows():
        ctrl_id      = ev_row.get("control_id", "")
        check_name   = ev_row.get("check_name", "")
        collected_at = fmt_ts(ev_row.get("collected_at"))
        stored_leaf  = ev_row.get("merkle_leaf_hash") or ""
        merkle_idx   = ev_row.get("merkle_index")
        sig_full     = ev_row.get("signature") or ""
        raw_data     = ev_row.get("raw_data") or {}

        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception:
                raw_data = {}

        # Hash verification
        expected_leaf = _m_hash_leaf(raw_data) if raw_data else ""
        hash_ok = bool(stored_leaf and expected_leaf == stored_leaf)

        # Merkle proof verification
        merkle_status = "N/A"
        if stored_leaf and stored_leaf in leaf_to_index and all_leaves:
            idx = leaf_to_index[stored_leaf]
            expected_root = root_by_control.get(ctrl_id, "")
            if expected_root and 0 <= idx < len(all_leaves):
                try:
                    proof = merkle_get_proof(all_leaves, idx)
                    ok = merkle_verify_proof(
                        proof["leaf_hash"],
                        proof["proof_hashes"],
                        expected_root,
                    )
                    merkle_status = "VALID" if ok else "INVALID"
                except Exception:
                    merkle_status = "ERROR"

        hash_color   = C_TEAL if hash_ok else (C_MUTED if not stored_leaf else C_RED)
        merkle_color = (
            C_TEAL   if merkle_status == "VALID"
            else C_MUTED if merkle_status == "N/A"
            else C_RED
        )
        hash_label   = "OK" if hash_ok else ("—" if not stored_leaf else "FAIL")

        header = f"{ctrl_id} | {check_name} | {collected_at}"

        with st.expander(header, expanded=False):
            col1, col2 = st.columns([2, 1])

            with col1:
                st.markdown(
                    f'<div class="mono-label" style="margin-bottom:8px">RAW EVIDENCE</div>',
                    unsafe_allow_html=True,
                )
                st.json(raw_data, expanded=True)

            with col2:
                sig_disp  = (
                    f"{sig_full[:20]}…{sig_full[-8:]}"
                    if len(sig_full) > 32
                    else sig_full
                )
                idx_disp  = int(merkle_idx) if merkle_idx is not None else "—"
                leaf_disp = f"{stored_leaf[:20]}…" if stored_leaf else "—"

                st.markdown(f"""
<div>
  <div class="mono-label" style="margin-bottom:8px">METADATA</div>
  <div style="font-size:12px;margin-bottom:4px">
    <span style="color:{C_MUTED}">Control:</span>
    <span style="font-family:monospace;color:{C_TEXT}">&nbsp;{ctrl_id}</span>
  </div>
  <div style="font-size:12px;margin-bottom:4px">
    <span style="color:{C_MUTED}">Merkle index:</span>
    <span style="font-family:monospace;color:{C_TEXT}">&nbsp;{idx_disp}</span>
  </div>
  <div style="font-size:12px;margin-bottom:4px">
    <span style="color:{C_MUTED}">Leaf hash:</span>
    <span class="merkle-hash">&nbsp;{leaf_disp}</span>
  </div>
  <div style="font-size:12px;margin-bottom:16px">
    <span style="color:{C_MUTED}">Signature:</span>
    <span class="merkle-hash">&nbsp;{sig_disp}</span>
  </div>
  <div class="mono-label" style="margin-bottom:8px">VERIFICATION</div>
  <div style="font-size:12px;margin-bottom:4px">
    <span style="color:{C_MUTED}">Hash:</span>
    <span style="font-family:monospace;color:{hash_color};font-weight:700">
      &nbsp;{hash_label}
    </span>
  </div>
  <div style="font-size:12px">
    <span style="color:{C_MUTED}">Merkle:</span>
    <span style="font-family:monospace;color:{merkle_color};font-weight:700">
      &nbsp;{merkle_status}
    </span>
  </div>
</div>""", unsafe_allow_html=True)
