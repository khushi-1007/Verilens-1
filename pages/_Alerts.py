"""
Alerts Page
Alert Management Center with Audit Intelligence Integration
Enterprise upgrade: auto-escalation, visual badges, smart filters, summary metrics.
Fixes: removed duplicate Auditor Notes / Escalation sections. Clean grouped layout.
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import database
import sys
from pathlib import Path

# ========== AUDIT ENGINE IMPORT ==========
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from utils.audit_engine import (
        generate_audit_flags,
        summarize_audit_findings,
        filter_by_audit_severity,
        get_flagged_transactions,
        get_audit_rules_documentation,
    )
    AUDIT_ENGINE_AVAILABLE = True
except ImportError:
    AUDIT_ENGINE_AVAILABLE = False
    print("Warning: Audit engine not available")
# ========== END AUDIT ENGINE IMPORT ==========

# ========== AUDIT CASE MANAGER IMPORT ==========
try:
    from utils.AuditCaseManager import (
        update_case_status,
        assign_case,
        add_case_comment,
        get_case_summary,
    )
    AUDIT_CASE_MANAGER_AVAILABLE = True
except ImportError:
    AUDIT_CASE_MANAGER_AVAILABLE = False
# ========== END AUDIT CASE MANAGER IMPORT ==========


# ===========================================================================
# UTILITY HELPERS
# ===========================================================================

def normalize_flags(flags):
    """Ensure audit_flags is always a list. Handles list, string, None safely."""
    if isinstance(flags, list):
        return flags
    if isinstance(flags, str):
        return [f.strip() for f in flags.split(";") if f.strip()]
    return []


def safe_str(value, default="N/A"):
    """Return string or default for missing/NaN values."""
    if value is None:
        return default
    try:
        if isinstance(value, float) and np.isnan(value):
            return default
    except Exception:
        pass
    return str(value)


# ===========================================================================
# SLA HELPER
# ===========================================================================
DEFAULT_SLA_DAYS = 5


def compute_sla_remaining(alert, record=None):
    """
    Returns (remaining_days: int | None, is_overdue: bool).
    Prefers audit_case_created / case_created_date on record,
    falls back to alert timestamp.
    """
    created_str = None
    if record is not None:
        created_str = record.get("audit_case_created") or record.get("case_created_date")
    if not created_str:
        created_str = alert.get("timestamp")
    if not created_str:
        return None, False
    try:
        created_dt = pd.to_datetime(created_str)
        elapsed    = (datetime.now() - created_dt).days
        remaining  = DEFAULT_SLA_DAYS - elapsed
        return remaining, remaining < 0
    except Exception:
        return None, False


# ===========================================================================
# RISK BREAKDOWN RENDERER
# ===========================================================================

def render_risk_breakdown(record):
    """Display Financial / Behavioral / Statistical risk bars."""
    fin_risk  = record.get("financial_risk")
    beh_risk  = record.get("behavioral_risk")
    stat_risk = record.get("statistical_risk")

    if fin_risk is None and beh_risk is None and stat_risk is None:
        base      = float(record.get("audit_risk_score", 0) or 0)
        fin_risk  = round(min(base * 0.45, 100), 1)
        beh_risk  = round(min(base * 0.35, 100), 1)
        stat_risk = round(min(base * 0.20, 100), 1)
    else:
        fin_risk  = float(fin_risk  or 0)
        beh_risk  = float(beh_risk  or 0)
        stat_risk = float(stat_risk or 0)

    st.markdown("**📊 Risk Breakdown**")
    rb1, rb2, rb3 = st.columns(3)
    with rb1:
        st.metric("💰 Financial Risk",   f"{fin_risk:.1f}%")
        st.progress(min(fin_risk  / 100, 1.0))
    with rb2:
        st.metric("🧠 Behavioral Risk",  f"{beh_risk:.1f}%")
        st.progress(min(beh_risk  / 100, 1.0))
    with rb3:
        st.metric("📈 Statistical Risk", f"{stat_risk:.1f}%")
        st.progress(min(stat_risk / 100, 1.0))


# ===========================================================================
# AUDIT EXPLANATION PANEL
# ===========================================================================

def render_audit_explanation(record):
    """Display the audit_explanation column in a styled panel."""
    explanation = record.get("audit_explanation") or record.get("audit_reason") or ""
    if not explanation:
        flags = normalize_flags(record.get("audit_flags", []))
        score = record.get("audit_risk_score", 0)
        if flags:
            explanation = (
                f"This transaction was flagged by the Audit Rule Engine with a risk score "
                f"of {score}/100. Key findings: {'; '.join(flags[:3])}."
            )
        else:
            explanation = "No audit explanation available for this transaction."
    st.markdown("**🔎 Audit Detection Reason**")
    st.info(explanation)


# ===========================================================================
# CASE TIMER WIDGET
# ===========================================================================

def render_case_timer(alert, record=None):
    """Show SLA countdown. Overdue → red. Near deadline → amber."""
    remaining, is_overdue = compute_sla_remaining(alert, record)
    if remaining is None:
        return
    if is_overdue:
        od = abs(remaining)
        st.markdown(
            f"""<div style="background:#fff0f0;border:2px solid #c0392b;border-radius:6px;
                padding:10px 14px;margin-bottom:8px;">
                <span style="color:#c0392b;font-weight:700;font-size:15px;">
                    🚨 SLA OVERDUE — {od} day{'s' if od != 1 else ''} past deadline
                </span></div>""",
            unsafe_allow_html=True,
        )
    else:
        color  = "#fff8e1" if remaining <= 2 else "#f0fff4"
        border = "#f5a623" if remaining <= 2 else "#27ae60"
        icon   = "⚠️"      if remaining <= 2 else "⏱️"
        st.markdown(
            f"""<div style="background:{color};border:1.5px solid {border};border-radius:6px;
                padding:10px 14px;margin-bottom:8px;">
                <span style="color:#333;font-weight:600;">
                    {icon} SLA: <strong>{remaining} day{'s' if remaining != 1 else ''}</strong> remaining
                </span></div>""",
            unsafe_allow_html=True,
        )


# ===========================================================================
# SEVERITY BADGE — CSS + RENDERER
# ===========================================================================

_BADGE_CSS = """
<style>
@keyframes _esc_flash {
    0%   { background-color:#922b21; }
    50%  { background-color:#e74c3c; box-shadow:0 0 10px #e74c3c; }
    100% { background-color:#922b21; }
}
.badge-escalated {
    display:inline-block; padding:4px 13px; border-radius:12px;
    font-size:12px; font-weight:700; color:#fff; letter-spacing:0.5px;
    animation:_esc_flash 1.1s infinite;
}
.badge-high {
    display:inline-block; padding:4px 13px; border-radius:12px;
    font-size:12px; font-weight:700; color:#fff;
    background:#c0392b; letter-spacing:0.5px;
}
.badge-medium {
    display:inline-block; padding:4px 13px; border-radius:12px;
    font-size:12px; font-weight:700; color:#fff;
    background:#e67e22; letter-spacing:0.5px;
}
.badge-low {
    display:inline-block; padding:4px 13px; border-radius:12px;
    font-size:12px; font-weight:700; color:#fff;
    background:#27ae60; letter-spacing:0.5px;
}
/* Section grouping inside expanders */
.alert-section {
    background:#f8f9fa; border-radius:8px;
    padding:12px 16px; margin:8px 0;
    border-left:4px solid #dee2e6;
}
.alert-section-ai    { border-left-color:#3498db; }
.alert-section-audit { border-left-color:#8e44ad; }
.alert-section-info  { border-left-color:#95a5a6; }
</style>
"""


def _inject_badge_css():
    if not st.session_state.get("_badge_css_injected"):
        st.markdown(_BADGE_CSS, unsafe_allow_html=True)
        st.session_state["_badge_css_injected"] = True


def severity_badge_html(severity: str, is_auto_escalated: bool = False) -> str:
    """Return inline HTML badge. Escalated → animated flash."""
    if is_auto_escalated:
        return '<span class="badge-escalated">🚨 ESCALATED</span>'
    sev = severity.lower().replace("audit_", "")
    if sev == "high":
        return '<span class="badge-high">🔴 HIGH</span>'
    if sev == "medium":
        return '<span class="badge-medium">🟠 MEDIUM</span>'
    return '<span class="badge-low">🟢 LOW</span>'


# ===========================================================================
# AUTO-ESCALATION LOGIC
# ===========================================================================

def apply_auto_escalation(df: pd.DataFrame) -> pd.DataFrame:
    """
    Set auto_escalated = True where:
        audit_severity == 'High'  AND  audit_risk_score > 70
    Safe when columns are absent.
    """
    if "auto_escalated" not in df.columns:
        df = df.copy()
        df["auto_escalated"] = False

    if "audit_severity" in df.columns and "audit_risk_score" in df.columns:
        mask = (
            df["audit_severity"].astype(str).str.strip().str.lower() == "high"
        ) & (
            pd.to_numeric(df["audit_risk_score"], errors="coerce").fillna(0) > 70
        )
        df.loc[mask, "auto_escalated"] = True

    return df


def sync_escalated_to_session(df: pd.DataFrame):
    """Push auto-escalated row indices into st.session_state.escalated_alerts."""
    if "auto_escalated" not in df.columns:
        return
    for idx in df.index[df["auto_escalated"] == True].tolist():
        st.session_state.escalated_alerts.add(idx)


# ===========================================================================
# AI CONFIDENCE HELPER
# ===========================================================================

def get_ai_confidence(score):
    if score >= 0.8:
        return score * 100, "High Confidence"
    elif score >= 0.5:
        return score * 100, "Medium Confidence"
    return score * 100, "Low Confidence"


# ===========================================================================
# AUTHENTICATION + RBAC
# ===========================================================================

if not st.session_state.get("authenticated"):
    st.error("🔒 Access Denied - Please login first")
    if st.button("🔐 Go to Login"):
        st.switch_page("pages/_Login.py")
    st.stop()

user_id   = st.session_state["user"]["id"]
user_role = st.session_state["user"].get("role", "viewer")

if user_role == "viewer":
    st.error("🚫 Alert management requires Auditor or Admin role")
    st.info("Contact your administrator to upgrade your access level")
    st.stop()

# ===========================================================================
# PAGE CONFIG + TITLE
# ===========================================================================

st.set_page_config(page_title="Alerts", page_icon="⚠️", layout="wide")
_inject_badge_css()
st.title("⚠️ Alert Management Center")

# ===========================================================================
# SESSION STATE INITIALISATION
# ===========================================================================

for _key, _default in [
    ("alerts",               []),
    ("reviewed_alerts",      set()),
    ("escalated_alerts",     set()),
    ("doc_requested_alerts", set()),
    ("audit_status",         {}),
    ("audit_notes",          {}),
    ("review_timestamps",    {}),
]:
    if _key not in st.session_state:
        st.session_state[_key] = _default

# ===========================================================================
# APPLY AUDIT ENGINE  (if not already done)
# ===========================================================================

if st.session_state.get("data") is not None:
    _df = st.session_state.data.copy()
    if AUDIT_ENGINE_AVAILABLE and "audit_flags" not in _df.columns:
        with st.spinner("🔍 Applying audit intelligence to data..."):
            try:
                _df = generate_audit_flags(_df)
                st.session_state.data = _df
                st.session_state.audit_processed = True
                st.success("✓ Audit rules applied to alert data")
            except Exception as _e:
                st.warning(f"Audit engine could not be applied: {_e}")
                AUDIT_ENGINE_AVAILABLE = False

# ===========================================================================
# APPLY AUTO-ESCALATION
# ===========================================================================

if st.session_state.get("data") is not None:
    _df = st.session_state.data
    if "audit_severity" in _df.columns and "audit_risk_score" in _df.columns:
        _df = apply_auto_escalation(_df)
        st.session_state.data = _df
        sync_escalated_to_session(_df)

# ===========================================================================
# DEPARTMENT FILTER  (existing logic — unchanged)
# ===========================================================================

alerts = st.session_state.alerts
selected_department = st.session_state.get("selected_department", "All Departments")

if selected_department != "All Departments" and st.session_state.get("data") is not None:
    _df = st.session_state.data
    _dept_alerts = []
    for _a in alerts:
        _rid = _a.get("id")
        if _rid is not None and _rid < len(_df):
            _rec = _df.iloc[_rid]
            _dept_val = _rec.get("department", _rec.get("dept", ""))
            if _dept_val == selected_department:
                _dept_alerts.append(_a)
    alerts = _dept_alerts

# ===========================================================================
# AUDIT INTELLIGENCE SUMMARY
# ===========================================================================

if AUDIT_ENGINE_AVAILABLE and st.session_state.get("data") is not None:
    _df = st.session_state.data
    if "audit_severity" in _df.columns:
        st.markdown("### 🔍 Audit Intelligence Summary")
        _audit_sum = summarize_audit_findings(_df)

        _as1, _as2, _as3, _as4 = st.columns(4)
        with _as1:
            st.metric("Total Audit Flags",      f"{_audit_sum['total_flagged']:,}")
        with _as2:
            st.metric("🔴 High Risk (Audit)",   f"{_audit_sum['high_risk_count']:,}")
        with _as3:
            st.metric("🟡 Medium Risk (Audit)", f"{_audit_sum['medium_risk_count']:,}")
        with _as4:
            st.metric("🟢 Low Risk (Audit)",    f"{_audit_sum['low_risk_count']:,}")

        with st.expander("📋 View Active Audit Rules"):
            for _rule in get_audit_rules_documentation():
                st.markdown(
                    f"**{_rule['rule_name']}** ({_rule['risk_level']} - {_rule['points']} points)"
                )
                st.markdown(f"- {_rule['description']}")
                st.markdown(f"- Flag: _{_rule['flag_message']}_")
                st.markdown("---")

        st.markdown("---")

# ===========================================================================
# ENTERPRISE SUMMARY METRICS
# ===========================================================================

st.markdown("### 📊 Alert Summary")

_total_alerts    = len(alerts)
_escalated_count = len(st.session_state.escalated_alerts)
_high_sev_count  = len([_a for _a in alerts if str(_a.get("severity", "")).lower() in ("high", "audit_high")])
_dept_count      = 0

if st.session_state.get("data") is not None:
    _dfs = st.session_state.data
    if "auto_escalated" in _dfs.columns:
        _escalated_count = max(_escalated_count, int(_dfs["auto_escalated"].sum()))
    for _col in ("department", "dept"):
        if _col in _dfs.columns:
            _dept_count = int(_dfs[_col].nunique())
            break
    if "audit_severity" in _dfs.columns:
        _high_sev_count = max(
            _high_sev_count,
            int((_dfs["audit_severity"].astype(str).str.lower() == "high").sum()),
        )

_sm1, _sm2, _sm3, _sm4 = st.columns(4)
with _sm1:
    st.metric("📋 Total Alerts", _total_alerts)
with _sm2:
    st.metric(
        "🚨 Escalated Alerts",
        _escalated_count,
        delta=f"+{_escalated_count} auto-escalated" if _escalated_count else None,
        delta_color="inverse",
    )
with _sm3:
    st.metric("🔴 High Severity", _high_sev_count)
with _sm4:
    st.metric("🏢 Departments Affected", _dept_count if _dept_count else "N/A")

st.markdown("---")

# ML metrics row
_ml1, _ml2, _ml3, _ml4 = st.columns(4)
with _ml1:
    st.metric("🔴 High Priority (ML)",   len([_a for _a in alerts if _a.get("severity") == "high"]))
with _ml2:
    st.metric("🟠 Medium Priority (ML)", len([_a for _a in alerts if _a.get("severity") == "medium"]))
with _ml3:
    st.metric("🟢 Low Priority (ML)",    len([_a for _a in alerts if _a.get("severity") == "low"]))
with _ml4:
    st.metric("📊 Total ML Alerts",      len(alerts))

st.markdown("---")

# ===========================================================================
# FILTER PANEL
# ===========================================================================

st.markdown("### 🔎 Filter Alerts")

_fc1, _fc2, _fc3, _fc4 = st.columns(4)

with _fc1:
    _filter_opts = ["high", "medium", "low"]
    if AUDIT_ENGINE_AVAILABLE and st.session_state.get("data") is not None:
        if "audit_severity" in st.session_state.data.columns:
            _filter_opts.extend(["audit_high", "audit_medium", "audit_low"])
    severity_filter = st.multiselect(
        "Filter by Severity", _filter_opts, default=["high", "medium", "low"]
    )

with _fc2:
    _esc_filter = st.selectbox(
        "Filter by Escalation",
        ["All", "Escalated Only", "Not Escalated"],
        index=0,
    )

with _fc3:
    _dept_options = ["All Departments"]
    if st.session_state.get("data") is not None:
        for _col in ("department", "dept"):
            if _col in st.session_state.data.columns:
                _depts = sorted(st.session_state.data[_col].dropna().unique().tolist())
                _dept_options.extend([str(d) for d in _depts])
                break
    _dept_filter = st.selectbox("Filter by Department", _dept_options, index=0)

with _fc4:
    sort_by = st.selectbox(
        "Sort by",
        ["Score (High to Low)", "Score (Low to High)", "Recent First", "Audit Risk Score"],
    )

search = st.text_input("🔍 Search by Record ID", "")

# ===========================================================================
# BUILD filtered_alerts
# ===========================================================================

filtered_alerts = [_a for _a in alerts if _a.get("severity") in severity_filter]

# Add audit-engine-based alerts
if AUDIT_ENGINE_AVAILABLE and st.session_state.get("data") is not None:
    _df = st.session_state.data
    if "audit_flags" in _df.columns:
        _inc_ah = "audit_high"   in severity_filter
        _inc_am = "audit_medium" in severity_filter
        _inc_al = "audit_low"    in severity_filter

        if _inc_ah or _inc_am or _inc_al:
            _flagged = get_flagged_transactions(_df, min_flags=1)
            for _idx, _row in _flagged.iterrows():
                _asev = str(_row.get("audit_severity", "Low")).lower()
                _should = (
                    (_asev == "high"   and _inc_ah) or
                    (_asev == "medium" and _inc_am) or
                    (_asev == "low"    and _inc_al)
                )
                if _should:
                    _aa = {
                        "id":        _idx,
                        "severity":  f"audit_{_asev}",
                        "score":     float(_row.get("audit_risk_score", 0) or 0) / 100,
                        "timestamp": datetime.now().isoformat(),
                        "reason":    "; ".join(normalize_flags(_row.get("audit_flags", []))),
                        "source":    "audit_engine",
                    }
                    if not any(
                        _a.get("id") == _idx and _a.get("source") == "audit_engine"
                        for _a in filtered_alerts
                    ):
                        filtered_alerts.append(_aa)

# Escalation filter
if _esc_filter != "All":
    _esc_ids = st.session_state.escalated_alerts
    if _esc_filter == "Escalated Only":
        filtered_alerts = [_a for _a in filtered_alerts if _a.get("id") in _esc_ids]
    else:
        filtered_alerts = [_a for _a in filtered_alerts if _a.get("id") not in _esc_ids]

# Department filter
if _dept_filter != "All Departments" and st.session_state.get("data") is not None:
    _dfd = st.session_state.data
    _dept_col = next((c for c in ("department", "dept") if c in _dfd.columns), None)
    if _dept_col:
        _dept_filtered = []
        for _a in filtered_alerts:
            _rid = _a.get("id")
            if _rid is not None and _rid < len(_dfd):
                if str(_dfd.iloc[_rid].get(_dept_col, "")) == _dept_filter:
                    _dept_filtered.append(_a)
        filtered_alerts = _dept_filtered

# Search
if search:
    filtered_alerts = [_a for _a in filtered_alerts if search in str(_a.get("id", ""))]

# Sort
if sort_by == "Score (High to Low)":
    filtered_alerts = sorted(filtered_alerts, key=lambda x: x.get("score", 0), reverse=True)
elif sort_by == "Score (Low to High)":
    filtered_alerts = sorted(filtered_alerts, key=lambda x: x.get("score", 0))
elif sort_by == "Audit Risk Score" and AUDIT_ENGINE_AVAILABLE:
    def _get_audit_score(_alert):
        if _alert.get("source") == "audit_engine":
            return _alert.get("score", 0)
        _rid = _alert.get("id")
        if st.session_state.get("data") is not None and _rid is not None:
            _dfs2 = st.session_state.data
            if _rid < len(_dfs2) and "audit_risk_score" in _dfs2.columns:
                return float(_dfs2.iloc[_rid].get("audit_risk_score", 0) or 0) / 100
        return _alert.get("score", 0)
    filtered_alerts = sorted(filtered_alerts, key=_get_audit_score, reverse=True)


# ===========================================================================
# ┌─────────────────────────────────────────────────────────────┐
# │  ALERT CARD LIST                                            │
# │                                                             │
# │  Each card = COMPACT SUMMARY ONLY:                         │
# │    • Severity badge + SLA timer                            │
# │    • Transaction Info (ID, score, case, status, date)      │
# │    • AI Detection Reason                                    │
# │    • Audit Detection Reason + flags                        │
# │    • Quick action row (Review / False Positive / Docs)     │
# │                                                             │
# │  NO Auditor Notes here — that lives in Transaction Details │
# │  NO Escalation form here — that lives in Transaction Details│
# └─────────────────────────────────────────────────────────────┘
# ===========================================================================

st.subheader(f"📋 Alerts ({len(filtered_alerts)})")

if not filtered_alerts:
    st.info("No alerts to display. Run AI Risk Scan or adjust filter settings.")
else:
    # Resolve audit case IDs (existing logic — unchanged)
    if (
        st.session_state.get("data") is not None
        and "audit_case_id" in st.session_state.data.columns
    ):
        _dfc2     = st.session_state.data
        _c_alerts = []
        for _a in filtered_alerts[:50]:
            _rid = _a.get("id")
            if _rid is not None and _rid < len(_dfc2):
                _cid = _dfc2.iloc[_rid].get("audit_case_id")
                if pd.notna(_cid):
                    _a["audit_case_id"] = _cid
                    _a["audit_status"]  = _dfc2.iloc[_rid].get("audit_status", "Open")
                    _c_alerts.append(_a)
        display_alerts = _c_alerts if _c_alerts else filtered_alerts[:50]
        st.info(f"Showing {len(display_alerts)} alerts with audit cases (High/Medium severity only)")
    else:
        display_alerts = filtered_alerts[:50]

    # ------------------------------------------------------------------
    # RENDER EACH ALERT CARD  — COMPACT, NO DUPLICATION
    # ------------------------------------------------------------------
    for i, alert in enumerate(display_alerts):
        severity        = alert.get("severity", "medium")
        alert_id        = alert.get("id", i)
        source          = alert.get("source", "ml")
        is_reviewed     = alert_id in st.session_state.reviewed_alerts
        is_escalated    = alert_id in st.session_state.escalated_alerts
        has_doc_request = alert_id in st.session_state.doc_requested_alerts

        # Pull dataframe record for enrichment
        _rec = None
        _is_auto_esc = False
        if st.session_state.get("data") is not None:
            _dfa = st.session_state.data
            if alert_id is not None and alert_id < len(_dfa):
                _rec = _dfa.iloc[alert_id]
                _is_auto_esc = bool(_rec.get("auto_escalated", False))

        # SLA
        _sla_rem, _is_overdue = compute_sla_remaining(alert, _rec)

        case_id      = alert.get("audit_case_id", "N/A")
        audit_status = alert.get("audit_status", "N/A")

        # Header label
        _sev_label = (
            severity.replace("audit_", "").upper() + " (AUDIT)"
            if severity.startswith("audit_")
            else severity.upper() + " (ML)"
        )

        # Header status text badges
        _header_badges = ""
        if is_reviewed:                  _header_badges += "✅ Reviewed "
        if _is_auto_esc or is_escalated: _header_badges += "🚨 Escalated "
        if has_doc_request:              _header_badges += "📄 Docs Requested "
        if _is_overdue:                  _header_badges += "🔥 SLA OVERDUE "
        elif _sla_rem is not None and _sla_rem <= 2:
            _header_badges += f"⚠️ SLA {_sla_rem}d "

        _header = f"Alert #{alert_id} — {_sev_label} — Score: {alert.get('score', 0):.3f}"
        if case_id != "N/A":
            _header += f" | 📋 {case_id} - {audit_status}"
        if _header_badges:
            _header += f"  {_header_badges}"

        with st.expander(_header):

            # ── SLA OVERDUE BANNER ──────────────────────────────────────────
            if _is_overdue:
                st.markdown(
                    f"""<div style="background:#ffe0e0;border:2px solid #c0392b;
                        border-radius:6px;padding:8px 14px;margin-bottom:10px;">
                        <strong style="color:#c0392b;">
                            🚨 OVERDUE — exceeded {DEFAULT_SLA_DAYS}-day SLA by
                            {abs(_sla_rem)} day{'s' if abs(_sla_rem) != 1 else ''}.
                            Immediate action required.
                        </strong></div>""",
                    unsafe_allow_html=True,
                )

            # ── SEVERITY BADGE + AUTO-ESCALATION NOTICE ────────────────────
            st.markdown(
                severity_badge_html(severity, _is_auto_esc),
                unsafe_allow_html=True,
            )
            if _is_auto_esc:
                st.markdown(
                    """<div style="background:#fff0f0;border-left:4px solid #c0392b;
                        border-radius:4px;padding:8px 12px;margin:6px 0 10px 0;">
                        <strong style="color:#c0392b;">⚡ Auto-Escalated:</strong>
                        audit_severity = High AND audit_risk_score &gt; 70
                    </div>""",
                    unsafe_allow_html=True,
                )

            # ── SLA TIMER ───────────────────────────────────────────────────
            render_case_timer(alert, _rec)

            # ── SECTION 1: TRANSACTION INFO ─────────────────────────────────
            st.markdown(
                '<div class="alert-section alert-section-info">',
                unsafe_allow_html=True,
            )
            st.markdown("**🧾 Transaction Information**")
            _ti1, _ti2, _ti3 = st.columns(3)
            with _ti1:
                st.markdown(f"**Record ID:** `{alert_id}`")
                if case_id != "N/A":
                    st.markdown(f"**Case ID:** `{case_id}`")
            with _ti2:
                st.markdown(f"**Risk Score:** `{alert.get('score', 0):.4f}`")
                if audit_status != "N/A":
                    _sc_map = {
                        "Open": "🟡", "Under Review": "🔵",
                        "Escalated": "🔴", "Closed": "🟢",
                    }
                    st.markdown(f"**Status:** {_sc_map.get(audit_status, '⚪')} {audit_status}")
            with _ti3:
                _ts = alert.get("timestamp", "")
                st.markdown(f"**Detected:** `{_ts[:19] if _ts else 'N/A'}`")
                if _rec is not None:
                    _amt = _rec.get("amount", _rec.get("transaction_amount", ""))
                    if _amt != "":
                        st.markdown(
                            f"**Amount:** `{'${:,.2f}'.format(_amt) if isinstance(_amt, (int, float)) else safe_str(_amt)}`"
                        )
            # Additional record fields
            if _rec is not None:
                _rd1, _rd2 = st.columns(2)
                with _rd1:
                    st.markdown(f"**Department:** {safe_str(_rec.get('department', _rec.get('dept')))}")
                    st.markdown(f"**Vendor:** {safe_str(_rec.get('vendor', _rec.get('vendor_name')))}")
                with _rd2:
                    st.markdown(f"**Date:** {safe_str(_rec.get('date', _rec.get('transaction_date')))}")
                    st.markdown(f"**Purpose:** {safe_str(_rec.get('purpose', _rec.get('description')))}")
                if "audit_risk_score" in _rec:
                    st.markdown(f"**Audit Risk Score:** `{_rec['audit_risk_score']}/100`")
                if "auto_escalated" in _rec:
                    st.markdown(f"**Auto-Escalated:** `{bool(_rec['auto_escalated'])}`")
            st.markdown('</div>', unsafe_allow_html=True)

            # ── SECTION 2: AI DETECTION REASON ─────────────────────────────
            _ai_reason = alert.get("reason", "")
            if _ai_reason or (alert.get("score", 0) > 0):
                st.markdown(
                    '<div class="alert-section alert-section-ai">',
                    unsafe_allow_html=True,
                )
                st.markdown("**🤖 AI Detection Reason**")
                _score = alert.get("score", 0)
                _conf_pct, _conf_lvl = get_ai_confidence(_score)
                st.markdown(f"AI Confidence: **{_conf_pct:.1f}%** ({_conf_lvl})")
                if _ai_reason:
                    st.markdown(f"> {_ai_reason}")
                else:
                    st.markdown(
                        "> 📊 Anomalous pattern detected via statistical / ML analysis."
                    )
                st.markdown('</div>', unsafe_allow_html=True)

            # ── SECTION 3: AUDIT DETECTION REASON ──────────────────────────
            if _rec is not None:
                _flags = normalize_flags(_rec.get("audit_flags", []))
                _audit_exp = (
                    _rec.get("audit_explanation")
                    or _rec.get("audit_reason")
                    or ""
                )
                if _flags or _audit_exp:
                    st.markdown(
                        '<div class="alert-section alert-section-audit">',
                        unsafe_allow_html=True,
                    )
                    st.markdown("**🔍 Audit Detection Reason**")
                    if _audit_exp:
                        st.markdown(f"> {_audit_exp}")
                    if _flags:
                        st.markdown("**Audit Flags:**")
                        for _f in _flags:
                            st.markdown(f"&nbsp;&nbsp;&nbsp;• {_f}")
                    st.markdown('</div>', unsafe_allow_html=True)

            # ── SECTION 4: QUICK ACTIONS (Review / False Positive / Docs) ──
            # NOTE: Auditor Notes and Escalation form are intentionally
            #       omitted here. They appear ONCE in the Transaction Details
            #       panel below, which is the proper investigation workspace.
            st.markdown("---")
            st.markdown("**👆 Quick Actions**")
            _ab1, _ab2, _ab3 = st.columns(3)
            with _ab1:
                if st.button(
                    "✅ Mark as Reviewed", key=f"review_{i}",
                    disabled=is_reviewed, use_container_width=True,
                ):
                    st.session_state.reviewed_alerts.add(alert_id)
                    st.rerun()
                if is_reviewed:
                    st.success("Already reviewed")
            with _ab2:
                if st.button(
                    "🚫 False Positive", key=f"fp_{i}",
                    use_container_width=True,
                ):
                    st.info("Marked as false positive")
            with _ab3:
                if st.button(
                    "📄 Request Documents", key=f"docs_{i}",
                    disabled=has_doc_request, use_container_width=True,
                ):
                    st.session_state.doc_requested_alerts.add(alert_id)
                    st.rerun()
                if has_doc_request:
                    st.info("Documents requested")

            st.caption(
                "💡 For full investigation (Auditor Notes, Escalation, "
                "Case Management) select this alert in the Transaction Details panel below."
            )


# ===========================================================================
# ┌─────────────────────────────────────────────────────────────────────────┐
# │  TRANSACTION DETAILS PANEL  — FULL INVESTIGATION WORKSPACE             │
# │                                                                         │
# │  This is the SINGLE location for:                                       │
# │    • Auditor Notes (appears exactly once)                               │
# │    • Escalation / Case Status (appears exactly once)                    │
# │    • Risk Breakdown                                                      │
# │    • Full audit explanation                                             │
# │    • Transaction timeline                                               │
# └─────────────────────────────────────────────────────────────────────────┘
# ===========================================================================

if filtered_alerts:
    st.markdown("---")
    st.subheader("📄 Transaction Details — Full Investigation")

    _alert_labels = []
    for _i, _a in enumerate(filtered_alerts[:50]):
        _sev = _a.get("severity", "medium")
        _lbl = (
            _sev.replace("audit_", "").upper() + " (AUDIT)"
            if _sev.startswith("audit_")
            else _sev.upper() + " (ML)"
        )
        _alert_labels.append(f"Alert #{_a.get('id', _i)} - {_lbl}")

    selected_alert_idx = st.selectbox(
        "Select alert to investigate:",
        range(len(_alert_labels)),
        format_func=lambda x: _alert_labels[x],
        key="transaction_selector",
    )

    if selected_alert_idx is not None:
        selected_alert = filtered_alerts[selected_alert_idx]
        record_id      = selected_alert.get("id")

        with st.container():
            _sev = selected_alert.get("severity", "medium")
            _sev_colors = (
                {"audit_high": "🔴", "audit_medium": "🟡", "audit_low": "🟢"}
                if _sev.startswith("audit_")
                else {"high": "🔴", "medium": "🟠", "low": "🟢"}
            )
            st.markdown(
                f"### {_sev_colors.get(_sev, '⚪')} Transaction ID: {record_id}"
            )

            # Severity badge + confidence
            _score = selected_alert.get("score", 0)
            _conf_pct, _conf_lvl = get_ai_confidence(_score)

            _hdr1, _hdr2, _hdr3 = st.columns(3)
            with _hdr1:
                st.markdown(
                    severity_badge_html(_sev),
                    unsafe_allow_html=True,
                )
            with _hdr2:
                st.warning(f"**Risk Score:** {_score:.4f}")
            with _hdr3:
                st.info(f"**AI Confidence:** {_conf_pct:.1f}% ({_conf_lvl})")

            # Resolve detail record
            _det_rec = None
            if st.session_state.get("data") is not None and record_id is not None:
                _dfd3 = st.session_state.data
                if record_id < len(_dfd3):
                    _det_rec = _dfd3.iloc[record_id]

            # SLA timer
            render_case_timer(selected_alert, _det_rec)

            # Auto-escalation notice
            if _det_rec is not None and bool(_det_rec.get("auto_escalated", False)):
                st.markdown(
                    severity_badge_html(_sev, is_auto_escalated=True),
                    unsafe_allow_html=True,
                )
                st.markdown(
                    """<div style="background:#fff0f0;border-left:4px solid #c0392b;
                        border-radius:4px;padding:8px 12px;margin:8px 0;">
                        <strong style="color:#c0392b;">⚡ Auto-Escalated:</strong>
                        audit_severity = High AND audit_risk_score &gt; 70
                    </div>""",
                    unsafe_allow_html=True,
                )

            if _det_rec is not None:
                record = _det_rec  # alias for readability below

                # ── GROUP A: TRANSACTION INFORMATION ───────────────────────
                st.markdown("#### 🧾 Transaction Information")
                _dc1, _dc2, _dc3 = st.columns(3)
                with _dc1:
                    st.markdown("**Date**")
                    st.text(record.get("date", record.get("transaction_date", "N/A")))
                with _dc2:
                    st.markdown("**Amount**")
                    _amt = record.get("amount", record.get("transaction_amount", 0))
                    st.text(
                        f"${_amt:,.2f}" if isinstance(_amt, (int, float)) else safe_str(_amt)
                    )
                with _dc3:
                    st.markdown("**Department**")
                    st.text(record.get("department", record.get("dept", "N/A")))

                _dd1, _dd2 = st.columns(2)
                with _dd1:
                    st.markdown("**Vendor**")
                    st.text(record.get("vendor", record.get("vendor_name", "N/A")))
                with _dd2:
                    st.markdown("**Purpose**")
                    st.text(record.get("purpose", record.get("description", "N/A")))

                st.markdown("---")

                # ── GROUP B: AI DETECTION REASON ───────────────────────────
                st.markdown("#### 🤖 AI Detection Reason")
                _reason = selected_alert.get(
                    "reason", "Anomalous pattern detected based on statistical analysis"
                )
                st.text_area(
                    "", value=_reason, height=80,
                    disabled=True, label_visibility="collapsed",
                )

                # Expanded AI explanation bullets
                with st.expander("View detailed AI analysis"):
                    _amt2  = record.get("amount", record.get("transaction_amount", 0))
                    _dept2 = record.get("department", record.get("dept", "Unknown"))
                    _vend2 = record.get("vendor", record.get("vendor_name", "Unknown"))
                    _sc2   = selected_alert.get("score", 0)
                    _exps  = []

                    if _sc2 > 0.8:
                        _exps.append("🔴 **High Anomaly Score**: Significantly deviates from normal patterns")
                    if isinstance(_amt2, (int, float)) and _amt2 > 100000:
                        _exps.append(f"💰 **Amount Deviation**: ${_amt2:,.2f} exceeds typical {_dept2} baseline")
                    if "Unknown" in str(_vend2) or not _vend2:
                        _exps.append("⚠️ **Vendor Risk**: Unknown or unregistered vendor")
                    if record.get("approval_status", "").lower() == "pending":
                        _exps.append("📋 **Approval Mismatch**: High-value transaction pending approval")
                    _pm = record.get("payment_method", "")
                    if "Wire Transfer" in str(_pm) and isinstance(_amt2, (int, float)) and _amt2 > 50000:
                        _exps.append("🏦 **Payment Method Alert**: Large wire transfer requires scrutiny")
                    try:
                        _td = pd.to_datetime(record.get("date", record.get("transaction_date")))
                        if _td.weekday() >= 5:
                            _exps.append("📅 **Time-Based Anomaly**: Transaction occurred on weekend")
                    except Exception:
                        pass

                    if not _exps:
                        _exps.append("📊 **Pattern Deviation**: Statistical analysis detected unusual characteristics")
                    for _e in _exps:
                        st.markdown(_e)

                st.markdown("---")

                # ── GROUP C: AUDIT DETECTION REASON ────────────────────────
                st.markdown("#### 🔍 Audit Detection Reason")
                render_audit_explanation(record)

                # Audit flags detail
                _afl = normalize_flags(record.get("audit_flags", []))
                if AUDIT_ENGINE_AVAILABLE and _afl:
                    with st.expander("View all audit flags"):
                        for _f in _afl:
                            st.markdown(f"• {_f}")
                        if "audit_risk_score" in record:
                            st.markdown(f"**Audit Risk Score:** {record['audit_risk_score']}/100")

                # Risk breakdown
                render_risk_breakdown(record)
                st.markdown("---")

                # ── GROUP D: TRANSACTION TIMELINE ──────────────────────────
                st.markdown("#### 📅 Transaction Timeline")
                _tl1, _tl2, _tl3, _tl4 = st.columns(4)
                try:
                    _tdate = pd.to_datetime(
                        record.get("date", record.get("transaction_date", datetime.now()))
                    )
                except Exception:
                    _tdate = datetime.now()

                _apst = record.get("approval_status", "Pending")
                with _tl1:
                    st.markdown("**Created**")
                    st.info(_tdate.strftime("%Y-%m-%d"))
                with _tl2:
                    st.markdown("**Approved**")
                    if _apst.lower() == "approved":
                        st.success((_tdate + timedelta(days=1)).strftime("%Y-%m-%d"))
                    else:
                        st.warning("Pending")
                with _tl3:
                    st.markdown("**Payment**")
                    if _apst.lower() == "approved":
                        st.success((_tdate + timedelta(days=3)).strftime("%Y-%m-%d"))
                    else:
                        st.warning("Not Paid")
                with _tl4:
                    st.markdown("**AI Flagged**")
                    _fdate = selected_alert.get("timestamp", datetime.now().isoformat())[:10]
                    st.error(_fdate)

                st.markdown("---")

            # ── GROUP E: AUDITOR ACTION SECTION (APPEARS EXACTLY ONCE) ─────
            # This block is the single source of truth for:
            #   • Case Status update
            #   • Auditor Notes
            #   • Escalation
            #   • Document request
            st.markdown("#### 👨‍💼 Auditor Action Section")

            _rid_int  = int(record_id) if record_id is not None else 0
            _db_audit = database.get_audit_status(_rid_int)

            if _db_audit:
                current_status = _db_audit["status"]
                current_notes  = _db_audit["auditor_notes"] or ""
                try:
                    current_timestamp = (
                        datetime.fromisoformat(_db_audit["review_timestamp"])
                        if _db_audit["review_timestamp"]
                        else st.session_state.review_timestamps.get(_rid_int)
                    )
                except Exception:
                    current_timestamp = st.session_state.review_timestamps.get(_rid_int)
            else:
                current_status    = st.session_state.audit_status.get(_rid_int, "Pending Review")
                current_notes     = st.session_state.audit_notes.get(_rid_int, "")
                current_timestamp = st.session_state.review_timestamps.get(_rid_int)

            # Case status + timestamp in one row
            _ea1, _ea2 = st.columns([1, 1])
            with _ea1:
                _cs_opts = ["Pending Review", "Reviewed", "Escalated"]
                _cs_idx  = (
                    _cs_opts.index(current_status) if current_status in _cs_opts else 0
                )
                new_status = st.selectbox(
                    "Case Status",
                    _cs_opts,
                    index=_cs_idx,
                    key=f"audit_status_{_rid_int}",
                )
                if new_status != current_status and current_status == "Pending Review":
                    st.session_state.review_timestamps[_rid_int] = datetime.now()
                    current_timestamp = st.session_state.review_timestamps[_rid_int]
            with _ea2:
                if current_timestamp:
                    st.markdown("**Review Timestamp**")
                    st.info(current_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
                else:
                    st.markdown("**Review Timestamp**")
                    st.warning("Not yet reviewed")

            # Auditor Notes — single instance
            st.markdown("**📝 Auditor Notes**")
            auditor_notes = st.text_area(
                "Enter investigation notes, findings, or recommendations:",
                value=current_notes,
                height=130,
                key=f"audit_notes_{_rid_int}",
                placeholder="Enter your notes about this transaction — findings, next steps, recommendations...",
                label_visibility="collapsed",
            )

            # Escalation + document request in one row
            _ea3, _ea4, _ea5 = st.columns(3)
            _is_esc  = _rid_int in st.session_state.escalated_alerts
            _has_doc = _rid_int in st.session_state.doc_requested_alerts
            _is_rev  = _rid_int in st.session_state.reviewed_alerts

            with _ea3:
                if st.button(
                    "✅ Mark as Reviewed", key="detail_review",
                    use_container_width=True, disabled=_is_rev,
                ):
                    st.session_state.reviewed_alerts.add(_rid_int)
                    st.success("✓ Marked as reviewed")
                    st.rerun()
                if _is_rev:
                    st.success("Already reviewed")

            with _ea4:
                # Single escalation button — the only escalation control on the page
                if st.button(
                    "🚨 Escalate to Supervisor", key="detail_escalate",
                    use_container_width=True, disabled=_is_esc,
                ):
                    st.session_state.escalated_alerts.add(_rid_int)
                    st.error("✓ Escalated to supervisor")
                    st.rerun()
                if _is_esc:
                    st.error("Already escalated")

            with _ea5:
                if st.button(
                    "📄 Request Documents", key="detail_docs",
                    use_container_width=True, disabled=_has_doc,
                ):
                    st.session_state.doc_requested_alerts.add(_rid_int)
                    st.info("✓ Document request sent")
                    st.rerun()
                if _has_doc:
                    st.info("Documents requested")

            # Save button
            if st.button(
                "💾 Save Audit Information",
                key=f"save_audit_{_rid_int}",
                type="primary",
                use_container_width=True,
            ):
                old_status = st.session_state.audit_status.get(_rid_int, "Pending Review")
                st.session_state.audit_status[_rid_int] = new_status
                st.session_state.audit_notes[_rid_int]  = auditor_notes

                if (
                    new_status != "Pending Review"
                    and _rid_int not in st.session_state.review_timestamps
                ):
                    st.session_state.review_timestamps[_rid_int] = datetime.now()
                current_timestamp = st.session_state.review_timestamps.get(_rid_int)

                try:
                    _uid  = st.session_state["user"]["id"]
                    _oid  = st.session_state["user"].get("organization_id")

                    if _det_rec is not None:
                        _tdata = {
                            "transaction_id":      _rid_int,
                            "department":          _det_rec.get("department", _det_rec.get("dept", "Unknown")),
                            "amount":              float(_det_rec.get("amount", _det_rec.get("transaction_amount", 0))),
                            "vendor":              _det_rec.get("vendor", _det_rec.get("vendor_name", "Unknown")),
                            "purpose":             _det_rec.get("purpose", _det_rec.get("description", "N/A")),
                            "transaction_date":    str(_det_rec.get("date", _det_rec.get("transaction_date", ""))),
                            "risk_score":          float(selected_alert.get("score", 0)),
                            "severity":            selected_alert.get("severity", "medium"),
                            "ai_reason":           selected_alert.get("reason", "Anomaly detected"),
                            "detection_timestamp": selected_alert.get("timestamp", datetime.now().isoformat()),
                        }
                        database.save_transaction(_tdata, user_id=_uid, organization_id=_oid)

                    database.save_audit_action(
                        transaction_id=_rid_int,
                        status=new_status,
                        auditor_notes=auditor_notes,
                        review_timestamp=(
                            current_timestamp.isoformat() if current_timestamp else None
                        ),
                        action_type=(
                            "status_update" if old_status != new_status else "notes_update"
                        ),
                    )
                    if old_status != new_status:
                        database.log_audit_history(_rid_int, "status", old_status, new_status)
                    st.success(f"✓ Audit information saved — Status: {new_status}")
                except Exception as _e:
                    st.error(f"Database save error: {_e}")
                    st.warning("Data saved to session only (not persisted)")
                st.rerun()

            # Audit summary (shown only after notes exist)
            if current_status != "Pending Review" or current_notes:
                st.markdown("---")
                st.markdown("**Audit Summary**")
                _ss1, _ss2 = st.columns(2)
                with _ss1:
                    _sc_map2 = {
                        "Pending Review": "🟡", "Reviewed": "✅", "Escalated": "🚨",
                    }
                    st.markdown(
                        f"{_sc_map2.get(current_status, '⚪')} **Status:** {current_status}"
                    )
                with _ss2:
                    if current_timestamp:
                        st.markdown(
                            f"📅 **Last Updated:** {current_timestamp.strftime('%Y-%m-%d %H:%M')}"
                        )
                if current_notes:
                    with st.expander("View Saved Notes"):
                        st.text(current_notes)

            # Case management (optional — only when case_id exists)
            _detail_case_id = selected_alert.get("audit_case_id", "N/A")
            if _detail_case_id != "N/A" and AUDIT_CASE_MANAGER_AVAILABLE:
                st.markdown("---")
                st.markdown("**🔧 Case Management**")
                _cm1, _cm2 = st.columns(2)

                _detail_audit_status = selected_alert.get("audit_status", "Open")
                with _cm1:
                    _cs_opts2 = ["Open", "Under Review", "Escalated", "Closed"]
                    _new_cs   = st.selectbox(
                        "Update Case Status", _cs_opts2,
                        index=(
                            _cs_opts2.index(_detail_audit_status)
                            if _detail_audit_status in _cs_opts2 else 0
                        ),
                        key="detail_case_status_select",
                    )
                    if st.button("💾 Update Case Status", key="detail_update_case_status"):
                        if st.session_state.get("data") is not None:
                            _d = st.session_state.data
                            _d = update_case_status(_d, _detail_case_id, _new_cs)
                            st.session_state.data = _d
                            try:
                                database.update_audit_case(_detail_case_id, "status", _new_cs)
                                st.success(f"✓ Case {_detail_case_id} → {_new_cs}")
                            except Exception as _e:
                                st.warning(f"Session updated; DB error: {_e}")
                            st.rerun()

                with _cm2:
                    _comment = st.text_input(
                        "Add Case Comment",
                        key="detail_case_comment",
                        placeholder="Enter case notes...",
                    )
                    if st.button("💬 Add Comment", key="detail_add_case_comment"):
                        if _comment and st.session_state.get("data") is not None:
                            _d = st.session_state.data
                            _d = add_case_comment(_d, _detail_case_id, _comment)
                            st.session_state.data = _d
                            try:
                                _prev = database.get_audit_cases().query(
                                    f"case_id == '{_detail_case_id}'"
                                )["auditor_comment"].iloc[0]
                                _ts_now = datetime.now().strftime("%Y-%m-%d %H:%M")
                                _new_c  = (
                                    f"{_prev}\n[{_ts_now}] {_comment}"
                                    if _prev else f"[{_ts_now}] {_comment}"
                                )
                                database.update_audit_case(
                                    _detail_case_id, "auditor_comment", _new_c
                                )
                                st.success(f"✓ Comment added to {_detail_case_id}")
                            except Exception:
                                st.warning("Comment added in session; not saved to DB")
                            st.rerun()


# ===========================================================================
# BULK ACTIONS
# ===========================================================================

st.markdown("---")
st.subheader("🛠️ Bulk Actions")

_ba1, _ba2, _ba3 = st.columns(3)

with _ba1:
    if st.button("📥 Export All Alerts", use_container_width=True):
        if alerts:
            _adf = pd.DataFrame(alerts)
            st.download_button(
                label="Download CSV",
                data=_adf.to_csv(index=False),
                file_name="alerts_export.csv",
                mime="text/csv",
            )

with _ba2:
    if st.button("✅ Mark All as Reviewed", use_container_width=True):
        for _a in filtered_alerts:
            st.session_state.reviewed_alerts.add(_a.get("id"))
        st.success("✓ All alerts marked as reviewed")

with _ba3:
    if st.button("🗑️ Clear All Alerts", use_container_width=True):
        st.session_state.alerts               = []
        st.session_state.reviewed_alerts      = set()
        st.session_state.escalated_alerts     = set()
        st.session_state.doc_requested_alerts = set()
        st.rerun()


# ===========================================================================
# ALERT CONFIGURATION
# ===========================================================================

st.markdown("---")
st.subheader("⚙️ Alert Configuration")

with st.expander("Configure Alert Rules"):
    st.markdown("#### Threshold Settings")
    _cfg1, _cfg2 = st.columns(2)
    with _cfg1:
        high_threshold   = st.slider("High Severity Threshold",   0.0, 1.0, 0.8)
        medium_threshold = st.slider("Medium Severity Threshold", 0.0, 1.0, 0.5)
    with _cfg2:
        email_notifications = st.checkbox("Enable Email Notifications", value=False)
        slack_notifications = st.checkbox("Enable Slack Notifications", value=False)
    if email_notifications:
        email = st.text_input("Notification Email")
    if st.button("Save Configuration"):
        st.success("✓ Configuration saved")
