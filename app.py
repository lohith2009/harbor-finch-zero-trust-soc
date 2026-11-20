import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pandas as pd
import streamlit as st

from main import run_full_security_pipeline, run_key_leak_scan
from verifier import is_approved_api_ip, resolve_ip_location
from virus_key_defense import (
    cleanup_scratch_test_files,
    clear_nonce_store,
    get_runtime_security_posture,
    scan_workspace_for_leaked_keys,
    validate_signed_request_with_nonce,
)

IST = ZoneInfo("Asia/Kolkata")
SCRATCH_TEST_FILE = Path("./_dashboard_dummy_key_check.txt")
STATE_FILE = Path("./.runtime_state/soc_state.json")
PROOF_PACK_PATH = Path("./output/proof_pack.json")


def _silence_win_connection_reset(loop: asyncio.AbstractEventLoop, context: dict[str, Any]) -> None:
    exc = context.get("exception")
    if isinstance(exc, ConnectionResetError) and getattr(exc, "winerror", None) == 10054:
        return
    loop.default_exception_handler(context)


def _install_asyncio_reset_filter() -> None:
    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(_silence_win_connection_reset)
    except RuntimeError:
        pass


st.set_page_config(
    page_title="Harbor & Finch | Zero-Trust SOC & API Defense Command",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

_install_asyncio_reset_filter()

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0b0f19;
        color: #e5e7eb;
    }
    header[data-testid="stHeader"] {
        background-color: rgba(11, 15, 25, 0.85);
    }

    /* Responsive Hero Banner */
    .soc-banner {
        background: linear-gradient(135deg, #111827 0%, #0f172a 60%, #1e1b4b 100%);
        border: 1px solid #1f2937;
        border-left: 5px solid #38bdf8;
        border-radius: 10px;
        padding: 18px 24px;
        margin-bottom: 18px;
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        justify-content: space-between;
        align-items: center;
    }
    .soc-title {
        font-size: 24px;
        font-weight: 800;
        color: #f9fafb;
        margin: 0;
        letter-spacing: -0.3px;
    }
    .soc-subtitle {
        font-size: 13px;
        color: #9ca3af;
        margin: 4px 0 0 0;
    }
    .soc-badge-ok {
        background-color: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #059669;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 700;
        white-space: nowrap;
    }
    .soc-badge-alert {
        background-color: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid #ef4444;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 700;
        white-space: nowrap;
        animation: pulseGlow 1.8s infinite;
    }
    @keyframes pulseGlow {
        0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.5); }
        70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
        100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }

    /* KPI Telemetry Cards */
    div[data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-radius: 10px;
        padding: 14px 18px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    }
    div[data-testid="stMetricLabel"] {
        color: #9ca3af !important;
        font-size: 13px !important;
        font-weight: 600 !important;
    }
    div[data-testid="stMetricValue"] {
        color: #f9fafb !important;
        font-size: 30px !important;
        font-weight: 800 !important;
    }

    /* Responsive 5-Stage Pipeline Cards */
    .pipeline-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
        gap: 10px;
        margin: 12px 0 20px 0;
    }
    .pipe-step {
        background-color: #111827;
        border: 1px solid #1f2937;
        border-top: 3px solid #38bdf8;
        border-radius: 8px;
        padding: 10px 12px;
    }
    .pipe-step.danger {
        border-top-color: #ef4444;
    }
    .pipe-num {
        font-size: 11px;
        font-weight: 700;
        color: #38bdf8;
        text-transform: uppercase;
    }
    .pipe-step.danger .pipe-num {
        color: #f87171;
    }
    .pipe-name {
        font-size: 13px;
        font-weight: 700;
        color: #f3f4f6;
        margin-top: 2px;
    }
    .pipe-desc {
        font-size: 11px;
        color: #9ca3af;
        margin-top: 2px;
    }

    .ok-banner {
        background-color: rgba(16, 185, 129, 0.12);
        border-left: 4px solid #10b981;
        border-radius: 6px;
        padding: 12px 14px;
        margin: 8px 0;
    }
    .alert-banner {
        background-color: rgba(239, 68, 68, 0.14);
        border-left: 4px solid #ef4444;
        border-radius: 6px;
        padding: 12px 14px;
        margin: 8px 0;
    }

    button[data-baseweb="tab"] {
        font-weight: 600 !important;
        color: #9ca3af !important;
    }
    button[data-baseweb="tab"][aria-selected="true"] {
        color: #38bdf8 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

SCENARIO_PRESETS: dict[str, dict[str, str]] = {
    "Former Employee Login (Rohan Menon - Left 30 Jun 2026)": {
        "user": "rohan.menon",
        "hr": "Terminated (30 Jun 2026)",
        "ip": "172.16.44.19",
    },
    "Traveling Network Contractor (Colin Lawson - New City IP)": {
        "user": "colin.lawson",
        "hr": "Active",
        "ip": "49.207.112.88",
    },
    "External Attacker Using Compromised Credentials": {
        "user": "farah.dsouza",
        "hr": "Active",
        "ip": "185.220.101.42",
    },
    "Third-Party API Key Outside Approved Subnet": {
        "user": "KEY-TB-902 (TallyBridge)",
        "hr": "N/A (Service Key)",
        "ip": "91.132.44.10",
    },
}

HR_OPTIONS = ["Active", "Terminated (30 Jun 2026)", "N/A (Service Key)"]
DEMO_OTP = "482910"
DEFAULT_TRUSTED_IPS: dict[str, list[str]] = {"colin.lawson": ["172.16.10.5"]}


def _utc_and_ist_stamp(dt: datetime | None = None) -> tuple[str, str]:
    now_utc = (dt or datetime.now(timezone.utc)).astimezone(timezone.utc)
    now_ist = now_utc.astimezone(IST)
    return (
        now_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        now_ist.strftime("%Y-%m-%d %H:%M:%S IST"),
    )


def _format_geo(geo: Any) -> str:
    if isinstance(geo, dict):
        city = geo.get("city") or "Unknown City"
        isp = geo.get("isp") or "Unknown ISP"
        return f"{city} ({isp})"
    return str(geo or "Unknown Location")


def _normalize_report(raw: Any) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    raw_summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    summary = {
        "total_server_alerts": int(raw_summary.get("total_server_alerts", 0) or 0),
        "owner_notifications_sent": int(raw_summary.get("owner_notifications_sent", 0) or 0),
        "ip_challenges_logged": int(raw_summary.get("ip_challenges_logged", 0) or 0),
        "benign_operations_suppressed": int(raw_summary.get("benign_operations_suppressed", 0) or 0),
    }
    broadcasts = data.get("server_broadcasts")
    challenges = data.get("ip_challenges")
    return {
        "summary": summary,
        "server_broadcasts": broadcasts if isinstance(broadcasts, list) else [],
        "ip_challenges": challenges if isinstance(challenges, list) else [],
    }


def _collect_key_scan_alerts(root_dir: str = ".") -> list[dict[str, Any]]:
    now_utc, now_ist = _utc_and_ist_stamp()
    formatted: list[dict[str, Any]] = []
    for bcast in run_key_leak_scan(root_dir=root_dir, include_scratch=True):
        formatted.append(
            {
                "timestamp_utc": now_utc,
                "timestamp_ist": now_ist,
                "severity": bcast.get("severity", "CRITICAL"),
                "actor": bcast.get("actor", "local_workspace_scanner"),
                "ip_address": bcast.get("ip_address", "127.0.0.1"),
                "location": bcast.get("geolocation", "Local Workstation"),
                "reason": f"[{bcast.get('category')}] {bcast.get('evidence_ids')} — {bcast.get('action_taken')}",
                "broadcast": bcast.get("action_taken", "KEY QUARANTINED + OWNER NOTIFIED"),
            }
        )
    return formatted


def _load_persisted_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        try:
            data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


def _save_persisted_state() -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "live_alerts": st.session_state.get("live_alerts", []),
        "live_accepted": st.session_state.get("live_accepted", []),
        "live_challenges": st.session_state.get("live_challenges", 0),
        "live_benign": st.session_state.get("live_benign", 0),
        "verified_ips": st.session_state.get("verified_ips", DEFAULT_TRUSTED_IPS),
        "blocked_vectors": st.session_state.get("blocked_vectors", {}),
    }
    STATE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _ensure_state() -> None:
    saved = _load_persisted_state()
    initial_report = _normalize_report(None)
    if PROOF_PACK_PATH.exists():
        try:
            initial_report = _normalize_report(json.loads(PROOF_PACK_PATH.read_text(encoding="utf-8")))
        except Exception:
            pass

    defaults: dict[str, Any] = {
        "live_alerts": saved.get("live_alerts", []),
        "key_scan_alerts": [],
        "live_accepted": saved.get("live_accepted", []),
        "live_challenges": int(saved.get("live_challenges", 0) or 0),
        "live_benign": int(saved.get("live_benign", 0) or 0),
        "challenge_active": False,
        "pending_login": {},
        "verified_ips": saved.get("verified_ips", {k: list(v) for k, v in DEFAULT_TRUSTED_IPS.items()}),
        "auth_feedback": None,
        "sidebar_feedback": None,
        "dialog_open": False,
        "active_alert": None,
        "active_recipients": "",
        "last_transit_sim": None,
        "last_suite_results": [],
        "blocked_vectors": saved.get("blocked_vectors", {}),
        "report": initial_report,
    }
    for key, val in defaults.items():
        st.session_state.setdefault(key, val)


_ensure_state()


def reset_challenge() -> None:
    st.session_state["challenge_active"] = False
    st.session_state["pending_login"] = {}


def record_accepted_event(actor: str, ip: str, geo: Any, method: str, details: str) -> None:
    now_utc, now_ist = _utc_and_ist_stamp()
    st.session_state["live_benign"] += 1
    st.session_state["live_accepted"].insert(
        0,
        {
            "timestamp_utc": now_utc,
            "timestamp_ist": now_ist,
            "status": "ACCEPTED",
            "actor": actor,
            "ip_address": ip,
            "location": _format_geo(geo),
            "verification": method,
            "details": details,
        },
    )
    _save_persisted_state()


def on_run_correlation() -> None:
    folder_path = st.session_state.get("data_dir_input", "./data").strip() or "./data"
    if os.path.isdir(folder_path):
        report_raw = run_full_security_pipeline(data_dir=folder_path, output_dir="./output", root_dir=".")
        st.session_state["report"] = _normalize_report(report_raw)
        st.session_state["key_scan_alerts"] = _collect_key_scan_alerts(".")
        st.session_state["sidebar_feedback"] = (
            "success",
            f"Correlation + key scan complete for '{folder_path}'. Updated ./output/proof_pack.json.",
        )
    else:
        st.session_state["sidebar_feedback"] = ("error", f"Folder '{folder_path}' not found.")


def on_reset_all() -> None:
    cleanup_scratch_test_files(".")
    clear_nonce_store()
    st.session_state["live_alerts"] = []
    st.session_state["key_scan_alerts"] = []
    st.session_state["live_accepted"] = []
    st.session_state["live_challenges"] = 0
    st.session_state["live_benign"] = 0
    st.session_state["verified_ips"] = {k: list(v) for k, v in DEFAULT_TRUSTED_IPS.items()}
    st.session_state["auth_feedback"] = None
    st.session_state["last_transit_sim"] = None
    st.session_state["last_suite_results"] = []
    st.session_state["blocked_vectors"] = {}
    st.session_state["dialog_open"] = False
    st.session_state["active_alert"] = None
    reset_challenge()
    if STATE_FILE.exists():
        try:
            STATE_FILE.unlink()
        except OSError:
            pass
    st.session_state["sidebar_feedback"] = (
        "info",
        "Persisted state, nonce store, scratch files, alerts, and trusted IP list reset.",
    )


def queue_lockdown(
    severity: str,
    actor: str,
    ip: str,
    geo: Any,
    reason: str,
    broadcast: str,
    recipients: str,
    timestamp_utc: str | None = None,
    timestamp_ist: str | None = None,
    open_modal: bool = True,
) -> None:
    default_utc, default_ist = _utc_and_ist_stamp()
    ts_utc = timestamp_utc or default_utc
    ts_ist = timestamp_ist or default_ist
    alert_obj = {
        "timestamp_utc": ts_utc,
        "timestamp_ist": ts_ist,
        "severity": severity,
        "actor": actor,
        "ip_address": ip,
        "location": _format_geo(geo),
        "reason": reason,
        "broadcast": broadcast,
    }
    st.session_state["live_alerts"].insert(0, alert_obj)
    if open_modal:
        st.session_state["active_alert"] = alert_obj
        st.session_state["active_recipients"] = recipients
        st.session_state["dialog_open"] = True
    st.session_state["auth_feedback"] = ("error", f"🚨 LOCKDOWN TRIGGERED for `{actor}` ({ip}) — {reason}")
    _save_persisted_state()


def _sign_test_request(
    key: str, secret: str, method: str, path: str, timestamp_epoch: int, nonce: str, body: bytes
) -> str:
    canonical = (
        f"{method.upper()}\n{path}\n{timestamp_epoch}\n{nonce}\n".encode("utf-8")
        + hashlib.sha256(body).digest()
    )
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def _build_combined_report(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "batch_proof_pack": report,
        "interactive_session": {
            "live_alerts": st.session_state["live_alerts"],
            "key_scan_alerts": st.session_state["key_scan_alerts"],
            "live_accepted": st.session_state["live_accepted"],
            "blocked_vectors_verified": st.session_state["blocked_vectors"],
            "verified_ips": st.session_state["verified_ips"],
        },
    }


def _filter_records(records: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    needle = query.strip().lower()
    if not needle:
        return records
    return [row for row in records if needle in json.dumps(row, default=str).lower()]


def render_correlation_summary(broadcasts: list[dict[str, Any]]) -> None:
    total_events = len(broadcasts)
    locked_count = sum(
        1
        for item in broadcasts
        if isinstance(item, dict)
        and str(item.get("status", item.get("action", ""))).strip().upper()
        in {"LOCKED", "TERMINATED", "BLOCKED", "SERVER_LOCKDOWN"}
    )
    flagged_count = sum(
        1
        for item in broadcasts
        if isinstance(item, dict)
        and str(item.get("status", item.get("severity", ""))).strip().upper()
        in {"FLAGGED", "HIGH", "CRITICAL", "WARNING"}
    )
    c1, c2, c3 = st.columns(3)
    c1.metric("Correlated Broadcasts", total_events)
    c2.metric("Flagged / High-Risk", flagged_count)
    c3.metric("Server Locks / Blocks", locked_count)


@st.dialog("🚨 CRITICAL CYBER SECURITY ALERT — SERVER LOCKDOWN", width="large")
def show_cyber_alert_modal(alert: dict[str, Any], recipients: str) -> None:
    st.markdown(
        """
        <div style="background-color:#3b0d0d; border:2px solid #ef4444; border-radius:8px; padding:16px; margin-bottom:14px;">
            <h3 style="color:#f87171; margin:0 0 6px 0;">⚠️ INTRUSION / POLICY VIOLATION INTERCEPTED</h3>
            <p style="color:#fecaca; margin:0; font-size:14px;">
                Automated Zero-Trust containment has been executed across all Harbor &amp; Finch nodes.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_a, col_b, col_c = st.columns(3)
    col_a.metric("Threat Severity", alert.get("severity", "CRITICAL"))
    col_b.metric("Timestamp (UTC)", str(alert.get("timestamp_utc", "")).replace(" UTC", ""))
    col_c.metric("Timestamp (IST)", str(alert.get("timestamp_ist", "")).replace(" IST", ""))

    st.markdown(
        f"""
        | Incident Field | Captured Telemetry |
        | :--- | :--- |
        | **Target / Actor** | `{alert.get('actor', 'unknown')}` |
        | **Source IP Address** | `{alert.get('ip_address', 'unknown')}` |
        | **Resolved Geolocation** | `{alert.get('location', 'unknown')}` |
        | **Trigger Reason** | {alert.get('reason', 'Policy violation')} |
        | **Containment Action** | **{alert.get('broadcast', 'LOCKDOWN')}** |
        | **Owner Alert Dispatched To** | `{recipients}` |
        """
    )

    st.error(
        "📡 **Company-Wide Server Broadcast Active:** LedgerOne, HelpDeskr, and BlueVault sessions terminated for this identity."
    )

    if st.button("Acknowledge & Log Incident", type="primary", width="stretch", key="ack_alert_btn"):
        st.session_state["dialog_open"] = False
        st.session_state["active_alert"] = None
        st.rerun()


# Sidebar Controls
st.sidebar.header("⚙️ SOC Control Panel")
st.sidebar.text_input("Evidence Folder Path", value="./data", key="data_dir_input")
owner_email = st.sidebar.text_input(
    "System Owner & Security Admin Target",
    value="dev.raghavan@harborfinch.in, aditi.kapoor@harborfinch.in",
)

st.sidebar.button(
    "🚀 Run Full Correlation + Key Scan",
    type="primary",
    width="stretch",
    key="sidebar_run_btn",
    on_click=on_run_correlation,
)

st.sidebar.button(
    "🧹 Reset Persisted State & Nonces",
    width="stretch",
    key="sidebar_reset_btn",
    on_click=on_reset_all,
)

with st.sidebar.expander("📌 Trusted IP Allowlist Manager"):
    target_user = st.text_input("Actor / Username", value="colin.lawson", key="allowlist_user")
    new_trusted_ip = st.text_input("Add Trusted IPv4/IPv6", placeholder="e.g. 172.16.10.22", key="allowlist_ip")
    if st.button("➕ Trust IP", key="add_trusted_ip_btn", width="stretch"):
        u = target_user.strip()
        ip_val = new_trusted_ip.strip()
        if u and ip_val:
            st.session_state["verified_ips"].setdefault(u, [])
            if ip_val not in st.session_state["verified_ips"][u]:
                st.session_state["verified_ips"][u].append(ip_val)
            _save_persisted_state()
            st.session_state["sidebar_feedback"] = ("success", f"Added `{ip_val}` to trusted IPs for `{u}`.")
            st.rerun()
    st.json(st.session_state["verified_ips"])

if st.session_state["sidebar_feedback"]:
    kind, msg = st.session_state["sidebar_feedback"]
    getattr(st.sidebar, kind)(msg)

report = _normalize_report(st.session_state.get("report"))
combined_live_alerts = list(st.session_state["live_alerts"]) + list(st.session_state["key_scan_alerts"])

live_count = len(combined_live_alerts)
accepted_count = len(st.session_state["live_accepted"])
total_lockdowns = report["summary"]["total_server_alerts"] + live_count
total_owner_alerts = report["summary"]["owner_notifications_sent"] + live_count
total_challenges = report["summary"]["ip_challenges_logged"] + st.session_state["live_challenges"]
total_benign = report["summary"]["benign_operations_suppressed"] + st.session_state["live_benign"]

# Hero Command Header
status_badge = (
    f'<span class="soc-badge-alert">🚨 ACTIVE LOCKDOWN ({total_lockdowns})</span>'
    if total_lockdowns > 0
    else '<span class="soc-badge-ok">● ZERO-TRUST ENGINE ARMED</span>'
)

st.markdown(
    f"""
    <div class="soc-banner">
        <div>
            <p class="soc-title">🛡️ Harbor &amp; Finch — Zero-Trust SSO, IP &amp; API Key Defense</p>
            <p class="soc-subtitle">CRIMEATHON’26 Case CR-26-047 &nbsp;|&nbsp; Persistent Nonce Store + HR Offboarding + 1-Attempt IP Gate + Key Guard</p>
        </div>
        <div>{status_badge}</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# KPI Cards
c1, c2, c3, c4 = st.columns(4)
c1.metric("🚨 Server-Wide Lockdowns", total_lockdowns)
c2.metric("📩 Owner IP/Geo Alerts Sent", total_owner_alerts)
c3.metric("🔐 1-Attempt IP Challenges", total_challenges)
c4.metric("✅ Benign Events Suppressed", total_benign)

st.write("")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔐 Interactive SSO Login & 1-Attempt IP Gate",
    f"🚨 Live Server & Owner Notification Feed ({live_count})",
    f"✅ Accepted & Verified Access ({accepted_count})",
    "📊 Full Case Evidence Correlation (E01–E19)",
    "🦠 API Key & Virus/Transit Defense",
])

with tab1:
    st.markdown(
        """
        <div class="pipeline-grid">
            <div class="pipe-step">
                <div class="pipe-num">Stage 01</div>
                <div class="pipe-name">Staff / API Auth</div>
                <div class="pipe-desc">SSO E03 &amp; Service Key Ingress</div>
            </div>
            <div class="pipe-step">
                <div class="pipe-num">Stage 02</div>
                <div class="pipe-name">HR Roster Sync</div>
                <div class="pipe-desc">Instant E14 Offboarding Check</div>
            </div>
            <div class="pipe-step">
                <div class="pipe-num">Stage 03</div>
                <div class="pipe-name">IP &amp; Subnet Check</div>
                <div class="pipe-desc">Approved CIDR &amp; Trusted IP List</div>
            </div>
            <div class="pipe-step">
                <div class="pipe-num">Stage 04</div>
                <div class="pipe-name">1-Attempt MFA Gate</div>
                <div class="pipe-desc">Single Challenge for New IPs</div>
            </div>
            <div class="pipe-step danger">
                <div class="pipe-num">Stage 05</div>
                <div class="pipe-name">Auto-Containment</div>
                <div class="pipe-desc">Server Lockdown + Owner Alert</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.session_state["auth_feedback"]:
        fb_kind, fb_msg = st.session_state["auth_feedback"]
        getattr(st, fb_kind)(fb_msg)

    col1, col2 = st.columns(2, gap="large")

    with col1:
        with st.container(border=True):
            st.markdown("#### 🔑 Step 1: Simulate SSO Sign-In Request")
            st.caption("Select an attack/travel preset or customize parameters to test the defense gate.")

            preset = st.selectbox(
                "Select Scenario Preset",
                list(SCENARIO_PRESETS.keys()),
                on_change=reset_challenge,
            )
            selected = SCENARIO_PRESETS[preset]

            actor_id = st.text_input("SSO Username / API Key", value=selected["user"])

            sub_c1, sub_c2 = st.columns(2)
            with sub_c1:
                hr_state = st.selectbox("HR Roster Status (E14)", HR_OPTIONS, index=HR_OPTIONS.index(selected["hr"]))
            with sub_c2:
                source_ip = st.text_input("Incoming IP Address", value=selected["ip"])

            st.write("")
            if st.button("⚡ Sign In via SSO / Verify Request", type="primary", width="stretch", key="sso_signin_btn"):
                clean_ip = source_ip.strip()
                clean_actor = actor_id.strip()
                geo = resolve_ip_location(clean_ip)

                if hr_state == "N/A (Service Key)" or clean_actor.upper().startswith("KEY-"):
                    reset_challenge()
                    if is_approved_api_ip(clean_ip):
                        record_accepted_event(
                            actor=clean_actor,
                            ip=clean_ip,
                            geo=geo,
                            method="Approved Subnet Policy",
                            details="Service key inside approved CIDR; benign event suppressed.",
                        )
                        st.session_state["auth_feedback"] = (
                            "success",
                            f"✅ API Key `{clean_actor}` verified inside approved subnet (`{clean_ip}`). Logged under Accepted Access.",
                        )
                    else:
                        queue_lockdown(
                            severity="CRITICAL",
                            actor=clean_actor,
                            ip=clean_ip,
                            geo=geo,
                            reason="Third-Party API Key outside 172.16.0.0/16 & 10.20.4.0/24",
                            broadcast="COMPANY SERVER LOCKDOWN + KEY REVOKED + OWNER NOTIFIED",
                            recipients=owner_email,
                        )
                elif hr_state.startswith("Terminated"):
                    reset_challenge()
                    queue_lockdown(
                        severity="CRITICAL",
                        actor=clean_actor,
                        ip=clean_ip,
                        geo=geo,
                        reason="Post-Offboarding SSO Access Attempt (E14 Terminated)",
                        broadcast="COMPANY SERVER LOCKDOWN + KIOSK/SSO SESSION KILLED + OWNER NOTIFIED",
                        recipients=owner_email,
                    )
                else:
                    known_ips = st.session_state["verified_ips"].get(clean_actor, [])
                    if clean_ip in known_ips:
                        reset_challenge()
                        record_accepted_event(
                            actor=clean_actor,
                            ip=clean_ip,
                            geo=geo,
                            method="Trusted Known IP",
                            details="Active employee signed in from previously verified IP.",
                        )
                        st.session_state["auth_feedback"] = (
                            "success",
                            f"✅ **SSO ACCESS GRANTED:** `{clean_actor}` signed in from recognized IP `{clean_ip}` ({_format_geo(geo)}).",
                        )
                    else:
                        ts_utc, ts_ist = _utc_and_ist_stamp()
                        st.session_state["challenge_active"] = True
                        st.session_state["live_challenges"] += 1
                        st.session_state["pending_login"] = {
                            "user": clean_actor,
                            "ip": clean_ip,
                            "geo": geo,
                            "time_utc": ts_utc,
                            "time_ist": ts_ist,
                        }
                        _save_persisted_state()
                        st.session_state["auth_feedback"] = (
                            "warning",
                            f"⚠️ **1-ATTEMPT MFA REQUIRED:** `{clean_actor}` requested SSO access from new IP `{clean_ip}` ({_format_geo(geo)}).",
                        )
                st.rerun()

    with col2:
        with st.container(border=True):
            st.markdown("#### 🛡️ Step 2: 1-Attempt New IP Verification Gate")
            if st.session_state["challenge_active"]:
                pending = st.session_state["pending_login"]
                st.warning(
                    f"⚠️ **UNRECOGNIZED IP DETECTED FOR `{pending['user']}`**\n\n"
                    f"- **New IP:** `{pending['ip']}`\n"
                    f"- **Resolved Location:** `{_format_geo(pending['geo'])}`\n"
                    f"- **Policy:** Active staff get **1 attempt** to confirm identity before lockdown."
                )

                with st.form("mfa_gate_form", clear_on_submit=True):
                    otp_input = st.text_input(
                        f"Enter 6-Digit SSO MFA Code (Valid demo code: `{DEMO_OTP}`)",
                        type="password",
                        placeholder="••••••",
                    )
                    submitted = st.form_submit_button("🔒 Submit Verification Attempt (1/1)", type="primary", width="stretch")

                    if submitted:
                        if otp_input.strip() == DEMO_OTP:
                            st.session_state["verified_ips"].setdefault(pending["user"], [])
                            if pending["ip"] not in st.session_state["verified_ips"][pending["user"]]:
                                st.session_state["verified_ips"][pending["user"]].append(pending["ip"])
                            record_accepted_event(
                                actor=pending["user"],
                                ip=pending["ip"],
                                geo=pending["geo"],
                                method="1/1 MFA IP Challenge Passed",
                                details="Identity verified on first attempt; IP persisted to trusted list.",
                            )
                            reset_challenge()
                            st.session_state["auth_feedback"] = (
                                "success",
                                f"✅ **1/1 ATTEMPT PASSED:** Identity confirmed for `{pending['user']}`! "
                                f"IP `{pending['ip']}` ({_format_geo(pending['geo'])}) added to trusted list.",
                            )
                        else:
                            reset_challenge()
                            queue_lockdown(
                                severity="HIGH",
                                actor=pending["user"],
                                ip=pending["ip"],
                                geo=pending["geo"],
                                reason="Failed 1/1 IP Verification Challenge on SSO",
                                broadcast="ACCOUNT LOCKED + COMPANY SERVER ALERT + OWNER NOTIFIED",
                                recipients=owner_email,
                                timestamp_utc=pending.get("time_utc"),
                                timestamp_ist=pending.get("time_ist"),
                            )
                        st.rerun()
            else:
                st.caption("Adaptive Challenge Status: **Standby**")
                st.info(
                    "🟢 **Gate Armed & Monitoring**\n\n"
                    "When an **Active** employee signs in from an unrecognized IP address (e.g., *Colin Lawson* traveling), "
                    "the **1-Attempt MFA Challenge** will dynamically lock this panel until verified or blocked."
                )
                trusted_str = ", ".join(st.session_state["verified_ips"].get("colin.lawson", []))
                st.markdown(f"**Currently Trusted IPs (`colin.lawson`):** `{trusted_str}`")

with tab2:
    st.subheader("🚨 Real-Time Company Server Broadcasts & Owner Notifications")
    if combined_live_alerts:
        alert_filter = st.text_input("Filter live alerts (actor, IP, reason, city)", key="filter_live_alerts")
        filtered_alerts = _filter_records(combined_live_alerts, alert_filter)
        st.dataframe(pd.DataFrame(filtered_alerts), width="stretch")

        exp_c1, exp_c2 = st.columns(2)
        with exp_c1:
            st.download_button(
                "⬇️ Export Live Alerts (JSON)",
                data=json.dumps(filtered_alerts, indent=2),
                file_name="live_cyber_alerts.json",
                mime="application/json",
                key="export_alerts_btn",
            )
        with exp_c2:
            st.download_button(
                "⬇️ Export Combined Defense Report (Batch + Live)",
                data=json.dumps(_build_combined_report(report), indent=2),
                file_name="combined_defense_report.json",
                mime="application/json",
                key="export_combined_tab2_btn",
            )
    else:
        st.info("No live alerts triggered yet. Test a failed 1-attempt login, terminated user, or key/transit attack.")

with tab3:
    st.subheader("✅ Correct & Accepted Access Log")
    st.caption("Shows active logins from known IPs, approved service API calls, new IPs that passed the 1/1 MFA gate, and valid signed API requests.")
    if st.session_state["live_accepted"]:
        acc_filter = st.text_input("Filter accepted events (actor, IP, method)", key="filter_live_accepted")
        filtered_accepted = _filter_records(st.session_state["live_accepted"], acc_filter)
        st.dataframe(pd.DataFrame(filtered_accepted), width="stretch")
        st.download_button(
            "⬇️ Export Accepted Log (JSON)",
            data=json.dumps(filtered_accepted, indent=2),
            file_name="accepted_access_log.json",
            mime="application/json",
            key="export_accepted_btn",
        )
    else:
        st.info("No accepted or 1/1-verified events logged yet. Approve a 1/1 MFA challenge or sign in from a trusted IP.")

with tab4:
    st.subheader("📊 Batch Evidence Correlation Results (E01–E19)")
    action_col, export_col1, export_col2 = st.columns([1.2, 1, 1.2])
    with action_col:
        st.button(
            "🚀 Run Correlation on ./data",
            type="primary",
            key="tab4_run_btn",
            on_click=on_run_correlation,
        )
    with export_col1:
        if PROOF_PACK_PATH.is_file():
            st.download_button(
                label="⬇️ Download proof_pack.json",
                data=PROOF_PACK_PATH.read_text(encoding="utf-8"),
                file_name="proof_pack.json",
                mime="application/json",
                key="tab4_download_proof_btn",
            )
    with export_col2:
        st.download_button(
            label="⬇️ Download Combined Report (Batch + Live)",
            data=json.dumps(_build_combined_report(report), indent=2),
            file_name="combined_defense_report.json",
            mime="application/json",
            key="tab4_download_combined_btn",
        )

    broadcasts = report["server_broadcasts"]
    if broadcasts:
        render_correlation_summary(broadcasts)
        corr_query = st.text_input("Filter correlated events (request_id, actor, IP, status)", key="filter_corr_query")
        filtered_broadcasts = _filter_records(broadcasts, corr_query)
        st.dataframe(pd.DataFrame(filtered_broadcasts), width="stretch")

        with st.expander("🔍 Inspect Raw Correlated Payload"):
            st.json(filtered_broadcasts[:25])
    else:
        st.info("Place E01–E19 CSV/JSON files in `./data` and click 'Run Correlation on ./data' or use the sidebar.")

with tab5:
    st.subheader("🦠 API Key & Malware / Transit Defense")
    st.caption(
        "Protects API keys at rest and in transit against infostealer file scraping, replay attacks, URL leaks, and HTTP/MitM downgrades. "
        "Note: this secures API keys, requests, and project files—pair with OS antivirus/EDR for host-level malware removal."
    )

    blocked_map = st.session_state.get("blocked_vectors", {})
    matrix_rows = [
        {
            "Threat / Malware Vector": "Infostealer Plaintext Key Theft",
            "How It Is Blocked": "At-rest pattern + entropy scan & redaction",
            "Defense Code": "PLAIN_TEXT_KEY_AT_REST",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("PLAIN_TEXT_KEY_AT_REST") else "🟢 Armed",
        },
        {
            "Threat / Malware Vector": "Replay Attack (Captured Request)",
            "How It Is Blocked": "Persistent SQLite WAL nonce store",
            "Defense Code": "REPLAY_NONCE_DETECTED",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("REPLAY_NONCE_DETECTED") else "🟢 Armed",
        },
        {
            "Threat / Malware Vector": "Stale / Delayed Packet Replay",
            "How It Is Blocked": "30-second timestamp freshness window",
            "Defense Code": "STALE_REQUEST",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("STALE_REQUEST") else "🟢 Armed",
        },
        {
            "Threat / Malware Vector": "URL / Log / Extension Key Leak",
            "How It Is Blocked": "Rejects credentials in URL query strings",
            "Defense Code": "KEY_IN_QUERY_STRING",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("KEY_IN_QUERY_STRING") else "🟢 Armed",
        },
        {
            "Threat / Malware Vector": "Packet Sniffer / MitM Downgrade",
            "How It Is Blocked": "Enforces HTTPS & X-Forwarded-Proto trust",
            "Defense Code": "INSECURE_TRANSIT_KEY_EXPOSURE",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("INSECURE_TRANSIT_KEY_EXPOSURE") else "🟢 Armed",
        },
        {
            "Threat / Malware Vector": "In-Transit Payload Tampering",
            "How It Is Blocked": "HMAC-SHA256 over method, path, ts, nonce & body",
            "Defense Code": "TAMPERED_IN_TRANSIT",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("TAMPERED_IN_TRANSIT") else "🟢 Armed",
        },
        {
            "Threat / Malware Vector": "Forged or Revoked API Key",
            "How It Is Blocked": "Constant-time SHA-256 digest comparison",
            "Defense Code": "INVALID_API_KEY",
            "Status": "🛡️ Blocked in Test" if blocked_map.get("INVALID_API_KEY") else "🟢 Armed",
        },
    ]
    st.markdown("#### 🛡️ Threat-to-Defense Blocking Matrix")
    st.dataframe(pd.DataFrame(matrix_rows), width="stretch", hide_index=True)

    st.write("")
    sub_left, sub_right = st.columns(2, gap="large")

    with sub_left:
        with st.container(border=True):
            st.markdown("#### 🔍 At-Rest Key & Infostealer File Scan")
            st.write("Scans workspace files for plaintext tokens/keys while redacting values in reports.")

            b1, b2, b3 = st.columns(3)
            with b1:
                if st.button("🔎 Scan Now", type="primary", width="stretch", key="scan_now_tab5"):
                    st.session_state["key_scan_alerts"] = _collect_key_scan_alerts(".")
                    st.rerun()
            with b2:
                if st.button("🧪 Dummy Key", width="stretch", key="add_dummy_tab5"):
                    SCRATCH_TEST_FILE.write_text("DEMO_KEY=AIzaSyDummyTestKey12345678901234567890\n", encoding="utf-8")
                    st.session_state["key_scan_alerts"] = _collect_key_scan_alerts(".")
                    st.session_state["blocked_vectors"]["PLAIN_TEXT_KEY_AT_REST"] = True
                    _save_persisted_state()
                    st.rerun()
            with b3:
                if st.button("🧹 Clean Dummy", width="stretch", key="del_dummy_tab5"):
                    cleanup_scratch_test_files(".")
                    st.session_state["key_scan_alerts"] = _collect_key_scan_alerts(".")
                    st.rerun()

            leaks = scan_workspace_for_leaked_keys(".")
            if leaks:
                st.session_state["blocked_vectors"]["PLAIN_TEXT_KEY_AT_REST"] = True
                _save_persisted_state()
                st.error(f"Detected {len(leaks)} plaintext credential pattern(s) (redacted):")
                st.dataframe(pd.DataFrame(leaks), width="stretch")
            else:
                st.success("No plaintext API keys or token patterns detected in workspace files.")

    with sub_right:
        with st.container(border=True):
            st.markdown("#### ⚡ Transit, Replay & MitM Simulator")
            st.write("Tests `validate_signed_request_with_nonce` individually or runs all 7 cases in one click.")

            enforce_https_flag = st.toggle("Require HTTPS", value=True, key="tab5_enforce_https")
            log_blocked_flag = st.toggle("Record Blocked Attacks as Alerts", value=True, key="tab5_log_blocked")

            def _build_cases() -> dict[str, tuple[str, str, int, str, bytes, str, str, dict[str, str]]]:
                t_key = "demo-api-key-123"
                t_secret = "demo-hmac-secret-456"
                c_body = json.dumps({"action": "verify_access", "status": "ok"}, separators=(",", ":")).encode("utf-8")
                now_epoch = int(time.time())
                s_nonce = uuid.uuid4().hex
                s_sig = _sign_test_request(t_key, t_secret, "POST", "/api/v1/verify", now_epoch, s_nonce, c_body)

                stale_ts = now_epoch - 120
                stale_nonce = uuid.uuid4().hex
                stale_sig = _sign_test_request(t_key, t_secret, "POST", "/api/v1/verify", stale_ts, stale_nonce, c_body)

                bad_key_nonce = uuid.uuid4().hex
                bad_key_sig = _sign_test_request(t_key, t_secret, "POST", "/api/v1/verify", now_epoch, bad_key_nonce, c_body)

                return {
                    "1. Valid Signed HTTPS + Unique Nonce": (t_key, "", now_epoch, s_nonce, c_body, s_sig, "https", {"X-Forwarded-Proto": "https"}),
                    "2. Replay Attack (Reused Nonce)": (t_key, "", now_epoch, s_nonce, c_body, s_sig, "https", {"X-Forwarded-Proto": "https"}),
                    "3. Stale Timestamp (now - 120s)": (t_key, "", stale_ts, stale_nonce, c_body, stale_sig, "https", {"X-Forwarded-Proto": "https"}),
                    "4. Key Leaked in URL (?api_key=...)": (t_key, "api_key=exposed_url_secret", now_epoch, uuid.uuid4().hex, c_body, "", "https", {"X-Forwarded-Proto": "https"}),
                    "5. Plaintext HTTP / Protocol Downgrade": (t_key, "", now_epoch, uuid.uuid4().hex, c_body, "", "http", {"X-Forwarded-Proto": "http"}),
                    "6. Tampered Payload Body": (t_key, "", now_epoch, uuid.uuid4().hex, b'{"action":"verify_access","status":"tampered"}', "", "https", {"X-Forwarded-Proto": "https"}),
                    "7. Invalid / Forged API Key": ("wrong-or-revoked-key", "", now_epoch, bad_key_nonce, c_body, bad_key_sig, "https", {"X-Forwarded-Proto": "https"}),
                }

            def _execute_case(
                case_name: str,
                params: tuple[str, str, int, str, bytes, str, str, dict[str, str]],
                log_alert: bool,
            ) -> dict[str, Any]:
                t_key = "demo-api-key-123"
                t_secret = "demo-hmac-secret-456"
                exp_hash = hashlib.sha256(t_key.encode("utf-8")).hexdigest()
                c_body = json.dumps({"action": "verify_access", "status": "ok"}, separators=(",", ":")).encode("utf-8")

                k_val, q_str, ts_val, n_val, b_val, preset_sig, scheme_val, hdr_val = params
                sig_val = preset_sig or _sign_test_request(t_key, t_secret, "POST", "/api/v1/verify", ts_val, n_val, c_body)
                ok, code, reason = validate_signed_request_with_nonce(
                    api_key=k_val,
                    expected_key_hash=exp_hash,
                    signing_secret=t_secret,
                    method="POST",
                    path="/api/v1/verify",
                    query_string=q_str,
                    timestamp_epoch=ts_val,
                    nonce=n_val,
                    raw_body=b_val,
                    provided_signature=sig_val,
                    transport_scheme=scheme_val,
                    require_https=enforce_https_flag,
                    headers=hdr_val,
                )
                if ok:
                    record_accepted_event(
                        actor="signed_api_client",
                        ip="127.0.0.1",
                        geo="Local Loopback",
                        method="HTTPS + Persistent Nonce + HMAC",
                        details=reason,
                    )
                else:
                    st.session_state["blocked_vectors"][code] = True
                    _save_persisted_state()
                    if log_alert:
                        queue_lockdown(
                            severity="HIGH",
                            actor="transit_security_guard",
                            ip="198.51.100.42",
                            geo="Simulated Transit Probe",
                            reason=f"[{code}] {case_name} — {reason}",
                            broadcast="REQUEST BLOCKED + KEY GUARD ALERT + OWNER NOTIFIED",
                            recipients=owner_email,
                            open_modal=False,
                        )
                return {"Scenario": case_name, "Allowed": ok, "Code": code, "Detail": reason}

            case_names = [
                "1. Valid Signed HTTPS + Unique Nonce",
                "2. Replay Attack (Reused Nonce)",
                "3. Stale Timestamp (now - 120s)",
                "4. Key Leaked in URL (?api_key=...)",
                "5. Plaintext HTTP / Protocol Downgrade",
                "6. Tampered Payload Body",
                "7. Invalid / Forged API Key",
            ]
            chosen_case = st.selectbox("Select Transit / Malware Attack Case", case_names)

            btn_c1, btn_c2 = st.columns(2)
            with btn_c1:
                if st.button("▶ Run Selected Case", type="primary", width="stretch", key="run_transit_btn"):
                    cases_now = _build_cases()
                    res = _execute_case(chosen_case, cases_now[chosen_case], log_blocked_flag)
                    st.session_state["last_transit_sim"] = res
                    st.rerun()
            with btn_c2:
                if st.button("⚡ Run All 7 Scenarios", width="stretch", key="run_all_transit_btn"):
                    cases_now = _build_cases()
                    suite_out = []
                    for cname in case_names:
                        suite_out.append(_execute_case(cname, cases_now[cname], log_blocked_flag))
                    st.session_state["last_suite_results"] = suite_out
                    st.session_state["last_transit_sim"] = suite_out[-1]
                    st.rerun()

            sim_res = st.session_state.get("last_transit_sim")
            if sim_res:
                if sim_res["Allowed"]:
                    st.markdown(
                        f'<div class="ok-banner"><strong>ALLOWED ({sim_res["Code"]}):</strong> {sim_res["Scenario"]} — {sim_res["Detail"]}</div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div class="alert-banner"><strong>BLOCKED ({sim_res["Code"]}):</strong> {sim_res["Scenario"]} — {sim_res["Detail"]}</div>',
                        unsafe_allow_html=True,
                    )

            if st.session_state.get("last_suite_results"):
                with st.expander("📋 Full 7-Scenario Suite Results", expanded=True):
                    st.dataframe(pd.DataFrame(st.session_state["last_suite_results"]), width="stretch", hide_index=True)

    st.write("")
    with st.expander("🧭 Pre-Demo & Production Hardening Checklist", expanded=False):
        st.dataframe(
            pd.DataFrame(get_runtime_security_posture(require_https=enforce_https_flag, root_dir=".")),
            width="stretch",
            hide_index=True,
        )
        st.markdown(
            """
            * **TLS & Proxy Hardening:** Terminate real TLS (HTTPS) in production and accept `X-Forwarded-Proto` only from trusted reverse proxies.
            * **Secret Management:** Inject real API keys and HMAC signing secrets via environment variables or a secret manager—never hardcode them or export them unredacted.
            * **Host Defense:** Pair this API defense layer with OS-level antivirus/EDR to detect or remove malware executing on endpoints.
            """
        )

if st.session_state["dialog_open"] and st.session_state["active_alert"]:
    show_cyber_alert_modal(st.session_state["active_alert"], st.session_state["active_recipients"])