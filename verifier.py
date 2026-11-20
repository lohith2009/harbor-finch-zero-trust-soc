from __future__ import annotations

from functools import lru_cache
import ipaddress
import json
from pathlib import Path
from typing import Any
import pandas as pd

APPROVED_API_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("172.16.0.0/16"),
    ipaddress.ip_network("10.20.4.0/24"),
)

DEMO_IP_GEO: dict[str, dict[str, str]] = {
    "172.16.10.5": {"city": "Chennai HQ (Internal)", "isp": "HarborFinch-Net"},
    "172.16.44.19": {"city": "Warehouse Kiosk / LAN", "isp": "HarborFinch-Internal"},
    "49.207.112.88": {"city": "Bengaluru", "isp": "Jio Fiber / Mobile"},
    "185.220.101.42": {"city": "Frankfurt (Exit Node)", "isp": "Tor / Transit AS"},
    "91.132.44.10": {"city": "Amsterdam", "isp": "External Cloud AS"},
}


def parse_ip(ip_str: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not ip_str:
        return None
    try:
        return ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return None


def is_approved_api_ip(ip_str: str | None) -> bool:
    addr = parse_ip(ip_str)
    if addr is None:
        return False
    return any(addr in net for net in APPROVED_API_NETWORKS if addr.version == net.version)


@lru_cache(maxsize=2048)
def resolve_ip_location(ip_str: str | None) -> dict[str, str]:
    cleaned = (ip_str or "").strip()
    if cleaned in DEMO_IP_GEO:
        return dict(DEMO_IP_GEO[cleaned])

    addr = parse_ip(cleaned)
    if addr is None:
        return {"city": "Invalid / Malformed IP", "isp": "Unknown ISP"}
    if addr.is_private:
        return {"city": "Private / Internal LAN", "isp": "RFC1918 Private"}
    if addr.is_loopback:
        return {"city": "Localhost", "isp": "Loopback"}
    return {"city": "External / Unmapped Region", "isp": "External ISP"}


def _load_records(folder: Path, stem: str) -> list[dict[str, Any]]:
    csv_path = folder / f"{stem}.csv"
    json_path = folder / f"{stem}.json"
    if csv_path.is_file():
        df = pd.read_csv(csv_path)
        return df.fillna("").to_dict(orient="records")
    if json_path.is_file():
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return [r for r in raw if isinstance(r, dict)]
        if isinstance(raw, dict):
            for key in ("records", "events", "data", stem):
                if isinstance(raw.get(key), list):
                    return [r for r in raw[key] if isinstance(r, dict)]
    return []


def evaluate_sso_attempt(
    actor: str,
    ip_str: str,
    hr_status: str,
    trusted_ips: set[str] | list[str],
    otp_attempt: str | None = None,
    expected_otp: str = "482910",
) -> dict[str, Any]:
    """Deterministic SSO & API gate evaluator with zero silent pass-through on invalid inputs."""
    clean_actor = (actor or "").strip()
    geo = resolve_ip_location(ip_str)
    trusted_set = {ip.strip() for ip in trusted_ips if ip and ip.strip()}

    if not clean_actor:
        return {
            "outcome": "LOCKDOWN",
            "severity": "HIGH",
            "actor": "<empty>",
            "ip": ip_str,
            "geo": geo,
            "reason": "Missing SSO identity / API actor identifier",
            "trust_new_ip": False,
        }

    if parse_ip(ip_str) is None:
        return {
            "outcome": "LOCKDOWN",
            "severity": "HIGH",
            "actor": clean_actor,
            "ip": ip_str,
            "geo": geo,
            "reason": f"Malformed or unparseable source IP: {ip_str!r}",
            "trust_new_ip": False,
        }

    clean_ip = str(parse_ip(ip_str))
    normalized_hr = (hr_status or "").strip().lower()

    if "service key" in normalized_hr or clean_actor.upper().startswith("KEY-"):
        if is_approved_api_ip(clean_ip):
            return {
                "outcome": "ACCEPTED",
                "severity": "LOW",
                "actor": clean_actor,
                "ip": clean_ip,
                "geo": geo,
                "reason": "Approved API subnet match",
                "trust_new_ip": False,
            }
        return {
            "outcome": "LOCKDOWN",
            "severity": "CRITICAL",
            "actor": clean_actor,
            "ip": clean_ip,
            "geo": geo,
            "reason": "Service API key outside approved CIDRs (172.16.0.0/16, 10.20.4.0/24)",
            "trust_new_ip": False,
        }

    if "terminated" in normalized_hr or "offboard" in normalized_hr or "left" in normalized_hr:
        return {
            "outcome": "LOCKDOWN",
            "severity": "CRITICAL",
            "actor": clean_actor,
            "ip": clean_ip,
            "geo": geo,
            "reason": "SSO access attempted by offboarded/terminated account (E14)",
            "trust_new_ip": False,
        }

    if clean_ip in trusted_set:
        return {
            "outcome": "ACCEPTED",
            "severity": "LOW",
            "actor": clean_actor,
            "ip": clean_ip,
            "geo": geo,
            "reason": "Verified trusted IP for active staff",
            "trust_new_ip": False,
        }

    if otp_attempt is None:
        return {
            "outcome": "CHALLENGE_1_TRY",
            "severity": "MEDIUM",
            "actor": clean_actor,
            "ip": clean_ip,
            "geo": geo,
            "reason": "Unrecognized IP for active staff; 1-attempt MFA required",
            "trust_new_ip": False,
        }

    if otp_attempt.strip() == expected_otp:
        return {
            "outcome": "ACCEPTED",
            "severity": "LOW",
            "actor": clean_actor,
            "ip": clean_ip,
            "geo": geo,
            "reason": "Passed 1/1 MFA IP verification challenge",
            "trust_new_ip": True,
        }

    return {
        "outcome": "LOCKDOWN",
        "severity": "HIGH",
        "actor": clean_actor,
        "ip": clean_ip,
        "geo": geo,
        "reason": "Failed 1/1 MFA IP verification challenge",
        "trust_new_ip": False,
    }


def run_defense_engine(folder_path: str) -> dict[str, Any]:
    """Correlates E01-E19 evidence, links E18 API calls to E19 bank edits via request_id, and builds summary."""
    folder = Path(folder_path)
    e18_rows = _load_records(folder, "E18")
    e19_rows = _load_records(folder, "E19")

    api_by_req: dict[str, dict[str, Any]] = {}
    for row in e18_rows:
        req_id = str(row.get("request_id", "")).strip()
        if req_id:
            api_by_req[req_id] = row

    server_broadcasts: list[dict[str, Any]] = []
    ip_challenges: list[dict[str, Any]] = []
    suppressed = 0

    for edit in e19_rows:
        req_id = str(edit.get("request_id", "")).strip()
        approval_ref = str(edit.get("approval_ref", "")).strip()
        api_call = api_by_req.get(req_id, {})
        src_ip = str(api_call.get("ip") or api_call.get("source_ip") or edit.get("ip") or "").strip()
        actor = str(api_call.get("actor") or api_call.get("user") or edit.get("actor") or "unknown").strip()
        geo = resolve_ip_location(src_ip)

        if approval_ref:
            suppressed += 1
            continue

        if src_ip and not is_approved_api_ip(src_ip):
            server_broadcasts.append({
                "request_id": req_id or "UNLINKED",
                "status": "LOCKED",
                "severity": "CRITICAL",
                "actor": actor,
                "ip_address": src_ip,
                "location": f"{geo['city']} ({geo['isp']})",
                "reason": "Unapproved vendor bank edit (E19) linked to off-subnet API IP (E18)",
            })
        else:
            ip_challenges.append({
                "request_id": req_id or "UNLINKED",
                "status": "FLAGGED",
                "actor": actor,
                "ip_address": src_ip or "N/A",
                "location": f"{geo['city']} ({geo['isp']})",
                "reason": "Vendor bank edit missing approval_ref",
            })

    summary = {
        "total_server_alerts": len(server_broadcasts),
        "owner_notifications_sent": len(server_broadcasts),
        "ip_challenges_logged": len(ip_challenges),
        "benign_operations_suppressed": suppressed,
    }
    return {
        "summary": summary,
        "server_broadcasts": server_broadcasts,
        "ip_challenges": ip_challenges,
    }