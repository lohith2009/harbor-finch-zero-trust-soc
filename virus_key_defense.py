import hashlib
import hmac
import math
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

_NONCE_LOCK = threading.Lock()
DEFAULT_NONCE_DB = Path("./.runtime_state/nonce_store.db")

SENSITIVE_QUERY_KEYS = {"api_key", "apikey", "key", "token", "access_token", "secret"}

SKIP_DIRS = {
    ".venv",
    "venv",
    "__pycache__",
    ".git",
    ".pytest_cache",
    "node_modules",
    "output",
    ".runtime_state",
}
SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".pyc",
    ".db",
    ".db-wal",
    ".db-shm",
    ".sqlite",
}
SCRATCH_FILES = {"_dashboard_dummy_key_check.txt", "_test_key_check.txt"}

# Tuned patterns to minimize false positives on normal base64/docs while catching real formats
KEY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Google / Firebase API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    ("OpenAI / Stripe Secret Key", re.compile(r"\bsk-(?:proj-|live-|test-)?[0-9A-Za-z\-_]{20,}\b")),
    ("GitHub Personal Access Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack Bot / User Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{16,}\b")),
    (
        "Credential Assignment (API_KEY / SECRET / TOKEN)",
        re.compile(
            r"(?i)\b(?:api_key|apikey|secret_key|hmac_secret|access_token|auth_token|bearer)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?"
        ),
    ),
]


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def redact_secret(secret_val: str) -> str:
    if len(secret_val) <= 8:
        return "*" * len(secret_val)
    return f"{secret_val[:4]}...{secret_val[-4:]}"


def cleanup_scratch_test_files(root_dir: str = ".") -> list[str]:
    """Removes temporary dummy key test files if left behind."""
    removed: list[str] = []
    base = Path(root_dir).resolve()
    for name in SCRATCH_FILES:
        target = base / name
        if target.exists() and target.is_file():
            try:
                target.unlink()
                removed.append(name)
            except OSError:
                pass
    return removed


def _init_nonce_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS seen_nonces (
            nonce TEXT PRIMARY KEY,
            expires_at REAL NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_seen_nonces_exp ON seen_nonces(expires_at);")
    return conn


def _record_and_check_nonce(
    nonce: str,
    ttl_seconds: int,
    db_path: Path = DEFAULT_NONCE_DB,
) -> bool:
    """
    Persistent SQLite-backed nonce check:
    Returns True if the nonce is fresh and records it; returns False if
    the nonce is invalid or was already seen within ttl_seconds (even across restarts).
    """
    if not nonce or len(nonce) < 8 or len(nonce) > 128:
        return False

    now = time.time()
    expires_at = now + max(ttl_seconds, 1)

    with _NONCE_LOCK:
        with _init_nonce_db(db_path) as conn:
            conn.execute("DELETE FROM seen_nonces WHERE expires_at <= ?", (now,))
            cur = conn.execute(
                "INSERT OR IGNORE INTO seen_nonces (nonce, expires_at) VALUES (?, ?)",
                (nonce, expires_at),
            )
            return cur.rowcount == 1


def clear_nonce_store(db_path: Path = DEFAULT_NONCE_DB) -> None:
    """Clears stored nonces (useful when resetting demo state)."""
    with _NONCE_LOCK:
        if db_path.exists():
            with _init_nonce_db(db_path) as conn:
                conn.execute("DELETE FROM seen_nonces")


def inspect_request_for_sniffing_or_mitm(
    query_string: str,
    transport_scheme: str = "https",
    require_https: bool = True,
    headers: dict[str, str] | None = None,
    trust_forwarded_headers: bool = False,
) -> tuple[bool, str, str]:
    """
    Checks for packet-sniffing / MitM exposure risks:
    - Credentials placed in URL query strings
    - Plaintext HTTP when HTTPS is required
    - Downgraded X-Forwarded-Proto header (only trusted when behind an explicit trusted proxy)
    """
    hdrs = {k.lower(): v.strip() for k, v in (headers or {}).items()}

    if query_string:
        params = parse_qs(query_string, keep_blank_values=True)
        leaked_params = [k for k in params if k.lower() in SENSITIVE_QUERY_KEYS]
        if leaked_params:
            return (
                False,
                "KEY_IN_QUERY_STRING",
                f"Sensitive credential parameter in URL query: {', '.join(leaked_params)}",
            )

    direct_scheme = transport_scheme.lower().strip()
    forwarded_proto = hdrs.get("x-forwarded-proto", "").lower()

    if require_https and direct_scheme != "https":
        return (
            False,
            "INSECURE_TRANSIT_KEY_EXPOSURE",
            f"Blocked plaintext transport ({direct_scheme}); HTTPS required",
        )

    if trust_forwarded_headers and forwarded_proto:
        if require_https and forwarded_proto != "https":
            return (
                False,
                "MITM_PROTOCOL_DOWNGRADE",
                f"Proxy protocol downgrade detected: direct={direct_scheme}, x-forwarded-proto={forwarded_proto}",
            )

    return True, "TRANSIT_OK", "Transport and URL hygiene verified"


def validate_signed_request_with_nonce(
    api_key: str,
    expected_key_hash: str,
    signing_secret: str,
    method: str,
    path: str,
    query_string: str,
    timestamp_epoch: int,
    nonce: str,
    raw_body: bytes,
    provided_signature: str,
    transport_scheme: str = "https",
    require_https: bool = True,
    max_age_seconds: int = 30,
    headers: dict[str, str] | None = None,
    trust_forwarded_headers: bool = True,
    nonce_db_path: Path = DEFAULT_NONCE_DB,
) -> tuple[bool, str, str]:
    """
    Full transit + anti-replay + integrity check binding api_key, method,
    path, timestamp, persistent SQLite nonce, and body hash.
    """
    transit_ok, transit_code, transit_reason = inspect_request_for_sniffing_or_mitm(
        query_string=query_string,
        transport_scheme=transport_scheme,
        require_https=require_https,
        headers=headers,
        trust_forwarded_headers=trust_forwarded_headers,
    )
    if not transit_ok:
        return False, transit_code, transit_reason

    if not api_key:
        return False, "MISSING_API_KEY", "No API key provided"

    actual_hash = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(actual_hash, expected_key_hash):
        return False, "INVALID_API_KEY", "API key digest mismatch"

    now_ts = int(time.time())
    if abs(now_ts - timestamp_epoch) > max_age_seconds:
        return False, "STALE_REQUEST", f"Request age exceeded {max_age_seconds}s window"

    if not _record_and_check_nonce(nonce, ttl_seconds=max_age_seconds, db_path=nonce_db_path):
        return False, "REPLAY_NONCE_DETECTED", "Duplicate or invalid request nonce (persistent store)"

    canonical = (
        f"{method.upper()}\n{path}\n{timestamp_epoch}\n{nonce}\n".encode("utf-8")
        + hashlib.sha256(raw_body).digest()
    )
    expected_sig = hmac.new(
        signing_secret.encode("utf-8"), canonical, hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_sig, provided_signature):
        return False, "TAMPERED_IN_TRANSIT", "HMAC signature mismatch (nonce/body/path integrity failed)"

    return True, "VERIFIED", "HTTPS, key, freshness, persistent nonce, and HMAC signature valid"


def scan_workspace_for_leaked_keys(
    root_dir: str = ".",
    include_scratch: bool = True,
) -> list[dict[str, Any]]:
    """
    Scans text/code files in root_dir for plaintext API keys/tokens,
    returning redacted findings (never raw secrets).
    """
    base_path = Path(root_dir).resolve()
    findings: list[dict[str, Any]] = []

    if not base_path.exists():
        return findings

    for file_path in base_path.rglob("*"):
        if not file_path.is_file():
            continue

        if not include_scratch and file_path.name in SCRATCH_FILES:
            continue

        rel_parts = set(file_path.relative_to(base_path).parts[:-1])
        if rel_parts & SKIP_DIRS:
            continue

        if file_path.suffix.lower() in SKIP_EXTENSIONS:
            continue

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel_name = str(file_path.relative_to(base_path))
        for line_no, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            # Skip regex pattern definitions inside virus_key_defense.py itself
            if rel_name.endswith("virus_key_defense.py") and "re.compile" in stripped:
                continue

            seen_spans: set[tuple[int, int]] = set()
            for label, pattern in KEY_PATTERNS:
                for match in pattern.finditer(line):
                    span = match.span()
                    if span in seen_spans:
                        continue
                    seen_spans.add(span)

                    candidate = match.group(1) if match.lastindex else match.group(0)
                    # Ignore obvious placeholder words
                    if candidate.lower() in {"your_api_key_here", "changeme", "example_token"}:
                        continue

                    entropy = round(_shannon_entropy(candidate), 2)
                    if label.startswith("Credential Assignment") and entropy < 3.2:
                        continue

                    findings.append(
                        {
                            "file": rel_name,
                            "line": line_no,
                            "finding_type": label,
                            "redacted_value": redact_secret(candidate),
                            "entropy": entropy,
                        }
                    )

    return findings


def build_malware_defense_broadcast(
    actor: str,
    ip_address: str,
    geolocation: str,
    category: str,
    detail: str,
    evidence_id: str = "VKD-01",
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": "CRITICAL",
        "category": category,
        "actor": actor,
        "ip_address": ip_address,
        "geolocation": geolocation,
        "evidence_ids": evidence_id,
        "action_taken": f"KEY QUARANTINED + OWNER NOTIFIED ({detail})",
    }


def get_runtime_security_posture(
    require_https: bool = True,
    root_dir: str = ".",
) -> list[dict[str, str]]:
    """Returns pre-demo / production readiness posture checks."""
    base = Path(root_dir).resolve()
    scratch_present = [name for name in SCRATCH_FILES if (base / name).exists()]
    env_key_set = bool(os.getenv("HARBOR_API_KEY") or os.getenv("API_KEY"))

    return [
        {
            "Check": "Scratch Test Files Cleaned",
            "Status": "✅ Clean" if not scratch_present else f"⚠️ Found: {', '.join(scratch_present)}",
            "Guidance": "Remove dummy key files before demos or commits.",
        },
        {
            "Check": "HTTPS Transport Enforcement",
            "Status": "✅ Enforced (require_https=True)" if require_https else "⚠️ Local Dev Mode (HTTP allowed)",
            "Guidance": "Keep require_https=False only on 127.0.0.1; enforce HTTPS over networks.",
        },
        {
            "Check": "Persistent Nonce Replay Store",
            "Status": f"✅ Active ({DEFAULT_NONCE_DB.as_posix()})",
            "Guidance": "SQLite WAL store blocks replay attempts across restarts/workers.",
        },
        {
            "Check": "Environment Secret Injection",
            "Status": "✅ Env Variable Detected" if env_key_set else "ℹ️ Using Demo Test Secret",
            "Guidance": "Load production API keys & HMAC secrets from env vars or a secret manager.",
        },
    ]