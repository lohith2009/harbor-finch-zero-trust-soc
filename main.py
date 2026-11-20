import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from verifier import run_defense_engine
from virus_key_defense import (
    build_malware_defense_broadcast,
    cleanup_scratch_test_files,
    scan_workspace_for_leaked_keys,
)

DEFAULT_DATA_DIR = "./data"
DEFAULT_OUTPUT_DIR = "./output"
PROOF_PACK_FILENAME = "proof_pack.json"


def run_key_leak_scan(root_dir: str = ".", include_scratch: bool = True) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for item in scan_workspace_for_leaked_keys(root_dir=root_dir, include_scratch=include_scratch):
        alerts.append(
            build_malware_defense_broadcast(
                actor="local_workspace_scanner",
                ip_address="127.0.0.1",
                geolocation="Local Workstation",
                category="PLAIN_TEXT_KEY_AT_REST",
                detail=(
                    f"{item['finding_type']} in {item['file']}:{item['line']} "
                    f"({item['redacted_value']}, entropy={item['entropy']})"
                ),
                evidence_id="VKD-SCAN",
            )
        )
    return alerts


def run_full_security_pipeline(
    data_dir: str = DEFAULT_DATA_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    root_dir: str = ".",
    clean_scratch_first: bool = False,
) -> dict[str, Any]:
    """
    Single shared entry point used by both CLI (`python main.py`) and Streamlit (`app.py`):
    1. Optionally cleans scratch dummy key files
    2. Correlates evidence in `data_dir` via `verifier.run_defense_engine`
    3. Scans workspace files for plaintext API keys
    4. Writes unified redacted `./output/proof_pack.json`
    """
    if clean_scratch_first:
        cleanup_scratch_test_files(root_dir)

    raw_report = run_defense_engine(data_dir) if Path(data_dir).is_dir() else {}
    report: dict[str, Any] = raw_report if isinstance(raw_report, dict) else {}

    summary = report.setdefault(
        "summary",
        {
            "total_server_alerts": 0,
            "owner_notifications_sent": 0,
            "ip_challenges_logged": 0,
            "benign_operations_suppressed": 0,
        },
    )
    broadcasts = report.setdefault("server_broadcasts", [])
    if not isinstance(broadcasts, list):
        broadcasts = []
        report["server_broadcasts"] = broadcasts

    key_alerts = run_key_leak_scan(root_dir=root_dir, include_scratch=True)
    if key_alerts:
        broadcasts.extend(key_alerts)
        summary["total_server_alerts"] = int(summary.get("total_server_alerts", 0)) + len(key_alerts)
        summary["owner_notifications_sent"] = int(summary.get("owner_notifications_sent", 0)) + len(key_alerts)

    report["generated_at_utc"] = datetime.now(timezone.utc).isoformat()
    report["key_scan_findings_count"] = len(key_alerts)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    proof_file = out_path / PROOF_PACK_FILENAME
    proof_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    report = run_full_security_pipeline(
        data_dir=DEFAULT_DATA_DIR,
        output_dir=DEFAULT_OUTPUT_DIR,
        root_dir=".",
        clean_scratch_first=False,
    )
    summary = report.get("summary", {})
    print("=== Harbor & Finch Defense Engine Summary ===")
    print(f"Total Server Alerts       : {summary.get('total_server_alerts', 0)}")
    print(f"Owner Notifications Sent  : {summary.get('owner_notifications_sent', 0)}")
    print(f"IP Challenges Logged      : {summary.get('ip_challenges_logged', 0)}")
    print(f"Benign Events Suppressed  : {summary.get('benign_operations_suppressed', 0)}")
    print(f"Key Leak Findings         : {report.get('key_scan_findings_count', 0)}")

    for alert in report.get("server_broadcasts", []):
        if alert.get("category") == "PLAIN_TEXT_KEY_AT_REST":
            print(f"ALERT: {alert}")

    print(f"Full Proof Pack exported to: {DEFAULT_OUTPUT_DIR}/{PROOF_PACK_FILENAME}")


if __name__ == "__main__":
    main()