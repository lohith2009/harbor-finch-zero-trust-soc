import json
import os
import pandas as pd

def create_dummy_case_data(data_dir: str = "./data"):
    os.makedirs(data_dir, exist_ok=True)

    # 1. E14.csv - HR Staff Roster (Includes Rohan Menon terminated 30 Jun 2026)
    e14 = pd.DataFrame([
        {"employee_id": "EMP-101", "username": "dev.raghavan", "full_name": "Dev Raghavan", "department": "Management", "role": "General Manager", "status": "Active", "hire_date": "2009-04-01", "termination_date": ""},
        {"employee_id": "EMP-108", "username": "farah.dsouza", "full_name": "Farah Dsouza", "department": "Finance", "role": "Senior Accountant", "status": "Active", "hire_date": "2019-06-15", "termination_date": ""},
        {"employee_id": "EMP-115", "username": "colin.lawson", "full_name": "Colin Lawson", "department": "IT", "role": "Network Contractor", "status": "Active", "hire_date": "2022-02-10", "termination_date": ""},
        {"employee_id": "EMP-142", "username": "rohan.menon", "full_name": "Rohan Menon", "department": "Finance", "role": "Accounts Payable Clerk", "status": "Terminated", "hire_date": "2023-01-12", "termination_date": "2026-06-30"},
    ])
    e14.to_csv(os.path.join(data_dir, "E14.csv"), index=False)

    # 2. E03.csv - Single Sign-On (SSO) Log
    e03 = pd.DataFrame([
        # Legitimate office login
        {"ts_utc": "2026-08-10T04:15:00Z", "event_id": "SSO-9001", "user": "farah.dsouza", "source_ip": "172.16.12.40", "city": "Chennai", "auth_method": "Password+MFA", "mfa_result": "PASS", "device_id": "DEV-FIN-04", "result": "SUCCESS"},
        # Traveling contractor Colin Lawson passing 1-attempt MFA from new city IP
        {"ts_utc": "2026-08-12T06:30:00Z", "event_id": "SSO-9045", "user": "colin.lawson", "source_ip": "49.207.112.88", "city": "Bengaluru", "auth_method": "Password+MFA", "mfa_result": "PASS", "device_id": "DEV-NET-02", "result": "SUCCESS"},
        # Former employee Rohan Menon logging in AFTER June 30, 2026 termination
        {"ts_utc": "2026-08-13T09:10:00Z", "event_id": "SSO-9102", "user": "rohan.menon", "source_ip": "172.16.44.19", "city": "Chennai Warehouse", "auth_method": "Password", "mfa_result": "NONE", "device_id": "KIOSK-WH-01", "result": "SUCCESS"},
        # External attacker failing 1-attempt IP verification on Farah's account
        {"ts_utc": "2026-08-22T18:45:00Z", "event_id": "SSO-9388", "user": "farah.dsouza", "source_ip": "185.220.101.42", "city": "Frankfurt", "auth_method": "Password+MFA", "mfa_result": "FAIL", "device_id": "UNKNOWN", "result": "DENIED"},
    ])
    e03.to_csv(os.path.join(data_dir, "E03.csv"), index=False)

    # 3. E04.json - Connected Software Register
    e04 = [
        {"integration": "TallyBridge Connect", "credential_id": "KEY-TB-902", "system": "LedgerOne", "vendor": "TallyBridge", "scope": "read_write_vendors", "owner": "Finance IT", "ip_restriction": "10.20.4.0/24", "status": "Active"},
        {"integration": "Nightly Reporting", "credential_id": "KEY-REP-101", "system": "LedgerOne", "vendor": "Internal", "scope": "read_only", "owner": "IT", "ip_restriction": "172.16.0.0/16", "status": "Active"},
    ]
    with open(os.path.join(data_dir, "E04.json"), "w", encoding="utf-8") as f:
        json.dump(e04, f, indent=2)

    # 4. E01.csv & E18.csv - LedgerOne API Access Logs
    e01 = pd.DataFrame([
        # Legitimate overnight sync via Private Link 10.20.4.0/24
        {"ts_utc": "2026-08-20T01:00:00Z", "request_id": "REQ-5001", "api_key_id": "KEY-TB-902", "caller_ip": "10.20.4.12", "user_agent": "TallyBridge-Sync/2.4", "endpoint": "/api/v1/vendors/sync", "method": "GET", "records_returned": 300, "status": 200},
        # Suspicious external IP calling API key KEY-TB-902
        {"ts_utc": "2026-08-21T21:14:00Z", "request_id": "REQ-7789", "api_key_id": "KEY-TB-902", "caller_ip": "91.132.44.10", "user_agent": "python-requests/2.31", "endpoint": "/api/v1/vendors/bank-details", "method": "PATCH", "records_returned": 1, "status": 200},
    ])
    e01.to_csv(os.path.join(data_dir, "E01.csv"), index=False)
    e01.iloc[1:].to_csv(os.path.join(data_dir, "E18.csv"), index=False)

    # 5. E19.csv - Vendor Record Change Log (Linked via request_id)
    e19 = pd.DataFrame([
        # Legitimate vendor cleanup with approval_ref
        {"ts_utc": "2026-07-31T11:00:00Z", "change_id": "CHG-101", "vendor_id": "V-204", "vendor_name": "Southern Hauliers", "field": "contact_email", "old_value": "old@sh.in", "new_value": "billing@sh.in", "changed_by": "farah.dsouza", "channel": "UI", "approval_ref": "APR-2026-07", "source_ip": "172.16.12.40", "request_id": ""},
        # Malicious unapproved bank account change linked to REQ-7789 from external IP
        {"ts_utc": "2026-08-21T21:14:02Z", "change_id": "CHG-319", "vendor_id": "V-112", "vendor_name": "Deccan Fuel Corp", "field": "bank_account_no", "old_value": "XXXX-4412", "new_value": "XXXX-9981", "changed_by": "KEY-TB-902", "channel": "API", "approval_ref": "", "source_ip": "91.132.44.10", "request_id": "REQ-7789"},
    ])
    e19.to_csv(os.path.join(data_dir, "E19.csv"), index=False)
    print(f"✅ Dummy case files generated successfully in '{data_dir}/'")

if __name__ == "__main__":
    create_dummy_case_data()