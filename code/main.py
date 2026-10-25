import os
import sys
import csv
import json
import sqlite3
from collections import defaultdict

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
EVIDENCE_DIR = os.path.join(DATASET_DIR, "evidence")
OUTPUT_PATH = os.path.join(BASE_DIR, "output.csv")

# Strict Operation Sequence Weights mandated by problem_statement.md
OP_ORDER = {
    # Phase 1: FINDING
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Phase 2: REMEDIATION
    "DISABLE_DATA_FLOW": 11,
    "BLOCK_RESTORE": 12,
    "DELETE_RECORD": 13,
    "REDACT_RECORD": 14,
    "ANONYMIZE_RECORD": 15,
    # Phase 3: VERIFICATION
    "VERIFY_RECORD_ABSENT": 21,
    "VERIFY_RECORD_PRESENT": 22,
    "VERIFY_RECORD_REDACTED": 23,
    "VERIFY_RECORD_ANONYMIZED": 24,
    "VERIFY_DATA_FLOW_DISABLED": 25,
    "VERIFY_RESTORE_BLOCKED": 26,
}

PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}

def load_csv(filename):
    path = os.path.join(DATASET_DIR, filename)
    if not os.path.exists(path):
        return []
    with open(path, mode="r", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))

def is_deletion_request(text):
    if not text:
        return False
    t = text.lower()
    delete_keywords = [
        "delete", "erasure", "erase", "forget", "gdpr", "ccpa", 
        "remove my data", "purge", "close account and delete", "right to be forgotten"
    ]
    non_deletion = [
        "export my data", "download data", "change my email", 
        "update address", "opt-out newsletter only", "subject access request", "access request"
    ]
    if any(k in t for k in non_deletion) and not any(k in t for k in delete_keywords):
        return False
    return any(k in t for k in delete_keywords)

class DisjointSet:
    def __init__(self):
        self.parent = {}

    def find(self, item):
        if item not in self.parent:
            self.parent[item] = item
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a, b):
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.parent[root_b] = root_a

def build_identity_clusters(identities, audit_logs):
    """
    Connects current identities and historical changes into transitive equivalence clusters.
    """
    ds = DisjointSet()
    all_identifiers = set()

    for row in identities:
        uid = row.get("user_id")
        if not uid:
            continue
        uid = uid.strip().lower()
        all_identifiers.add(uid)
        for field in ["email", "phone", "username", "account_id", "email_hash"]:
            val = row.get(field)
            if val:
                v = val.strip().lower()
                all_identifiers.add(v)
                ds.union(uid, v)

    for row in audit_logs:
        uid = row.get("user_id")
        if not uid:
            continue
        uid = uid.strip().lower()
        all_identifiers.add(uid)
        for field in ["old_value", "new_value", "identifier"]:
            val = row.get(field)
            if val:
                v = val.strip().lower()
                all_identifiers.add(v)
                ds.union(uid, v)

    cluster_map = defaultdict(set)
    for identifier in all_identifiers:
        root = ds.find(identifier)
        cluster_map[root].add(identifier)

    return ds, cluster_map

def get_known_identifiers(target, ds, cluster_map):
    t = target.strip().lower()
    root = ds.find(t)
    return cluster_map.get(root, {t})

def sort_and_deduplicate_steps(steps):
    seen = set()
    unique_steps = []

    for s in steps:
        key = (s["phase"], s["operation"], s.get("system_id", ""), s.get("resource_id", ""), s.get("evidence_id", ""))
        if key not in seen:
            seen.add(key)
            unique_steps.append(s)

    def sort_key(s):
        p_rank = PHASE_ORDER.get(s["phase"], 99)
        op_rank = OP_ORDER.get(s["operation"], 99)
        sys_id = s.get("system_id", "")
        res_id = s.get("resource_id", "")
        return (p_rank, op_rank, sys_id, res_id)

    ordered = sorted(unique_steps, key=sort_key)
    for idx, s in enumerate(ordered, 1):
        s["step_no"] = idx
    return ordered

def inspect_evidence_file(file_path, known_ids):
    """
    Inspects physical SQLite, JSON, or text logs for presence of user identifiers.
    Returns: (found_any: bool, has_direct_pii: bool, detected_resources: list)
    """
    if not os.path.exists(file_path):
        return False, False, []

    ext = os.path.splitext(file_path)[1].lower()
    found_matches = []
    has_direct_pii = False

    if ext in [".sqlite", ".db", ".sql"]:
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            for (tname,) in tables:
                cursor.execute(f"PRAGMA table_info({tname});")
                columns = [col[1] for col in cursor.fetchall()]
                cursor.execute(f"SELECT * FROM {tname};")
                for row in cursor.fetchall():
                    row_strs = [str(val).lower() for val in row if val is not None]
                    if any(ident in row_strs or any(ident in cell for cell in row_strs) for ident in known_ids):
                        found_matches.append(tname)
                        if any(c.lower() in ["email", "name", "phone", "first_name", "last_name", "address"] for c in columns):
                            has_direct_pii = True
            conn.close()
        except Exception:
            pass

    elif ext == ".json":
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as jf:
                content = jf.read().lower()
                if any(ident in content for ident in known_ids):
                    found_matches.append("json_record")
                    if any(k in content for k in ["email", "phone", "name", "first_name"]):
                        has_direct_pii = True
        except Exception:
            pass

    else:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as lf:
                content = lf.read().lower()
                if any(ident in content for ident in known_ids):
                    found_matches.append("log_record")
                    has_direct_pii = True
        except Exception:
            pass

    return len(found_matches) > 0, has_direct_pii, found_matches

def main():
    requests = load_csv("deletion_requests.csv")
    identities = load_csv("user_identities.csv")
    audit_logs = load_csv("user_audit_log.csv")
    system_activity = load_csv("system_activity.csv")
    deletion_rules = load_csv("deletion_rules.csv")
    evidence_manifest = load_csv("evidence_files.csv")

    ds, cluster_map = build_identity_clusters(identities, audit_logs)

    rules_by_sys = {r.get("system_id"): r for r in deletion_rules if r.get("system_id")}
    rules_by_cat = {r.get("category"): r for r in deletion_rules if r.get("category")}

    results = []

    for req in requests:
        case_id = req["case_id"]
        email = req.get("email", "").strip().lower()
        audit_at = req.get("audit_at", "")
        req_text = req.get("request_text", "")

        # 1. Intent Validation
        if not is_deletion_request(req_text):
            results.append({
                "case_id": case_id,
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": "[]"
            })
            continue

        known_ids = get_known_identifiers(email, ds, cluster_map)

        findings = []
        remediations = []
        verifications_incomplete = []
        verifications_complete = []

        # 2. System Activity & Recreation Risk Checks
        for act in system_activity:
            timestamp = act.get("timestamp", "")
            if audit_at and timestamp and timestamp > audit_at:
                continue

            act_user = (act.get("user_id") or act.get("target_id") or "").strip().lower()
            act_email = (act.get("email") or "").strip().lower()
            if not (act_user in known_ids or act_email in known_ids):
                continue

            act_type = act.get("activity_type", "").upper()
            status = act.get("status", "").upper()
            sys_id = act.get("system_id", "sync_service")
            res_id = act.get("resource_id", "sync_job")
            act_id = act.get("activity_id", "")

            # Sync / Export / Import active recreation flows
            if any(k in act_type for k in ["SYNC", "IMPORT", "EXPORT"]):
                if status in ["ACTIVE", "SCHEDULED", "RUNNING"]:
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_ACTIVE_DATA_FLOW",
                        "state": "ACTIVE",
                        "evidence_id": act_id
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DISABLE_DATA_FLOW",
                        "state": "DISABLED",
                        "evidence_id": ""
                    })
                    verifications_incomplete.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_DATA_FLOW_DISABLED",
                        "state": "DISABLED",
                        "evidence_id": ""
                    })

            # Restore / Backup reactivation risk
            if any(k in act_type for k in ["RESTORE", "BACKUP"]):
                if status in ["PENDING_RESTORE", "ACTIVE_RESTORE", "SCHEDULED_RESTORE"]:
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_RESTORE_RISK",
                        "state": "ACTIVE",
                        "evidence_id": act_id
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "BLOCK_RESTORE",
                        "state": "BLOCKED",
                        "evidence_id": ""
                    })
                    verifications_incomplete.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RESTORE_BLOCKED",
                        "state": "BLOCKED",
                        "evidence_id": ""
                    })

        # 3. Evidence Audit
        for ev in evidence_manifest:
            ev_id = ev.get("evidence_id") or ev.get("file_id", "")
            sys_id = ev.get("system_id", "primary_store")
            res_id = ev.get("resource_id", "record")
            category = ev.get("category", "")
            file_name = ev.get("file_name") or ev.get("path", "")

            rule = rules_by_sys.get(sys_id) or rules_by_cat.get(category, {})
            policy_action = (rule.get("required_action") or "DELETE").upper()
            retain_record = (rule.get("retain_record") or "FALSE").upper() == "TRUE"

            file_path = os.path.join(EVIDENCE_DIR, file_name) if file_name else ""
            found_in_file, file_has_pii, _ = inspect_evidence_file(file_path, known_ids)

            manifest_user = (ev.get("user_id") or "").strip().lower()
            is_relevant = (manifest_user in known_ids) or found_in_file

            if not is_relevant:
                continue

            manifest_deleted = ev.get("is_deleted", "").upper() == "TRUE"
            is_deleted = manifest_deleted if ("is_deleted" in ev and ev["is_deleted"] != "") else (not found_in_file)
            has_exposed_pii = (ev.get("contains_direct_pii", "").upper() == "TRUE") or file_has_pii

            if not is_deleted:
                if retain_record:
                    # Allowed tombstone/statutory record
                    if has_exposed_pii:
                        findings.append({
                            "phase": "FINDING",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII",
                            "state": "PRESENT",
                            "evidence_id": ev_id
                        })
                        rem_op = "REDACT_RECORD" if policy_action == "REDACT" else "ANONYMIZE_RECORD"
                        rem_st = "REDACTED" if policy_action == "REDACT" else "ANONYMIZED"
                        ver_op = "VERIFY_RECORD_REDACTED" if policy_action == "REDACT" else "VERIFY_RECORD_ANONYMIZED"

                        remediations.append({
                            "phase": "REMEDIATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": rem_op,
                            "state": rem_st,
                            "evidence_id": ""
                        })
                        verifications_incomplete.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": ver_op,
                            "state": rem_st,
                            "evidence_id": ""
                        })
                    else:
                        verifications_complete.append({
                            "phase": "VERIFICATION",
                            "system_id": sys_id,
                            "resource_id": res_id,
                            "operation": "VERIFY_RECORD_PRESENT",
                            "state": "PRESENT",
                            "evidence_id": ev_id
                        })
                else:
                    # Record must be deleted
                    findings.append({
                        "phase": "FINDING",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "REPORT_REMAINING_RECORD",
                        "state": "PRESENT",
                        "evidence_id": ev_id
                    })
                    remediations.append({
                        "phase": "REMEDIATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "DELETE_RECORD",
                        "state": "ABSENT",
                        "evidence_id": ""
                    })
                    verifications_incomplete.append({
                        "phase": "VERIFICATION",
                        "system_id": sys_id,
                        "resource_id": res_id,
                        "operation": "VERIFY_RECORD_ABSENT",
                        "state": "ABSENT",
                        "evidence_id": ""
                    })
            else:
                verifications_complete.append({
                    "phase": "VERIFICATION",
                    "system_id": sys_id,
                    "resource_id": res_id,
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": ev_id
                })

        # 4. Final Classification & Evidence Isolation
        if len(findings) > 0 or len(remediations) > 0:
            status = "INCOMPLETE"
            final_steps = findings + remediations + verifications_incomplete
        else:
            status = "COMPLETE"
            # COMPLETE requires ONLY verification steps citing valid evidence IDs
            final_steps = [v for v in verifications_complete if v.get("evidence_id")]

        ordered_steps = sort_and_deduplicate_steps(final_steps)

        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": json.dumps(ordered_steps, separators=(",", ":"))
        })

    # Sort strictly by case_id
    results.sort(key=lambda x: x["case_id"])

    with open(OUTPUT_PATH, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(results)

    print(f"Audit completed: {len(results)} rows written to {OUTPUT_PATH}")
    assert len(results) == 518, f"Output row count mismatch: Expected 518, got {len(results)}"

if __name__ == "__main__":
    main()