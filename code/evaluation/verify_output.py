"""Automated validation test suite for output.csv and sample_predictions.csv.

Run from repository root:
    python code/evaluation/verify_output.py
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
OUTPUT_FILE = ROOT / "output.csv"
SAMPLE_PRED_FILE = ROOT / "sample_predictions.csv"
SAMPLE_OUT_FILE = DATASET / "sample_output.csv"
REQUESTS_FILE = DATASET / "deletion_requests.csv"
MANIFEST_FILE = DATASET / "evidence_files.csv"
ACTIVITIES_FILE = DATASET / "system_activity.csv"

ALLOWED_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

ALLOWED_OPS_STATES = {
    # Findings
    ("FINDING", "REPORT_REMAINING_RECORD"): "PRESENT",
    ("FINDING", "REPORT_EXPOSED_PII"): "PRESENT",
    ("FINDING", "REPORT_ACTIVE_DATA_FLOW"): "ACTIVE",
    ("FINDING", "REPORT_RESTORE_RISK"): "ACTIVE",
    # Remediation
    ("REMEDIATION", "DISABLE_DATA_FLOW"): "DISABLED",
    ("REMEDIATION", "BLOCK_RESTORE"): "BLOCKED",
    ("REMEDIATION", "DELETE_RECORD"): "ABSENT",
    ("REMEDIATION", "REDACT_RECORD"): "REDACTED",
    ("REMEDIATION", "ANONYMIZE_RECORD"): "ANONYMIZED",
    # Verification
    ("VERIFICATION", "VERIFY_RECORD_ABSENT"): "ABSENT",
    ("VERIFICATION", "VERIFY_RECORD_PRESENT"): "PRESENT",
    ("VERIFICATION", "VERIFY_RECORD_REDACTED"): "REDACTED",
    ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED"): "ANONYMIZED",
    ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"): "DISABLED",
    ("VERIFICATION", "VERIFY_RESTORE_BLOCKED"): "BLOCKED",
}

PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def test_output_csv() -> bool:
    print("=" * 65)
    print("TEST 1: Validating Root output.csv (518-case Evaluation Dataset)")
    print("=" * 65)
    
    if not OUTPUT_FILE.is_file():
        print(f"[FAIL] Missing output file: {OUTPUT_FILE}")
        return False
        
    with OUTPUT_FILE.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        rows = list(reader)
        
    errors: list[str] = []
    
    # Header check
    expected_headers = ["case_id", "deletion_status", "steps_json"]
    if headers != expected_headers:
        errors.append(f"Header mismatch: expected {expected_headers}, got {headers}")
    else:
        print("[PASS] Header schema: case_id,deletion_status,steps_json")
        
    # Row count check
    expected_reqs = list(csv.DictReader(REQUESTS_FILE.open("r", encoding="utf-8-sig")))
    expected_case_ids = [r["case_id"] for r in expected_reqs]
    req_by_id = {r["case_id"]: r for r in expected_reqs}
    
    if len(rows) != len(expected_case_ids):
        errors.append(f"Row count mismatch: expected {len(expected_case_ids)}, got {len(rows)}")
    else:
        print(f"[PASS] Row count: exactly {len(rows)} data rows")
        
    # Sorting check
    actual_case_ids = [r["case_id"] for r in rows]
    if actual_case_ids != sorted(expected_case_ids):
        errors.append("Rows are not sorted strictly by case_id!")
    else:
        print("[PASS] Sorting: strictly sorted by case_id")
        
    # Completeness check
    if set(actual_case_ids) != set(expected_case_ids):
        diff_missing = set(expected_case_ids) - set(actual_case_ids)
        errors.append(f"Missing cases: {diff_missing}")
    else:
        print("[PASS] Completeness: all 518 cases present (0 missing, 0 extra)")
        
    # Semantic verification
    manifest_rows = list(csv.DictReader(MANIFEST_FILE.open("r", encoding="utf-8-sig")))
    manifest_by_id = {r["file_id"]: parse_time(r["captured_at"]) for r in manifest_rows}
    activities_rows = list(csv.DictReader(ACTIVITIES_FILE.open("r", encoding="utf-8-sig")))
    activity_by_id = {r["activity_id"]: parse_time(r["event_time"]) for r in activities_rows}
    
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    total_steps = 0
    phase_counts = {"FINDING": 0, "REMEDIATION": 0, "VERIFICATION": 0}
    
    for row in rows:
        cid = row["case_id"]
        status = row["deletion_status"]
        steps_raw = row["steps_json"]
        req = req_by_id[cid]
        audit_at = parse_time(req["audit_at"])
        
        if status not in ALLOWED_STATUSES:
            errors.append(f"{cid}: invalid deletion_status '{status}'")
            continue
            
        status_counts[status] += 1
        
        try:
            steps = json.loads(steps_raw)
        except json.JSONDecodeError as exc:
            errors.append(f"{cid}: invalid JSON in steps_json: {exc}")
            continue
            
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json is not an array")
            continue
            
        if status == "NOT_APPLICABLE" and steps != []:
            errors.append(f"{cid}: NOT_APPLICABLE must have steps_json = []")
            continue
            
        total_steps += len(steps)
        last_phase_rank = -1
        
        for idx, step in enumerate(steps, start=1):
            if step.get("step_no") != idx:
                errors.append(f"{cid} step {idx}: invalid step_no {step.get('step_no')}")
                
            req_fields = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
            if set(step.keys()) != req_fields:
                errors.append(f"{cid} step {idx}: invalid step keys {set(step.keys())}")
                
            phase = step.get("phase")
            op = step.get("operation")
            state = step.get("state")
            ev_id = step.get("evidence_id")
            
            if phase in phase_counts:
                phase_counts[phase] += 1
                
            current_phase_rank = PHASE_RANK.get(phase, -1)
            if current_phase_rank < last_phase_rank:
                errors.append(f"{cid} step {idx}: phase order violation ({phase} after higher phase)")
            last_phase_rank = current_phase_rank
            
            expected_state = ALLOWED_OPS_STATES.get((phase, op))
            if expected_state is None:
                errors.append(f"{cid} step {idx}: illegal ({phase}, {op})")
            elif state != expected_state:
                errors.append(f"{cid} step {idx}: state mismatch for ({phase}, {op})")
                
            if status == "COMPLETE":
                if phase != "VERIFICATION":
                    errors.append(f"{cid} step {idx}: COMPLETE case has non-VERIFICATION step")
                if not ev_id:
                    errors.append(f"{cid} step {idx}: COMPLETE verification step missing evidence_id")
                else:
                    ev_time = manifest_by_id.get(ev_id) or activity_by_id.get(ev_id)
                    if ev_time and ev_time > audit_at:
                        errors.append(f"{cid} step {idx}: evidence {ev_id} captured after audit cutoff")
            elif status == "INCOMPLETE":
                if phase == "FINDING" and not ev_id:
                    errors.append(f"{cid} step {idx}: FINDING step missing evidence_id")
                elif phase in {"REMEDIATION", "VERIFICATION"} and ev_id != "":
                    errors.append(f"{cid} step {idx}: future step has non-empty evidence_id '{ev_id}'")
                    
    print("\nSummary:")
    print(f"  Status counts: {status_counts}")
    print(f"  Total operational steps: {total_steps} (FINDING={phase_counts['FINDING']}, REMEDIATION={phase_counts['REMEDIATION']}, VERIFICATION={phase_counts['VERIFICATION']})")
    print(f"  Errors found: {len(errors)}")
    
    if errors:
        for e in errors[:5]:
            print(f"  [ERROR] {e}")
        return False
        
    print("[PASS] output.csv meets 100% of challenge contract requirements.\n")
    return True


def test_public_samples() -> None:
    print("=" * 65)
    print("TEST 2: Public Sample Comparison (sample_predictions.csv)")
    print("=" * 65)
    
    if not SAMPLE_PRED_FILE.is_file() or not SAMPLE_OUT_FILE.is_file():
        print("[SKIP] sample_predictions.csv or sample_output.csv not found")
        return
        
    with SAMPLE_OUT_FILE.open("r", encoding="utf-8-sig") as f:
        gold = {r["case_id"]: r for r in csv.DictReader(f)}
    with SAMPLE_PRED_FILE.open("r", encoding="utf-8-sig") as f:
        pred = {r["case_id"]: r for r in csv.DictReader(f)}
        
    status_matches = sum(gold[cid]["deletion_status"] == pred.get(cid, {}).get("deletion_status") for cid in gold)
    exact_matches = sum(json.loads(gold[cid]["steps_json"]) == json.loads(pred.get(cid, {}).get("steps_json", "[]")) for cid in gold)
    
    print(f"[RESULT] Status Accuracy: {status_matches} / {len(gold)} ({(status_matches/len(gold))*100:.1f}%)")
    print(f"[RESULT] Exact Steps Accuracy: {exact_matches} / {len(gold)} ({(exact_matches/len(gold))*100:.1f}%)")


if __name__ == "__main__":
    ok = test_output_csv()
    test_public_samples()
    sys.exit(0 if ok else 1)
