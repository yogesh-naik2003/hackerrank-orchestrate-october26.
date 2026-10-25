# Ghost Data Still Exists — Project Guide

## 1. The challenge in plain language

Northstar Shop must honor customer deletion requests, but a workflow status such as `COMPLETE` is not proof that the data is gone. A person's data can remain in replicas, logs, support documents, search indexes, analytics exports, archives, or backups. A sync, import, or restore process can also recreate data after the source record was deleted.

Your job is to build a deterministic audit agent. For every deletion request, it must decide whether deletion was requested, identify the person (including prior identities), reconstruct the state of all relevant data at a specific cutoff time, apply the policy, and write an auditable answer to `output.csv`.

The project is not simply a record search. It is a time-aware, policy-driven investigation that must distinguish evidence from operational claims and propose safe remediation in the correct dependency order.

## 2. The required decision for each case

Each row in `dataset/deletion_requests.csv` is one audit case:

```text
case_id,email,requested_at,reported_status,reported_at,audit_at,request_text
```

The agent must produce exactly one of these results:

| Status | When to use it |
| --- | --- |
| `NOT_APPLICABLE` | The text does not authorize deletion (for example, an access, export, correction, or marketing opt-out request). Its steps must be `[]`. |
| `COMPLETE` | Deletion was authorized and, at `audit_at`, all copies have the policy-required treatment, required retained records remain, and no live flow or restore path can recreate prohibited data. |
| `INCOMPLETE` | Deletion was authorized but evidence shows one or more policy violations or recreation risks at `audit_at`. |

`reported_status` (`COMPLETE`, `PARTIALLY_COMPLETE`, or `NOT_STARTED`) is only a workflow claim. It never replaces an evidence-based audit.

## 3. What makes the investigation difficult

### Identity resolution

The email in the request may be a current or historical address. Start with `user_identities.csv`, then use `user_audit_log.csv` to collect every relevant historical value: old emails, names, phones, hashes, and the stable `user_id`. Search evidence using all grounded identifiers, not merely the email supplied in the request.

### Time reconstruction

The decision must reflect the state **at or before `audit_at`**. Do not allow evidence captured after that cutoff to change the result. Build a timeline from request timestamps, identity history, activity records, evidence capture times, and database/log content. Activity logs and operation success messages are claims; direct evidence of the resulting record state is stronger.

### Policy application

`deletion_rules.csv` decides the required treatment for each relevant record/category. A matching record is not automatically deleted: policy may require deletion, redaction, anonymization, retention, or a redacted account tombstone.

An `ACCOUNT_TOMBSTONE` may retain the stable internal `user_id` so other permitted records can still refer to it. It must not retain prohibited direct identifiers such as name, email, phone, or email hash when the rule requires them to be removed.

### Recreation risk

Even if a source record is absent, deletion is incomplete if an active sync/import/indexing flow could recreate it, or a backup/restore path could bring it back. Those risks are findings in their own right and must be remediated before dependent data is changed.

## 4. Dataset map

All investigation data is participant-facing and lives under `dataset/`.

| Location | Purpose |
| --- | --- |
| `deletion_requests.csv` | The 518 evaluation cases that need answers. |
| `sample_deletion_requests.csv` | 32 public example cases. |
| `sample_output.csv` | Correct output format and decisions for the sample cases. |
| `user_identities.csv` | Current identity snapshot and stable `user_id`. |
| `user_audit_log.csv` | Historical identity changes used to recover old identifiers. |
| `system_activity.csv` | Deletion, sync, export, backup, restore, indexing, and audit activity. Treat it as claims unless corroborated. |
| `deletion_rules.csv` | Required treatment by data category and condition. |
| `evidence_files.csv` | Manifest mapping a `file_id` to an evidence path, source, and capture time. |
| `evidence/` | The actual PDFs, images, logs, JSON/text records, and SQLite-compatible SQL exports. |
| `output.csv` | Blank format reference inside the dataset; do not overwrite it as the final submission. |

Only `deletion_requests.csv` requires predictions. Never use organizer-only material outside `dataset/` to make predictions.

## 5. Evidence rules

Use the evidence manifest to locate files, then inspect their actual contents. A manifest entry alone does not prove that it concerns a case. Connect a file to a person through concrete identifiers, timestamps, system/resource IDs, or hashes.

Valid finding evidence IDs are participant-visible `file_id`, `activity_id`, or `audit_id` values. For a `COMPLETE` result, each verification step must cite evidence proving the compliant state at the cutoff. For an `INCOMPLETE` result, proposed remediation and future verification are plans, so their `evidence_id` is an empty string.

## 6. Output contract

Write the final result to **repository-root** `output.csv`, not `dataset/output.csv`.

```text
case_id,deletion_status,steps_json
```

Requirements:

- Exactly 518 data rows, one for each evaluation request.
- Sort by `case_id`.
- `steps_json` is a valid JSON array.
- Every step has exactly `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id`.
- Step numbers begin at 1 and are consecutive.
- Phase order is always `FINDING`, then `REMEDIATION`, then `VERIFICATION`.
- A `NOT_APPLICABLE` row must have `steps_json=[]`.

Example step:

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

## 7. Allowed steps

| Phase | Purpose | Operations and states |
| --- | --- | --- |
| `FINDING` | Describe current policy violations and risks proved by evidence. | `REPORT_REMAINING_RECORD` / `PRESENT`; `REPORT_EXPOSED_PII` / `PRESENT`; `REPORT_ACTIVE_DATA_FLOW` / `ACTIVE`; `REPORT_RESTORE_RISK` / `ACTIVE` |
| `REMEDIATION` | Describe future work for incomplete cases. | `DISABLE_DATA_FLOW` / `DISABLED`; `BLOCK_RESTORE` / `BLOCKED`; `DELETE_RECORD` / `ABSENT`; `REDACT_RECORD` / `REDACTED`; `ANONYMIZE_RECORD` / `ANONYMIZED` |
| `VERIFICATION` | Prove completion or define checks after future work. | `VERIFY_RECORD_ABSENT` / `ABSENT`; `VERIFY_RECORD_PRESENT` / `PRESENT`; `VERIFY_RECORD_REDACTED` / `REDACTED`; `VERIFY_RECORD_ANONYMIZED` / `ANONYMIZED`; `VERIFY_DATA_FLOW_DISABLED` / `DISABLED`; `VERIFY_RESTORE_BLOCKED` / `BLOCKED` |

Do not invent phases, operations, or states.

For an incomplete case, findings describe all discovered violations. Remediation then safely resolves them: disable data flows and block restores before making dependent record changes; where dependency requires it, process downstream copies before their sources. Verification covers every final state introduced by the remediation.

Within a phase, use the operation order defined in the problem statement and then sort by `system_id` and `resource_id`.

## 8. Suggested solution architecture

The starter files `code/main.py` and `code/evaluation/main.py` are empty. A practical implementation can be organized into the following pipeline:

1. **Load and validate data.** Read CSVs and the evidence manifest relative to the repository root. Validate required columns and parse all timestamps consistently.
2. **Learn the public contract.** Run against the sample requests and compare generated rows with `sample_output.csv`; use this only as public training/format feedback, not as a shortcut for evaluation cases.
3. **Classify request authorization.** Detect whether `request_text` is a deletion request. Return `NOT_APPLICABLE` immediately for another request type.
4. **Build an identity profile.** Resolve the request email to a stable person and collect current plus historical identifiers valid at the audit time.
5. **Index evidence.** Parse text/log/JSON/SQL artifacts and make records searchable by identifier, resource ID, and time. Use suitable extraction for PDFs and images if needed.
6. **Reconstruct state at the cutoff.** Combine direct evidence with activity history, excluding events and captures after `audit_at`.
7. **Apply policy.** For each relevant record/process, determine whether its required action is delete, redact, anonymize, retain, or tombstone redaction.
8. **Generate deterministic steps.** Emit evidence-backed findings; for incomplete cases add ordered remediation and future verification; for complete cases emit only evidence-backed verification.
9. **Validate and write output.** Check row count, unique sorted case IDs, allowed operation/state pairs, required key set, sequential numbering, evidence-ID rules, and valid JSON before writing root `output.csv`.

## 9. How to run and evaluate

The intended Python entry point is:

```bash
python3 code/main.py
```

The finished implementation should be runnable from the repository root and use paths relative to that root. Evaluation materials belong in `code/evaluation/`:

- `evaluation_report.md`: case-level status accuracy, step/field accuracy, sequence accuracy, at least three team-created cases, failures, and improvements.
- `usage_report.md`: provider/model names, model calls, input/output tokens, totals and averages per request, and estimated total/per-request costs.

Package runnable code, prompts/configuration, the README, and evaluation reports in `code.zip`. Exclude `dataset/`, virtual environments, dependency caches, nested archives, secrets, and sensitive configuration. Submit root `output.csv` separately along with root `log.txt` as the chat transcript.

## 10. Final checklist

- [ ] Every request has a decision based on its text, not the reported status.
- [ ] Current and historical identifiers were investigated.
- [ ] No evidence after `audit_at` influenced the decision.
- [ ] Every relevant record has the treatment required by policy.
- [ ] Account tombstones retain only allowed stable references.
- [ ] Active flows and restore risks were assessed.
- [ ] Findings and completed-case verification cite real participant-visible evidence.
- [ ] Future remediation and verification have empty evidence IDs.
- [ ] Output is sorted, valid, complete, and written to root `output.csv`.
- [ ] The submission includes both evaluation reports and no secrets or dataset files.
