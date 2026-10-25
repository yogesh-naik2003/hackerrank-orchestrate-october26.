"""Public-sample evaluation loop for the deletion-audit agent.

Run from the repository root:
    python code/evaluation/main.py

It writes a disposable prediction CSV and a human-readable mismatch report. It
does not change the submission output at the repository root.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "dataset"
PREDICTIONS = ROOT / "sample_predictions.csv"
REPORT = ROOT / "code" / "evaluation" / "sample_validation_report.md"
STEP_FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def fingerprint(step: dict[str, object]) -> tuple[object, ...]:
    """Compare steps semantically while intentionally ignoring sequence number."""
    return tuple(step.get(field) for field in STEP_FIELDS)


def read_rows(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return {row["case_id"]: row for row in csv.DictReader(handle)}


def run_agent() -> None:
    command = [
        sys.executable,
        str(ROOT / "code" / "main.py"),
        "--requests", str(DATASET / "sample_deletion_requests.csv"),
        "--output", str(PREDICTIONS),
    ]
    subprocess.run(command, cwd=ROOT, check=True)


def compare(expected: dict[str, dict[str, str]], actual: dict[str, dict[str, str]]) -> tuple[str, bool]:
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    status_matches = 0
    exact_steps_matches = 0
    field_total: Counter[str] = Counter()
    field_matches: Counter[str] = Counter()
    missing_by_operation: Counter[str] = Counter()
    extra_by_operation: Counter[str] = Counter()
    mismatches: list[str] = []

    for case_id in sorted(set(expected) & set(actual)):
        expected_row, actual_row = expected[case_id], actual[case_id]
        expected_steps = json.loads(expected_row["steps_json"])
        actual_steps = json.loads(actual_row["steps_json"])
        status_match = expected_row["deletion_status"] == actual_row["deletion_status"]
        steps_match = expected_steps == actual_steps
        status_matches += status_match
        exact_steps_matches += steps_match

        for expected_step, actual_step in zip(expected_steps, actual_steps):
            for field in STEP_FIELDS:
                field_total[field] += 1
                field_matches[field] += expected_step.get(field) == actual_step.get(field)

        if not status_match or not steps_match:
            expected_counter = Counter(fingerprint(step) for step in expected_steps)
            actual_counter = Counter(fingerprint(step) for step in actual_steps)
            missing_steps = list((expected_counter - actual_counter).elements())
            extra_steps = list((actual_counter - expected_counter).elements())
            missing_by_operation.update(step[3] for step in missing_steps)
            extra_by_operation.update(step[3] for step in extra_steps)
            mismatches.append(
                "\n".join((
                    f"### {case_id}",
                    f"- Status: expected `{expected_row['deletion_status']}`, got `{actual_row['deletion_status']}`.",
                    f"- Missing semantic steps: `{json.dumps(missing_steps, ensure_ascii=False)}`",
                    f"- Extra semantic steps: `{json.dumps(extra_steps, ensure_ascii=False)}`",
                    f"- Expected steps: `{json.dumps(expected_steps, ensure_ascii=False)}`",
                    f"- Actual steps: `{json.dumps(actual_steps, ensure_ascii=False)}`",
                ))
            )

    total = len(expected)
    percent = lambda part, whole: f"{(100 * part / whole):.1f}%" if whole else "n/a"
    field_table = "\n".join(
        f"| `{field}` | {field_matches[field]} / {field_total[field]} | {percent(field_matches[field], field_total[field])} |"
        for field in STEP_FIELDS
    )
    operation_table = "\n".join(
        f"| `{operation}` | {missing_by_operation[operation]} | {extra_by_operation[operation]} |"
        for operation in sorted(set(missing_by_operation) | set(extra_by_operation))
    ) or "| none | 0 | 0 |"
    report = "\n".join((
        "# Public Sample Validation Report",
        "",
        "This report compares generated predictions with the provided public sample answers. It is a development aid, not the required final evaluation report.",
        "",
        "## Summary",
        "",
        f"- Cases expected/generated: {total} / {len(actual)}",
        f"- Status accuracy: {status_matches} / {total} ({percent(status_matches, total)})",
        f"- Exact `steps_json` accuracy: {exact_steps_matches} / {total} ({percent(exact_steps_matches, total)})",
        f"- Missing cases: {', '.join(missing) if missing else 'none'}",
        f"- Unexpected cases: {', '.join(unexpected) if unexpected else 'none'}",
        "",
        "## Field Accuracy at Matching Step Positions",
        "",
        "| Field | Matches / compared | Accuracy |",
        "| --- | --- | --- |",
        field_table,
        "",
        "## Semantic Step Delta by Operation",
        "",
        "| Operation | Missing | Extra |",
        "| --- | ---: | ---: |",
        operation_table,
        "",
        "## Cases to Investigate",
        "",
        "\n\n".join(mismatches) if mismatches else "All public sample cases match exactly.",
        "",
    ))
    return report, not missing and not unexpected and status_matches == total and exact_steps_matches == total


def main() -> int:
    run_agent()
    report, passed = compare(read_rows(DATASET / "sample_output.csv"), read_rows(PREDICTIONS))
    REPORT.write_text(report, encoding="utf-8")
    print(f"wrote validation report to {REPORT}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
