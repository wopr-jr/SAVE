from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from SAVE.cli.cli_common import (
    ExitCode,
    print_summary,
)


@dataclass(slots=True)
class ChecklistInspection:
    """
    A presentation-oriented summary of one normalized checklist.

    This is intentionally independent of import results, source files,
    database access, or CLI argument parsing.
    """

    checklist_uuid: str
    stig_count: int
    rule_count: int

    open_count: int
    not_a_finding_count: int
    not_applicable_count: int
    not_reviewed_count: int

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    unknown_severity_count: int


def inspect_checklist(
    checklist,
) -> ChecklistInspection:
    """
    Inspect an already-loaded normalized Checklist.

    No imports, exports, file access, database access, or mutation occur here.
    """
    status_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    rule_count = 0

    for stig in checklist.stigs:
        for rule in stig.rules:
            rule_count += 1

            status_counts[rule.status.value] += 1
            severity_counts[rule.severity.value] += 1

    return ChecklistInspection(
        checklist_uuid=str(checklist.checklist_uuid),
        stig_count=len(checklist.stigs),
        rule_count=rule_count,

        open_count=status_counts["open"],
        not_a_finding_count=status_counts["not_a_finding"],
        not_applicable_count=status_counts["not_applicable"],
        not_reviewed_count=status_counts["not_reviewed"],

        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        unknown_severity_count=severity_counts["unknown"],
    )


def command_inspect_checklist(
    *,
    checklist,
) -> ExitCode:
    """
    Render inspection output for an already-resolved Checklist.

    The caller is responsible for obtaining `checklist`.
    """
    inspection = inspect_checklist(checklist)

    print_summary(
        checklist=checklist,
        inspection=inspection,
    )

    return ExitCode.SUCCESS