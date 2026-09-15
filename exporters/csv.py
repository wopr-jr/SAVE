from __future__ import annotations

import csv
from pathlib import Path

from stig_ingest.model import Checklist


CSV_COLUMNS = [
    "checklist_uuid",
    "source_format",
    "source_filename",
    "source_sha256",
    "checklist_title",
    "host_name",
    "fqdn",
    "ip_address",
    "target_key",
    "stig_uuid",
    "stig_id",
    "stig_name",
    "display_name",
    "release_info",
    "rule_uuid",
    "vuln_id",
    "group_id",
    "group_id_source",
    "group_title",
    "rule_id",
    "rule_id_source",
    "rule_version",
    "rule_title",
    "severity",
    "status",
    "weight",
    "classification",
    "discussion",
    "check_content",
    "fix_text",
    "finding_details",
    "comments",
    "ccis",
    "legacy_ids",
    "group_tree",
    "created_at",
    "updated_at",
]


def export_csv(
    checklist: Checklist,
    destination: str | Path,
) -> None:
    """
    Export a flat, one-row-per-rule CSV file.
    """
    destination_path = Path(destination)

    asset = checklist.asset

    with destination_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=CSV_COLUMNS,
            extrasaction="ignore",
        )

        writer.writeheader()

        for stig in checklist.stigs:
            for rule in stig.rules:
                group_title = None

                if rule.group_tree:
                    group_title = rule.group_tree[-1].title

                writer.writerow(
                    {
                        "checklist_uuid": str(checklist.checklist_uuid),
                        "source_format": checklist.checklist_format.value,
                        "source_filename": checklist.source_filename,
                        "source_sha256": checklist.source_sha256,
                        "checklist_title": checklist.title,

                        "host_name": asset.host_name if asset else None,
                        "fqdn": asset.fqdn if asset else None,
                        "ip_address": asset.ip_address if asset else None,
                        "target_key": asset.target_key if asset else None,

                        "stig_uuid": str(stig.stig_uuid),
                        "stig_id": stig.stig_id,
                        "stig_name": stig.stig_name,
                        "display_name": stig.display_name,
                        "release_info": stig.release_info,

                        "rule_uuid": str(rule.rule_uuid),
                        "vuln_id": rule.vuln_id,
                        "group_id": rule.group_id,
                        "group_id_source": rule.group_id_source,
                        "group_title": group_title,
                        "rule_id": rule.rule_id,
                        "rule_id_source": rule.rule_id_source,
                        "rule_version": rule.rule_version,
                        "rule_title": rule.title,
                        "severity": rule.severity.value,
                        "status": rule.status.value,
                        "weight": rule.weight,
                        "classification": rule.classification,
                        "discussion": rule.discussion,
                        "check_content": rule.check_content,
                        "fix_text": rule.fix_text,
                        "finding_details": rule.finding_details,
                        "comments": rule.comments,
                        "ccis": ";".join(rule.ccis),
                        "legacy_ids": ";".join(rule.legacy_ids),
                        "group_tree": " / ".join(
                            group.source_id
                            for group in rule.group_tree
                        ),
                        "created_at": (
                            rule.created_at.isoformat()
                            if rule.created_at
                            else None
                        ),
                        "updated_at": (
                            rule.updated_at.isoformat()
                            if rule.updated_at
                            else None
                        ),
                    }
                )