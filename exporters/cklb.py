from __future__ import annotations

import json
from pathlib import Path

from stig_ingest.model import (
    Checklist,
    FindingStatus,
)


def export_cklb(
    checklist: Checklist,
    destination: str | Path,
    *,
    cklb_version: str = "1.0",
) -> None:
    """
    Export normalized data to a CKLB-shaped JSON document.

    Validate generated output against the CKLB schema and test it in the
    intended STIG Viewer version before relying on it operationally.
    """
    destination_path = Path(destination)

    payload = {
        "id": str(checklist.checklist_uuid),
        "title": checklist.title or "",
        "cklb_version": (
            checklist.checklist_version
            or cklb_version
        ),
        "active": checklist.active,
        "mode": checklist.mode,
        "has_path": checklist.has_path,
        "target_data": _asset_to_cklb(checklist),
        "stigs": [
            _stig_to_cklb(stig)
            for stig in checklist.stigs
        ],
    }

    payload = _omit_none(payload)

    with destination_path.open("w", encoding="utf-8") as output_file:
        json.dump(
            payload,
            output_file,
            indent=2,
            ensure_ascii=False,
        )
        output_file.write("\n")


def _asset_to_cklb(checklist: Checklist) -> dict | None:
    asset = checklist.asset

    if asset is None:
        return None

    return _omit_none(
        {
            "target_type": asset.target_type,
            "host_name": asset.host_name,
            "fqdn": asset.fqdn,
            "ip_address": asset.ip_address,
            "mac_address": asset.mac_address,
            "target_key": asset.target_key,
            "role": asset.role,
            "tech_area": asset.technology_area,
            "comments": asset.comments,
        }
    )


def _stig_to_cklb(stig) -> dict:
    return _omit_none(
        {
            "stig_name": stig.stig_name,
            "display_name": stig.display_name,
            "stig_id": stig.stig_id,
            "release_info": stig.release_info,
            "uuid": str(stig.stig_uuid),
            "reference_identifier": stig.reference_identifier,
            "size": stig.source_rule_count or len(stig.rules),
            "rules": [
                _rule_to_cklb(rule)
                for rule in stig.rules
            ],
        }
    )


def _rule_to_cklb(rule) -> dict:
    override = None

    if rule.override is not None:
        override = _omit_none(
            {
                "severity": (
                    rule.override.severity.value
                    if rule.override.severity
                    else None
                ),
                "rationale": rule.override.rationale,
            }
        )

    return _omit_none(
        {
            "uuid": str(rule.rule_uuid),
            "stig_uuid": str(rule.stig_uuid),

            "vuln_id": rule.vuln_id,

            "group_id": rule.group_id,
            "group_id_src": rule.group_id_source,
            "rule_id": rule.rule_id,
            "rule_id_src": rule.rule_id_source,
            "rule_version": rule.rule_version,
            "rule_title": rule.title,

            "severity": rule.severity.value,
            "status": _status_to_cklb(rule.status),

            "weight": rule.weight,
            "classification": rule.classification,

            "discussion": rule.discussion,
            "check_content": rule.check_content,
            "fix_text": rule.fix_text,

            "reference_identifier": rule.reference_identifier,
            "target_key": rule.target_key,

            "check_content_ref": (
                {
                    "name": rule.check_content_ref.name,
                    "href": rule.check_content_ref.href,
                }
                if rule.check_content_ref
                else None
            ),

            "legacy_ids": rule.legacy_ids,
            "ccis": rule.ccis,

            "group_tree": [
                _omit_none(
                    {
                        "id": group.source_id,
                        "title": group.title,
                        "description": group.description,
                    }
                )
                for group in rule.group_tree
            ],

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

            "overrides": override,
            "comments": rule.comments,
            "finding_details": rule.finding_details,
        }
    )


def _status_to_cklb(status: FindingStatus) -> str:
    mapping = {
        FindingStatus.NOT_A_FINDING: "NotAFinding",
        FindingStatus.NOT_APPLICABLE: "Not_Applicable",
        FindingStatus.OPEN: "Open",
        FindingStatus.NOT_REVIEWED: "Not_Reviewed",
    }

    return mapping[status]


def _omit_none(value):
    if isinstance(value, dict):
        return {
            key: _omit_none(item)
            for key, item in value.items()
            if item is not None
        }

    if isinstance(value, list):
        return [
            _omit_none(item)
            for item in value
        ]

    return value