from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from stig_ingest.model import (
    Asset,
    Checklist,
    ChecklistFormat,
    CheckReference,
    FindingStatus,
    RuleOverride,
    Severity,
    Stig,
    StigGroup,
    StigRule,
)


class CklbImportError(ValueError):
    """Raised when a source file cannot be interpreted as a CKLB file."""


@dataclass(slots=True)
class CklbImportResult:
    checklist: Checklist
    warnings: list[str] = field(default_factory=list)


def import_cklb(
    source: str | Path,
    *,
    checklist_uuid: UUID | None = None,
) -> CklbImportResult:
    """
    Import a CKLB JSON file into the normalized checklist model.

    UUID precedence:
      1. Valid top-level CKLB `id`
      2. Caller-provided checklist_uuid
      3. Newly generated UUIDv4

    The caller-provided UUID is intended as a fallback for malformed or
    incomplete CKLB files, not as an override of a valid source CKLB ID.
    """
    source_path = Path(source)

    if not source_path.is_file():
        raise FileNotFoundError(f"CKLB file not found: {source_path}")

    source_sha256 = _sha256_file(source_path)
    warnings: list[str] = []

    try:
        with source_path.open("r", encoding="utf-8-sig") as source_file:
            document = json.load(source_file)
    except json.JSONDecodeError as exc:
        raise CklbImportError(
            f"Invalid JSON in CKLB file {source_path.name}: {exc}"
        ) from exc

    if not isinstance(document, dict):
        raise CklbImportError(
            f"CKLB root must be a JSON object, not {type(document).__name__}."
        )

    cklb_version = _optional_string(document.get("cklb_version"))
    if not cklb_version:
        warnings.append(
            "Document has no cklb_version field; importing as a permissive CKLB variant."
        )

    embedded_checklist_uuid = _parse_uuid(
        document.get("id"),
        context="top-level id",
        warnings=warnings,
    )

    resolved_checklist_uuid = (
        embedded_checklist_uuid
        or checklist_uuid
        or uuid4()
    )

    if embedded_checklist_uuid and checklist_uuid:
        if embedded_checklist_uuid != checklist_uuid:
            warnings.append(
                "Caller-provided checklist UUID differs from CKLB top-level id; "
                "preserving the source CKLB id."
            )

    target_data = _object_or_empty(
        document.get("target_data"),
        context="target_data",
        warnings=warnings,
    )

    asset = _parse_asset(target_data)

    raw_stigs = _list_or_empty(
        document.get("stigs"),
        context="stigs",
        warnings=warnings,
    )

    stigs: list[Stig] = []

    for stig_index, raw_stig in enumerate(raw_stigs):
        if not isinstance(raw_stig, dict):
            warnings.append(
                f"Skipping stigs[{stig_index}]: expected object, "
                f"received {type(raw_stig).__name__}."
            )
            continue

        stig, stig_warnings = _parse_stig(
            raw_stig,
            checklist_uuid=resolved_checklist_uuid,
            stig_index=stig_index,
        )
        stigs.append(stig)
        warnings.extend(stig_warnings)

    checklist = Checklist(
        checklist_uuid=resolved_checklist_uuid,
        title=_optional_string(document.get("title")) or source_path.name,
        checklist_format=ChecklistFormat.CKLB,
        checklist_version=cklb_version,
        source_filename=source_path.name,
        source_sha256=source_sha256,
        imported_at=_parse_datetime(document.get("updated_at")),
        asset=asset,
        stigs=stigs,
        active=_optional_bool(document.get("active")),
        mode=_optional_int(document.get("mode")),
        has_path=_optional_bool(document.get("has_path")),
    )

    return CklbImportResult(
        checklist=checklist,
        warnings=warnings,
    )


def _parse_asset(data: dict[str, Any]) -> Asset | None:
    """
    CKLB target_data field names have varied in third-party generated files.
    Support expected names and a few safe aliases.
    """
    if not data:
        return None

    return Asset(
        target_type=_optional_string(data.get("target_type")) or "Computing",
        host_name=_optional_string(data.get("host_name")),
        fqdn=_first_string(data, "fqdn", "host_fqdn"),
        ip_address=_optional_string(data.get("ip_address")),
        mac_address=_optional_string(data.get("mac_address")),
        target_key=_optional_string(data.get("target_key")),
        role=_optional_string(data.get("role")),
        technology_area=_first_string(
            data,
            "technology_area",
            "tech_area",
        ),
        comments=_optional_string(data.get("comments")),
    )


def _parse_stig(
    data: dict[str, Any],
    *,
    checklist_uuid: UUID,
    stig_index: int,
) -> tuple[Stig, list[str]]:
    warnings: list[str] = []

    stig_id = _optional_string(data.get("stig_id"))
    stig_name = _optional_string(data.get("stig_name"))
    display_name = _optional_string(data.get("display_name"))
    release_info = _optional_string(data.get("release_info"))
    reference_identifier = _optional_string(data.get("reference_identifier"))

    source_stig_uuid = _parse_uuid(
        data.get("uuid"),
        context=f"stigs[{stig_index}].uuid",
        warnings=warnings,
    )

    stig_identity = stig_id or stig_name or f"index-{stig_index}"

    stig_uuid = source_stig_uuid or uuid5(
        NAMESPACE_URL,
        f"checklist:{checklist_uuid}:stig:{stig_identity}",
    )

    raw_rules = _list_or_empty(
        data.get("rules"),
        context=f"stigs[{stig_index}].rules",
        warnings=warnings,
    )

    rules: list[StigRule] = []

    for rule_index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            warnings.append(
                f"Skipping stigs[{stig_index}].rules[{rule_index}]: "
                f"expected object, received {type(raw_rule).__name__}."
            )
            continue

        rule, rule_warnings = _parse_rule(
            raw_rule,
            checklist_uuid=checklist_uuid,
            stig_uuid=stig_uuid,
            stig_id=stig_id,
            stig_index=stig_index,
            rule_index=rule_index,
        )

        rules.append(rule)
        warnings.extend(rule_warnings)

    declared_size = _optional_int(data.get("size"))

    if declared_size is not None and declared_size != len(rules):
        warnings.append(
            f"STIG {stig_id or stig_index} declares size={declared_size}, "
            f"but contains {len(rules)} imported rule records."
        )

    return (
        Stig(
            stig_uuid=stig_uuid,
            stig_id=stig_id,
            stig_name=stig_name,
            display_name=display_name or stig_name,
            release_info=release_info,
            reference_identifier=reference_identifier,
            source_rule_count=declared_size or len(rules),
            rules=rules,
        ),
        warnings,
    )


def _parse_rule(
    data: dict[str, Any],
    *,
    checklist_uuid: UUID,
    stig_uuid: UUID,
    stig_id: str | None,
    stig_index: int,
    rule_index: int,
) -> tuple[StigRule, list[str]]:
    warnings: list[str] = []

    vuln_id = _first_string(data, "vuln_id", "vuln_num")
    rule_id_source = _first_string(data, "rule_id_src", "rule_id")
    group_id_source = _first_string(data, "group_id_src", "group_id")

    rule_identity = vuln_id or rule_id_source or f"index-{rule_index}"

    source_rule_uuid = _parse_uuid(
        data.get("uuid"),
        context=f"stigs[{stig_index}].rules[{rule_index}].uuid",
        warnings=warnings,
    )

    rule_uuid = source_rule_uuid or uuid5(
        NAMESPACE_URL,
        (
            f"checklist:{checklist_uuid}:"
            f"stig:{stig_id or stig_uuid}:"
            f"rule:{rule_identity}"
        ),
    )

    source_stig_uuid = _parse_uuid(
        data.get("stig_uuid"),
        context=f"stigs[{stig_index}].rules[{rule_index}].stig_uuid",
        warnings=warnings,
    )

    if source_stig_uuid and source_stig_uuid != stig_uuid:
        warnings.append(
            f"Rule {rule_identity} has a stig_uuid that differs from its "
            f"parent STIG UUID. The parent STIG UUID was retained."
        )

    group_tree = _parse_group_tree(
        data.get("group_tree"),
        context=f"stigs[{stig_index}].rules[{rule_index}].group_tree",
        warnings=warnings,
    )

    check_content_ref = _parse_check_reference(
        data.get("check_content_ref"),
        context=f"stigs[{stig_index}].rules[{rule_index}].check_content_ref",
        warnings=warnings,
    )

    overrides = _object_or_empty(
        data.get("overrides"),
        context=f"stigs[{stig_index}].rules[{rule_index}].overrides",
        warnings=warnings,
    )

    override_severity = _severity(overrides.get("severity"))
    override = None

    if override_severity != Severity.UNKNOWN:
        override = RuleOverride(
            severity=override_severity,
            rationale=_first_string(
                overrides,
                "rationale",
                "comments",
                "reason",
            ),
        )

    return (
        StigRule(
            rule_uuid=rule_uuid,
            stig_uuid=stig_uuid,

            # Add this field to StigRule if it is not already present.
            vuln_id=vuln_id,

            group_id=_first_string(data, "group_id"),
            group_id_source=group_id_source,
            rule_id=_first_string(data, "rule_id"),
            rule_id_source=rule_id_source,
            rule_version=_optional_string(data.get("rule_version")),

            title=_first_string(data, "rule_title", "title"),
            severity=_severity(data.get("severity")),
            status=_finding_status(data.get("status")),

            classification=_optional_string(data.get("classification")),
            weight=_optional_string(data.get("weight")),
            discussion=_first_string(data, "discussion", "vuln_discuss"),
            check_content=_first_string(data, "check_content", "checkcontent"),
            fix_text=_first_string(data, "fix_text", "fixtext"),

            finding_details=_optional_string(data.get("finding_details")),
            comments=_optional_string(data.get("comments")),

            reference_identifier=_optional_string(
                data.get("reference_identifier")
            ),
            target_key=_optional_string(data.get("target_key")),
            check_content_ref=check_content_ref,

            ccis=_string_list(data.get("ccis")),
            legacy_ids=_string_list(data.get("legacy_ids")),
            group_tree=group_tree,

            override=override,
            created_at=_parse_datetime(data.get("created_at")),
            updated_at=_parse_datetime(data.get("updated_at")),
        ),
        warnings,
    )


def _parse_group_tree(
    value: Any,
    *,
    context: str,
    warnings: list[str],
) -> list[StigGroup]:
    groups: list[StigGroup] = []

    if value is None:
        return groups

    if not isinstance(value, list):
        warnings.append(f"{context} is not an array; ignoring it.")
        return groups

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            warnings.append(
                f"{context}[{index}] is not an object; ignoring it."
            )
            continue

        source_id = _first_string(item, "id", "group_id")

        if not source_id:
            warnings.append(
                f"{context}[{index}] has no id; assigning an import placeholder."
            )
            source_id = f"unknown-group-{index}"

        groups.append(
            StigGroup(
                source_id=source_id,
                title=_optional_string(item.get("title")),
                description=_optional_string(item.get("description")),
            )
        )

    return groups


def _parse_check_reference(
    value: Any,
    *,
    context: str,
    warnings: list[str],
) -> CheckReference | None:
    if value is None:
        return None

    if isinstance(value, str):
        return CheckReference(name=value)

    if not isinstance(value, dict):
        warnings.append(f"{context} is not an object or string; ignoring it.")
        return None

    name = _optional_string(value.get("name"))
    href = _optional_string(value.get("href"))

    if not name and not href:
        return None

    return CheckReference(name=name or href or "unnamed-reference", href=href)


def _finding_status(value: Any) -> FindingStatus:
    normalized = (_optional_string(value) or "").strip().lower()
    normalized = normalized.replace("-", "_").replace(" ", "_")

    mapping = {
        "not_a_finding": FindingStatus.NOT_A_FINDING,
        "notafinding": FindingStatus.NOT_A_FINDING,
        "not_applicable": FindingStatus.NOT_APPLICABLE,
        "notapplicable": FindingStatus.NOT_APPLICABLE,
        "open": FindingStatus.OPEN,
        "not_reviewed": FindingStatus.NOT_REVIEWED,
        "notreviewed": FindingStatus.NOT_REVIEWED,
        "nr": FindingStatus.NOT_REVIEWED,
        "na": FindingStatus.NOT_APPLICABLE,
        "nf": FindingStatus.NOT_A_FINDING,
        "op": FindingStatus.OPEN,
    }

    return mapping.get(normalized, FindingStatus.NOT_REVIEWED)


def _severity(value: Any) -> Severity:
    normalized = (_optional_string(value) or "").strip().lower()

    mapping = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "cat iii": Severity.LOW,
        "cat ii": Severity.MEDIUM,
        "cat i": Severity.HIGH,
    }

    return mapping.get(normalized, Severity.UNKNOWN)


def _parse_uuid(
    value: Any,
    *,
    context: str,
    warnings: list[str],
) -> UUID | None:
    text = _optional_string(value)

    if not text:
        return None

    try:
        return UUID(text)
    except ValueError:
        warnings.append(f"{context} is not a valid UUID: {text!r}.")
        return None


def _parse_datetime(value: Any) -> datetime | None:
    text = _optional_string(value)

    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        result = value.strip()
        return result or None

    if isinstance(value, (int, float, bool)):
        return str(value)

    return None


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"true", "1", "yes"}:
            return True

        if normalized in {"false", "0", "no"}:
            return False

    return None


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None

    return None


def _first_string(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = _optional_string(data.get(key))
        if value is not None:
            return value

    return None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []

    if isinstance(value, str):
        # Preserve a single string as one value rather than guessing whether
        # commas or spaces are part of an identifier.
        return [value] if value.strip() else []

    if not isinstance(value, list):
        return []

    results: list[str] = []

    for item in value:
        text = _optional_string(item)
        if text:
            results.append(text)

    return results


def _object_or_empty(
    value: Any,
    *,
    context: str,
    warnings: list[str],
) -> dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    warnings.append(
        f"{context} should be an object; received {type(value).__name__}."
    )
    return {}


def _list_or_empty(
    value: Any,
    *,
    context: str,
    warnings: list[str],
) -> list[Any]:
    if value is None:
        return []

    if isinstance(value, list):
        return value

    warnings.append(
        f"{context} should be an array; received {type(value).__name__}."
    )
    return []