from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from SAVE.modules.diff.interface import (
    ChecklistDiffResult,
    DiffAvailableMethod,
    DiffChangeKind,
    DiffEntry,
    DiffOptions,
    DiffScope,
    FieldChange,
)


CHECKLIST_FIELDS = (
    "title",
    "checklist_version",
    "active",
    "mode",
    "has_path",
)

ASSET_FIELDS = (
    "target_type",
    "host_name",
    "fqdn",
    "ip_address",
    "mac_address",
    "target_key",
    "role",
    "technology_area",
    "comments",
)

STIG_FIELDS = (
    "stig_id",
    "stig_name",
    "display_name",
    "release_info",
    "reference_identifier",
)

RULE_METADATA_FIELDS = (
    "vuln_id",
    "group_id",
    "group_id_source",
    "rule_id",
    "rule_id_source",
    "rule_version",
    "title",
    "severity",
    "weight",
    "classification",
    "discussion",
    "check_content",
    "fix_text",
    "reference_identifier",
    "target_key",
    "check_content_ref",
    "ccis",
    "legacy_ids",
    "group_tree",
)

RULE_ASSESSMENT_FIELDS = (
    "status",
    "comments",
    "finding_details",
    "override",
    "created_at",
    "updated_at",
)


def semantic_checklist_diff(
    previous,
    current,
    options: DiffOptions,
) -> ChecklistDiffResult:
    """
    Compare two normalized SAVE Checklist objects.

    The comparison focuses on semantic STIG and rule identity rather than
    comparing object memory addresses, source filenames, import timestamps,
    or checklist UUIDs.
    """
    result = ChecklistDiffResult(
        method=DiffAvailableMethod.SEMANTIC,
        previous_checklist_uuid=str(
            previous.checklist_uuid
        ),
        current_checklist_uuid=str(
            current.checklist_uuid
        ),
    )

    if options.compare_checklist_metadata:
        _compare_object_fields(
            result=result,
            scope=DiffScope.CHECKLIST,
            identity="checklist",
            previous=previous,
            current=current,
            field_names=CHECKLIST_FIELDS,
            options=options,
        )

    if options.compare_asset:
        _compare_asset(
            result=result,
            previous_asset=previous.asset,
            current_asset=current.asset,
            options=options,
        )

    previous_stigs = _index_items(
        items=previous.stigs,
        identity_function=_stig_identity,
        item_label="previous STIG",
        warnings=result.warnings,
    )

    current_stigs = _index_items(
        items=current.stigs,
        identity_function=_stig_identity,
        item_label="current STIG",
        warnings=result.warnings,
    )

    all_stig_keys = sorted(
        set(previous_stigs) | set(current_stigs)
    )

    for stig_key in all_stig_keys:
        previous_stig = previous_stigs.get(stig_key)
        current_stig = current_stigs.get(stig_key)

        if previous_stig is None:
            result.entries.append(
                DiffEntry(
                    scope=DiffScope.STIG,
                    change_kind=DiffChangeKind.ADDED,
                    identity=stig_key,
                )
            )

            _add_all_rules(
                result=result,
                stig=current_stig,
                stig_identity=stig_key,
            )
            continue

        if current_stig is None:
            result.entries.append(
                DiffEntry(
                    scope=DiffScope.STIG,
                    change_kind=DiffChangeKind.REMOVED,
                    identity=stig_key,
                )
            )

            _remove_all_rules(
                result=result,
                stig=previous_stig,
                stig_identity=stig_key,
            )
            continue

        if options.compare_stig_metadata:
            _compare_object_fields(
                result=result,
                scope=DiffScope.STIG,
                identity=stig_key,
                previous=previous_stig,
                current=current_stig,
                field_names=STIG_FIELDS,
                options=options,
            )

        _compare_rules(
            result=result,
            previous_stig=previous_stig,
            current_stig=current_stig,
            stig_identity=stig_key,
            options=options,
        )

    return result


def _compare_asset(
    *,
    result: ChecklistDiffResult,
    previous_asset,
    current_asset,
    options: DiffOptions,
) -> None:
    if previous_asset is None and current_asset is None:
        return

    if previous_asset is None:
        result.entries.append(
            DiffEntry(
                scope=DiffScope.ASSET,
                change_kind=DiffChangeKind.ADDED,
                identity="asset",
            )
        )
        return

    if current_asset is None:
        result.entries.append(
            DiffEntry(
                scope=DiffScope.ASSET,
                change_kind=DiffChangeKind.REMOVED,
                identity="asset",
            )
        )
        return

    _compare_object_fields(
        result=result,
        scope=DiffScope.ASSET,
        identity="asset",
        previous=previous_asset,
        current=current_asset,
        field_names=ASSET_FIELDS,
        options=options,
    )


def _compare_rules(
    *,
    result: ChecklistDiffResult,
    previous_stig,
    current_stig,
    stig_identity: str,
    options: DiffOptions,
) -> None:
    previous_rules = _index_items(
        items=previous_stig.rules,
        identity_function=_rule_identity,
        item_label=f"previous rule in {stig_identity}",
        warnings=result.warnings,
    )

    current_rules = _index_items(
        items=current_stig.rules,
        identity_function=_rule_identity,
        item_label=f"current rule in {stig_identity}",
        warnings=result.warnings,
    )

    all_rule_keys = sorted(
        set(previous_rules) | set(current_rules)
    )

    for rule_key in all_rule_keys:
        previous_rule = previous_rules.get(rule_key)
        current_rule = current_rules.get(rule_key)

        if previous_rule is None:
            result.entries.append(
                DiffEntry(
                    scope=DiffScope.RULE,
                    change_kind=DiffChangeKind.ADDED,
                    identity=rule_key,
                    parent_identity=stig_identity,
                )
            )
            continue

        if current_rule is None:
            result.entries.append(
                DiffEntry(
                    scope=DiffScope.RULE,
                    change_kind=DiffChangeKind.REMOVED,
                    identity=rule_key,
                    parent_identity=stig_identity,
                )
            )
            continue

        field_names: list[str] = []

        if options.compare_rule_metadata:
            field_names.extend(
                RULE_METADATA_FIELDS
            )

        if options.compare_assessment_data:
            field_names.extend(
                RULE_ASSESSMENT_FIELDS
            )

        _compare_object_fields(
            result=result,
            scope=DiffScope.RULE,
            identity=rule_key,
            parent_identity=stig_identity,
            previous=previous_rule,
            current=current_rule,
            field_names=tuple(field_names),
            options=options,
        )


def _add_all_rules(
    *,
    result: ChecklistDiffResult,
    stig,
    stig_identity: str,
) -> None:
    for rule in stig.rules:
        result.entries.append(
            DiffEntry(
                scope=DiffScope.RULE,
                change_kind=DiffChangeKind.ADDED,
                identity=_rule_identity(rule),
                parent_identity=stig_identity,
            )
        )


def _remove_all_rules(
    *,
    result: ChecklistDiffResult,
    stig,
    stig_identity: str,
) -> None:
    for rule in stig.rules:
        result.entries.append(
            DiffEntry(
                scope=DiffScope.RULE,
                change_kind=DiffChangeKind.REMOVED,
                identity=_rule_identity(rule),
                parent_identity=stig_identity,
            )
        )


def _compare_object_fields(
    *,
    result: ChecklistDiffResult,
    scope: DiffScope,
    identity: str,
    previous,
    current,
    field_names: tuple[str, ...],
    options: DiffOptions,
    parent_identity: str | None = None,
) -> None:
    changes: list[FieldChange] = []

    for field_name in field_names:
        if field_name in options.ignored_fields:
            continue

        previous_value = getattr(
            previous,
            field_name,
            None,
        )

        current_value = getattr(
            current,
            field_name,
            None,
        )

        comparable_previous = _make_comparable(
            previous_value,
            max_length=options.max_value_length,
        )

        comparable_current = _make_comparable(
            current_value,
            max_length=options.max_value_length,
        )

        if comparable_previous == comparable_current:
            continue

        changes.append(
            FieldChange(
                field_name=field_name,
                previous_value=comparable_previous,
                current_value=comparable_current,
            )
        )

    if changes:
        result.entries.append(
            DiffEntry(
                scope=scope,
                change_kind=DiffChangeKind.MODIFIED,
                identity=identity,
                parent_identity=parent_identity,
                field_changes=changes,
            )
        )

    elif options.include_unchanged:
        result.entries.append(
            DiffEntry(
                scope=scope,
                change_kind=DiffChangeKind.UNCHANGED,
                identity=identity,
                parent_identity=parent_identity,
            )
        )


def _index_items(
    *,
    items,
    identity_function,
    item_label: str,
    warnings: list[str],
) -> dict[str, Any]:
    """
    Build an identity map while preserving duplicate records as unique keys.

    Duplicate semantic identifiers are a data-quality warning because SAVE
    cannot safely infer which duplicate should match the other checklist.
    """
    indexed: dict[str, Any] = {}

    for index, item in enumerate(items):
        identity = identity_function(item)

        if identity not in indexed:
            indexed[identity] = item
            continue

        duplicate_identity = f"{identity}#duplicate-{index}"

        warnings.append(
            f"Duplicate {item_label} identity {identity!r}; "
            f"using synthetic identity {duplicate_identity!r}."
        )

        indexed[duplicate_identity] = item

    return indexed


def _stig_identity(
    stig,
) -> str:
    return (
        getattr(stig, "stig_id", None)
        or str(getattr(stig, "stig_uuid", ""))
        or getattr(stig, "display_name", None)
        or getattr(stig, "stig_name", None)
        or "unknown-stig"
    )


def _rule_identity(
    rule,
) -> str:
    return (
        getattr(rule, "vuln_id", None)
        or getattr(rule, "rule_id_source", None)
        or getattr(rule, "rule_id", None)
        or str(getattr(rule, "rule_uuid", ""))
        or "unknown-rule"
    )


def _make_comparable(
    value: Any,
    *,
    max_length: int,
) -> Any:
    """
    Convert rich SAVE model values to deterministic display values.
    """
    if isinstance(value, Enum):
        return value.value

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if is_dataclass(value):
        return _make_comparable(
            asdict(value),
            max_length=max_length,
        )

    if isinstance(value, list):
        return [
            _make_comparable(
                item,
                max_length=max_length,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            _make_comparable(
                item,
                max_length=max_length,
            )
            for item in value
        ]

    if isinstance(value, set):
        return sorted(
            _make_comparable(
                item,
                max_length=max_length,
            )
            for item in value
        )

    if isinstance(value, dict):
        return {
            str(key): _make_comparable(
                item,
                max_length=max_length,
            )
            for key, item in sorted(
                value.items(),
                key=lambda item: str(item[0]),
            )
        }

    if isinstance(value, str) and len(value) > max_length:
        return (
            value[:max_length]
            + f"... [truncated; original length={len(value)}]"
        )

    return value