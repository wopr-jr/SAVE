from __future__ import annotations

import csv
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Mapping
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


class CsvImportError(ValueError):
    """Raised when a CSV source cannot be normalized."""


@dataclass(slots=True)
class CsvImportResult:
    checklist: Checklist
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class CsvColumnMap:
    """
    Explicit mapping from normalized field names to CSV header names.

    Example:
        CsvColumnMap(
            columns={
                "vuln_id": "Vulnerability ID",
                "rule_id": "Rule Identifier",
                "status": "Assessment Status",
                "comments": "Analyst Notes",
            }
        )

    If a field is not provided here, the importer tries its built-in aliases.
    """

    columns: Mapping[str, str] = field(default_factory=dict)


DEFAULT_ALIASES: dict[str, tuple[str, ...]] = {
    # Checklist-level metadata
    "checklist_title": (
        "checklist_title",
        "checklist name",
        "assessment title",
    ),
    "checklist_version": (
        "checklist_version",
        "cklb_version",
        "version",
    ),

    # Asset metadata
    "host_name": (
        "host_name",
        "hostname",
        "host",
        "target",
    ),
    "fqdn": (
        "fqdn",
        "host_fqdn",
    ),
    "ip_address": (
        "ip_address",
        "ip",
        "host_ip",
        "target_ip",
    ),
    "mac_address": (
        "mac_address",
        "mac",
        "host_mac",
    ),
    "target_key": (
        "target_key",
        "targetkey",
    ),
    "role": (
        "role",
        "asset_role",
    ),
    "technology_area": (
        "technology_area",
        "tech_area",
        "technology",
    ),
    "asset_comments": (
        "asset_comments",
        "host_comments",
    ),

    # STIG-level metadata
    "stig_id": (
        "stig_id",
        "stigid",
        "benchmark_id",
        "benchmark id",
    ),
    "stig_name": (
        "stig_name",
        "stig title",
        "benchmark_title",
        "benchmark title",
    ),
    "display_name": (
        "display_name",
        "display name",
    ),
    "release_info": (
        "release_info",
        "release info",
        "release",
        "release_version",
    ),
    "reference_identifier": (
        "reference_identifier",
        "reference id",
        "stig_ref",
    ),

    # Rule identity
    "vuln_id": (
        "vuln_id",
        "vuln_num",
        "vuln num",
        "vulnerability_id",
        "vulnerability id",
    ),
    "rule_id": (
        "rule_id",
        "rule id",
        "rule_identifier",
        "rule identifier",
    ),
    "rule_id_source": (
        "rule_id_src",
        "rule id src",
        "source_rule_id",
    ),
    "rule_version": (
        "rule_version",
        "rule ver",
        "rule_ver",
        "rule version",
    ),

    # Group hierarchy
    "group_id": (
        "group_id",
        "group id",
    ),
    "group_id_source": (
        "group_id_src",
        "group id src",
        "source_group_id",
    ),
    "group_title": (
        "group_title",
        "group title",
    ),

    # Rule content
    "rule_title": (
        "rule_title",
        "rule title",
        "title",
    ),
    "severity": (
        "severity",
        "cat",
        "category",
    ),
    "status": (
        "status",
        "finding_status",
        "finding status",
        "assessment_status",
        "assessment status",
    ),
    "weight": (
        "weight",
    ),
    "classification": (
        "classification",
        "class",
    ),
    "discussion": (
        "discussion",
        "vuln_discuss",
        "vulnerability discussion",
    ),
    "check_content": (
        "check_content",
        "check content",
        "checkcontent",
    ),
    "check_content_ref_name": (
        "check_content_ref_name",
        "check content ref name",
    ),
    "check_content_ref_href": (
        "check_content_ref_href",
        "check content ref href",
    ),
    "fix_text": (
        "fix_text",
        "fix text",
        "fixtext",
    ),

    # Assessment results
    "comments": (
        "comments",
        "comment",
        "analyst_comments",
        "analyst comments",
        "notes",
    ),
    "finding_details": (
        "finding_details",
        "finding details",
        "evidence",
        "evidence_details",
    ),
    "severity_override": (
        "severity_override",
        "severity override",
        "override_severity",
    ),
    "override_rationale": (
        "override_rationale",
        "override rationale",
        "override_comments",
    ),
    "created_at": (
        "created_at",
        "created",
    ),
    "updated_at": (
        "updated_at",
        "updated",
        "last_modified",
        "last modified",
    ),

    # References
    "ccis": (
        "ccis",
        "cci",
        "cci_ref",
        "cci refs",
    ),
    "legacy_ids": (
        "legacy_ids",
        "legacy id",
        "legacy_ids",
    ),
}


def import_csv(
    source: str | Path,
    *,
    column_map: CsvColumnMap | None = None,
    checklist_uuid: UUID | None = None,
    delimiter: str = ",",
    encoding: str = "utf-8-sig",
    default_stig_id: str | None = None,
    default_stig_name: str | None = None,
    default_asset: Asset | None = None,
) -> CsvImportResult:
    """
    Import a CSV assessment file into the normalized checklist model.

    This importer assumes all rows belong to one logical checklist. If the CSV
    contains multiple hosts, it retains the first target identity and emits
    warnings for inconsistent host data.

    Args:
        source:
            Path to the CSV file.

        column_map:
            Optional explicit normalized-field-to-header mapping.

        checklist_uuid:
            Persisted checklist UUID to reuse. A UUIDv4 is created when absent.

        delimiter:
            CSV delimiter. Use '\\t' for tab-separated files.

        encoding:
            Input encoding. UTF-8 with optional BOM is the default.

        default_stig_id/default_stig_name:
            Fallback STIG identity for CSV exports that do not include STIG
            metadata columns.

        default_asset:
            Optional asset object to use when CSV target columns are absent.
    """
    source_path = Path(source)

    if not source_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {source_path}")

    warnings: list[str] = []
    source_sha256 = _sha256_file(source_path)
    resolved_checklist_uuid = checklist_uuid or uuid4()
    mapping = column_map or CsvColumnMap()

    try:
        with source_path.open(
            "r",
            encoding=encoding,
            newline="",
        ) as source_file:
            reader = csv.DictReader(source_file, delimiter=delimiter)

            if not reader.fieldnames:
                raise CsvImportError("CSV source has no header row.")

            resolved_columns = _resolve_columns(
                reader.fieldnames,
                mapping,
                warnings,
            )

            rows = list(reader)

    except UnicodeDecodeError as exc:
        raise CsvImportError(
            f"Could not decode {source_path.name} using {encoding!r}."
        ) from exc

    if not rows:
        warnings.append("CSV contains a header row but no assessment rows.")

    checklist_title = _first_row_value(
        rows,
        resolved_columns,
        "checklist_title",
    ) or source_path.stem

    checklist_version = _first_row_value(
        rows,
        resolved_columns,
        "checklist_version",
    )

    asset = _build_asset(
        rows=rows,
        columns=resolved_columns,
        default_asset=default_asset,
        warnings=warnings,
    )

    stigs = _build_stigs(
        rows=rows,
        columns=resolved_columns,
        checklist_uuid=resolved_checklist_uuid,
        default_stig_id=default_stig_id,
        default_stig_name=default_stig_name,
        warnings=warnings,
    )

    checklist = Checklist(
        checklist_uuid=resolved_checklist_uuid,
        title=checklist_title,
        checklist_format=ChecklistFormat.CSV,
        checklist_version=checklist_version,
        source_filename=source_path.name,
        source_sha256=source_sha256,
        imported_at=datetime.now(),
        asset=asset,
        stigs=stigs,
    )

    return CsvImportResult(
        checklist=checklist,
        warnings=warnings,
    )


def _build_stigs(
    *,
    rows: list[dict[str, str]],
    columns: dict[str, str],
    checklist_uuid: UUID,
    default_stig_id: str | None,
    default_stig_name: str | None,
    warnings: list[str],
) -> list[Stig]:
    """
    Group source rows by STIG identity, then construct Stig and StigRule
    objects for each group.
    """
    stig_rows: dict[str, list[tuple[int, dict[str, str]]]] = {}

    for row_number, row in enumerate(rows, start=2):
        stig_id = _row_value(row, columns, "stig_id") or default_stig_id
        stig_name = _row_value(row, columns, "stig_name") or default_stig_name

        stig_identity = stig_id or stig_name or "unknown-stig"

        stig_rows.setdefault(stig_identity, []).append((row_number, row))

    stigs: list[Stig] = []

    for stig_index, (stig_identity, grouped_rows) in enumerate(stig_rows.items()):
        first_row = grouped_rows[0][1]

        stig_id = (
            _row_value(first_row, columns, "stig_id")
            or default_stig_id
        )
        stig_name = (
            _row_value(first_row, columns, "stig_name")
            or default_stig_name
        )

        display_name = (
            _row_value(first_row, columns, "display_name")
            or stig_name
        )

        release_info = _row_value(first_row, columns, "release_info")
        reference_identifier = _row_value(
            first_row,
            columns,
            "reference_identifier",
        )

        stig_uuid = uuid5(
            NAMESPACE_URL,
            f"checklist:{checklist_uuid}:stig:{stig_identity}",
        )

        rules: list[StigRule] = []
        seen_rule_keys: set[str] = set()

        for row_number, row in grouped_rows:
            rule = _build_rule(
                row=row,
                row_number=row_number,
                columns=columns,
                checklist_uuid=checklist_uuid,
                stig_uuid=stig_uuid,
                stig_id=stig_id,
                warnings=warnings,
            )

            if rule is None:
                continue

            rule_key = rule.vuln_id or rule.rule_id_source or str(rule.rule_uuid)

            if rule_key in seen_rule_keys:
                warnings.append(
                    f"CSV row {row_number}: duplicate rule identity "
                    f"{rule_key!r} in STIG {stig_id or stig_identity!r}; "
                    "duplicate row skipped."
                )
                continue

            seen_rule_keys.add(rule_key)
            rules.append(rule)

        if not stig_id and not stig_name:
            warnings.append(
                f"STIG group {stig_index} has no STIG ID or STIG name. "
                "Consider passing default_stig_id/default_stig_name."
            )

        stigs.append(
            Stig(
                stig_uuid=stig_uuid,
                stig_id=stig_id,
                stig_name=stig_name,
                display_name=display_name,
                release_info=release_info,
                reference_identifier=reference_identifier,
                source_rule_count=len(rules),
                rules=rules,
            )
        )

    return stigs


def _build_rule(
    *,
    row: dict[str, str],
    row_number: int,
    columns: dict[str, str],
    checklist_uuid: UUID,
    stig_uuid: UUID,
    stig_id: str | None,
    warnings: list[str],
) -> StigRule | None:
    vuln_id = _row_value(row, columns, "vuln_id")
    rule_id_source = (
        _row_value(row, columns, "rule_id_source")
        or _row_value(row, columns, "rule_id")
    )

    if not vuln_id and not rule_id_source:
        warnings.append(
            f"CSV row {row_number}: skipped because it has neither "
            "a vulnerability ID nor Rule ID."
        )
        return None

    rule_identity = vuln_id or rule_id_source

    rule_uuid = uuid5(
        NAMESPACE_URL,
        (
            f"checklist:{checklist_uuid}:"
            f"stig:{stig_id or stig_uuid}:"
            f"rule:{rule_identity}"
        ),
    )

    group_id_source = (
        _row_value(row, columns, "group_id_source")
        or _row_value(row, columns, "group_id")
    )

    group_title = _row_value(row, columns, "group_title")

    group_tree: list[StigGroup] = []

    if group_id_source or group_title:
        group_tree.append(
            StigGroup(
                source_id=group_id_source or group_title or "unknown-group",
                title=group_title,
            )
        )

    reference_name = _row_value(
        row,
        columns,
        "check_content_ref_name",
    )

    reference_href = _row_value(
        row,
        columns,
        "check_content_ref_href",
    )

    check_reference = None

    if reference_name or reference_href:
        check_reference = CheckReference(
            name=reference_name or reference_href or "unnamed-reference",
            href=reference_href,
        )

    override_severity = _severity(
        _row_value(row, columns, "severity_override")
    )

    override = None

    if override_severity != Severity.UNKNOWN:
        override = RuleOverride(
            severity=override_severity,
            rationale=_row_value(row, columns, "override_rationale"),
        )

    return StigRule(
        rule_uuid=rule_uuid,
        stig_uuid=stig_uuid,

        vuln_id=vuln_id,

        group_id=_display_group_id(
            _row_value(row, columns, "group_id")
            or group_id_source
        ),
        group_id_source=group_id_source,

        rule_id=_display_rule_id(
            _row_value(row, columns, "rule_id")
            or rule_id_source
        ),
        rule_id_source=rule_id_source,

        rule_version=_row_value(row, columns, "rule_version"),
        title=_row_value(row, columns, "rule_title"),

        severity=_severity(_row_value(row, columns, "severity")),
        status=_finding_status(_row_value(row, columns, "status")),

        classification=_row_value(row, columns, "classification"),
        weight=_row_value(row, columns, "weight"),
        discussion=_row_value(row, columns, "discussion"),
        check_content=_row_value(row, columns, "check_content"),
        fix_text=_row_value(row, columns, "fix_text"),

        reference_identifier=_row_value(
            row,
            columns,
            "reference_identifier",
        ),
        check_content_ref=check_reference,

        comments=_row_value(row, columns, "comments"),
        finding_details=_row_value(row, columns, "finding_details"),

        ccis=_split_identifiers(_row_value(row, columns, "ccis")),
        legacy_ids=_split_identifiers(
            _row_value(row, columns, "legacy_ids")
        ),

        group_tree=group_tree,
        override=override,

        created_at=_parse_datetime(
            _row_value(row, columns, "created_at")
        ),
        updated_at=_parse_datetime(
            _row_value(row, columns, "updated_at")
        ),
    )


def _build_asset(
    *,
    rows: list[dict[str, str]],
    columns: dict[str, str],
    default_asset: Asset | None,
    warnings: list[str],
) -> Asset | None:
    if not rows:
        return default_asset

    first_row = rows[0]

    host_name = _row_value(first_row, columns, "host_name")
    fqdn = _row_value(first_row, columns, "fqdn")
    ip_address = _row_value(first_row, columns, "ip_address")
    mac_address = _row_value(first_row, columns, "mac_address")
    target_key = _row_value(first_row, columns, "target_key")

    has_csv_asset_data = any(
        [
            host_name,
            fqdn,
            ip_address,
            mac_address,
            target_key,
        ]
    )

    if not has_csv_asset_data:
        return default_asset

    for row_number, row in enumerate(rows[1:], start=3):
        row_host = _row_value(row, columns, "host_name")
        row_ip = _row_value(row, columns, "ip_address")

        if row_host and host_name and row_host != host_name:
            warnings.append(
                f"CSV row {row_number}: host name {row_host!r} differs from "
                f"first-row host name {host_name!r}. This importer assumes "
                "one target per checklist."
            )

        if row_ip and ip_address and row_ip != ip_address:
            warnings.append(
                f"CSV row {row_number}: IP address {row_ip!r} differs from "
                f"first-row IP address {ip_address!r}. This importer assumes "
                "one target per checklist."
            )

    return Asset(
        target_type="Computing",
        host_name=host_name,
        fqdn=fqdn,
        ip_address=ip_address,
        mac_address=mac_address,
        target_key=target_key,
        role=_row_value(first_row, columns, "role"),
        technology_area=_row_value(
            first_row,
            columns,
            "technology_area",
        ),
        comments=_row_value(first_row, columns, "asset_comments"),
    )


def _resolve_columns(
    headers: list[str],
    column_map: CsvColumnMap,
    warnings: list[str],
) -> dict[str, str]:
    """
    Resolve each normalized field to one actual CSV header.

    Explicit mappings take precedence over aliases.
    """
    normalized_headers: dict[str, str] = {}

    for header in headers:
        normalized = _normalize_header(header)

        if normalized in normalized_headers:
            warnings.append(
                f"Duplicate normalized CSV header {normalized!r}: "
                f"{normalized_headers[normalized]!r} and {header!r}. "
                "The later header will be used."
            )

        normalized_headers[normalized] = header

    resolved: dict[str, str] = {}

    for field_name, aliases in DEFAULT_ALIASES.items():
        explicit_header = column_map.columns.get(field_name)

        if explicit_header:
            normalized_explicit = _normalize_header(explicit_header)
            actual_header = normalized_headers.get(normalized_explicit)

            if actual_header is None:
                warnings.append(
                    f"Explicit mapping for {field_name!r} references missing "
                    f"header {explicit_header!r}."
                )
                continue

            resolved[field_name] = actual_header
            continue

        for alias in aliases:
            actual_header = normalized_headers.get(_normalize_header(alias))

            if actual_header:
                resolved[field_name] = actual_header
                break

    if "vuln_id" not in resolved and "rule_id" not in resolved:
        warnings.append(
            "No Vuln ID or Rule ID column was resolved. Rows without a rule "
            "identifier will be skipped."
        )

    return resolved


def _row_value(
    row: dict[str, str],
    columns: dict[str, str],
    normalized_field: str,
) -> str | None:
    actual_column = columns.get(normalized_field)

    if not actual_column:
        return None

    value = row.get(actual_column)

    if value is None:
        return None

    value = value.strip()
    return value or None


def _first_row_value(
    rows: list[dict[str, str]],
    columns: dict[str, str],
    normalized_field: str,
) -> str | None:
    for row in rows:
        value = _row_value(row, columns, normalized_field)

        if value:
            return value

    return None


def _normalize_header(value: str) -> str:
    """
    Convert header labels such as 'Vuln ID', 'vuln-id', and 'VULN_ID'
    into a common value: 'vuln_id'.
    """
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    return value.strip("_")


def _split_identifiers(value: str | None) -> list[str]:
    """
    Split common multi-value cells while retaining meaningful identifiers.

    Accepted separators:
      - comma
      - semicolon
      - pipe
      - newline
    """
    if not value:
        return []

    parts = re.split(r"[,;|\r\n]+", value)

    return [
        part.strip()
        for part in parts
        if part.strip()
    ]


def _severity(value: str | None) -> Severity:
    normalized = (value or "").strip().lower()

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


def _finding_status(value: str | None) -> FindingStatus:
    normalized = (value or "").strip().lower()
    normalized = normalized.replace("-", "_").replace(" ", "_")

    mapping = {
        "not_a_finding": FindingStatus.NOT_A_FINDING,
        "notafinding": FindingStatus.NOT_A_FINDING,
        "nf": FindingStatus.NOT_A_FINDING,

        "not_applicable": FindingStatus.NOT_APPLICABLE,
        "notapplicable": FindingStatus.NOT_APPLICABLE,
        "na": FindingStatus.NOT_APPLICABLE,

        "open": FindingStatus.OPEN,
        "op": FindingStatus.OPEN,
        "fail": FindingStatus.OPEN,

        "not_reviewed": FindingStatus.NOT_REVIEWED,
        "notreviewed": FindingStatus.NOT_REVIEWED,
        "nr": FindingStatus.NOT_REVIEWED,
        "unknown": FindingStatus.NOT_REVIEWED,
    }

    return mapping.get(normalized, FindingStatus.NOT_REVIEWED)


def _display_rule_id(value: str | None) -> str | None:
    if not value:
        return None

    for prefix in (
        "xccdf_mil.disa.stig_rule_",
        "xccdf_mil.disa.stig_rule.",
        "rule_",
    ):
        if value.lower().startswith(prefix):
            return value[len(prefix):]

    return value


def _display_group_id(value: str | None) -> str | None:
    if not value:
        return None

    for prefix in (
        "xccdf_mil.disa.stig_group_",
        "xccdf_mil.disa.stig_group.",
        "group_",
    ):
        if value.lower().startswith(prefix):
            return value[len(prefix):]

    return value


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()