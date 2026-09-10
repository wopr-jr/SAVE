from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

# Prefer defusedxml when processing files from outside your trust boundary.
# pip install defusedxml
from defusedxml import ElementTree as ET

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


class CklImportError(ValueError):
    """Raised when a source file cannot be interpreted as a CKL."""


@dataclass(slots=True)
class CklImportResult:
    checklist: Checklist
    warnings: list[str] = field(default_factory=list)


def import_ckl(
    source: str | Path,
    *,
    checklist_uuid: UUID | None = None,
) -> CklImportResult:
    """
    Import a legacy CKL XML checklist into the normalized model.

    Args:
        source:
            Path to a .ckl file.

        checklist_uuid:
            A previously persisted checklist UUID, if this source is being
            re-imported or updated. If omitted, a UUIDv4 is generated.

    Returns:
        CklImportResult containing the normalized checklist and non-fatal
        parsing warnings.

    Important:
        Persist checklist.checklist_uuid after the initial import. Pass that
        same UUID on subsequent imports or use the persisted object during
        CKLB export.
    """
    source_path = Path(source)

    if not source_path.is_file():
        raise FileNotFoundError(f"CKL file not found: {source_path}")

    source_sha256 = _sha256_file(source_path)

    try:
        root = ET.parse(source_path).getroot()
    except ET.ParseError as exc:
        raise CklImportError(f"Invalid XML in CKL file {source_path.name}: {exc}") from exc

    if _local_name(root.tag).upper() != "CHECKLIST":
        raise CklImportError(
            f"{source_path.name} does not have CHECKLIST as its XML root element."
        )

    warnings: list[str] = []
    checklist_id = checklist_uuid or uuid4()

    asset_element = _first_child(root, "ASSET")
    asset = _parse_asset(asset_element) if asset_element is not None else None

    stigs_element = _first_child(root, "STIGS")
    if stigs_element is None:
        warnings.append("CKL contains no STIGS element.")
        stig_elements: list[ET.Element] = []
    else:
        stig_elements = _children(stigs_element, "iSTIG")

    stigs: list[Stig] = []

    for stig_index, stig_element in enumerate(stig_elements):
        stig, stig_warnings = _parse_stig(
            stig_element,
            checklist_uuid=checklist_id,
            stig_index=stig_index,
        )
        stigs.append(stig)
        warnings.extend(stig_warnings)

    checklist = Checklist(
        checklist_uuid=checklist_id,
        title=source_path.name,
        checklist_format=ChecklistFormat.CKL,
        checklist_version=None,
        source_filename=source_path.name,
        source_sha256=source_sha256,
        imported_at=datetime.now(timezone.utc),
        asset=asset,
        stigs=stigs,
    )

    return CklImportResult(checklist=checklist, warnings=warnings)


def _parse_asset(asset_element: ET.Element) -> Asset:
    """
    Parse the top-level CKL ASSET section.

    CKL elements are often empty rather than absent, so `_text()` normalizes
    blank strings to None.
    """
    return Asset(
        target_type=_text(_first_child(asset_element, "ASSET_TYPE")) or "Computing",
        host_name=_text(_first_child(asset_element, "HOST_NAME")),
        fqdn=_text(_first_child(asset_element, "HOST_FQDN")),
        ip_address=_text(_first_child(asset_element, "HOST_IP")),
        mac_address=_text(_first_child(asset_element, "HOST_MAC")),
        target_key=_text(_first_child(asset_element, "TARGET_KEY")),
        role=_text(_first_child(asset_element, "ROLE")),
        technology_area=_text(_first_child(asset_element, "TECH_AREA")),
        comments=_text(_first_child(asset_element, "COMMENTS")),
    )


def _parse_stig(
    stig_element: ET.Element,
    *,
    checklist_uuid: UUID,
    stig_index: int,
) -> tuple[Stig, list[str]]:
    warnings: list[str] = []

    stig_info = _first_child(stig_element, "STIG_INFO")
    stig_info_data = _name_value_map(
        stig_info,
        record_name="SI_DATA",
        key_name="SID_NAME",
        value_name="SID_DATA",
    )

    # CKL STIG_INFO keys are conventionally lower-case, such as:
    # stigid, title, releaseinfo, version, uuid, description.
    stig_id = stig_info_data.get("stigid")
    stig_name = stig_info_data.get("title")
    release_info = stig_info_data.get("releaseinfo")
    reference_identifier = stig_info_data.get("uuid")

    # The generated STIG UUID is stable for this normalized checklist.
    # A CKL may lack a STIG UUID, so this avoids regenerating a new UUID
    # every time the same persisted checklist is exported.
    stig_identity = stig_id or stig_name or f"stig-index-{stig_index}"
    stig_uuid = uuid5(
        NAMESPACE_URL,
        f"checklist:{checklist_uuid}:stig:{stig_identity}",
    )

    vuln_elements = _children(stig_element, "VULN")
    rules: list[StigRule] = []

    for rule_index, vuln_element in enumerate(vuln_elements):
        rule, rule_warnings = _parse_rule(
            vuln_element,
            checklist_uuid=checklist_uuid,
            stig_uuid=stig_uuid,
            stig_id=stig_id,
            rule_index=rule_index,
        )
        rules.append(rule)
        warnings.extend(rule_warnings)

    if not stig_id:
        warnings.append(
            f"STIG at index {stig_index} has no STIG_INFO/stigid value."
        )

    return (
        Stig(
            stig_uuid=stig_uuid,
            stig_id=stig_id,
            stig_name=stig_name,
            display_name=stig_name,
            release_info=release_info,
            reference_identifier=reference_identifier,
            # This is the number imported from this CKL, not necessarily
            # the total rule count in the originating XCCDF benchmark.
            source_rule_count=len(rules),
            rules=rules,
        ),
        warnings,
    )


def _parse_rule(
    vuln_element: ET.Element,
    *,
    checklist_uuid: UUID,
    stig_uuid: UUID,
    stig_id: str | None,
    rule_index: int,
) -> tuple[StigRule, list[str]]:
    warnings: list[str] = []

    stig_data = _name_value_map(
        vuln_element,
        record_name="STIG_DATA",
        key_name="VULN_ATTRIBUTE",
        value_name="ATTRIBUTE_DATA",
    )

    vuln_id = stig_data.get("vuln_num")
    raw_rule_id = stig_data.get("rule_id")
    raw_group_id = stig_data.get("group_id")

    # Prefer Vuln_Num for a checklist-local stable key. Fall back to Rule_ID.
    rule_identity = vuln_id or raw_rule_id or f"rule-index-{rule_index}"

    rule_uuid = uuid5(
        NAMESPACE_URL,
        (
            f"checklist:{checklist_uuid}:"
            f"stig:{stig_id or stig_uuid}:"
            f"rule:{rule_identity}"
        ),
    )

    status = _finding_status(_text(_first_child(vuln_element, "STATUS")))
    severity = _severity(stig_data.get("severity"))

    severity_override = _severity(
        _text(_first_child(vuln_element, "SEVERITY_OVERRIDE"))
    )

    override = None
    if severity_override != Severity.UNKNOWN:
        override = RuleOverride(severity=severity_override)

    group_title = stig_data.get("group_title")
    group_tree: list[StigGroup] = []

    # Traditional CKL files provide a Group_ID and Group_Title but do not
    # preserve a full nested XCCDF group hierarchy.
    if raw_group_id or group_title:
        group_tree.append(
            StigGroup(
                source_id=raw_group_id or group_title or "unknown-group",
                title=group_title,
            )
        )

    check_content_ref = stig_data.get("check_content_ref")
    check_reference = None
    if check_content_ref:
        check_reference = CheckReference(name=check_content_ref)

    if not vuln_id:
        warnings.append(
            f"Rule {rule_index} in STIG {stig_id or '<unknown>'} has no Vuln_Num."
        )

    if not raw_rule_id:
        warnings.append(
            f"Rule {vuln_id or rule_index} in STIG "
            f"{stig_id or '<unknown>'} has no Rule_ID."
        )

    rule = StigRule(
        rule_uuid=rule_uuid,
        stig_uuid=stig_uuid,

        # Add this field to the normalized StigRule dataclass.
        vuln_id=vuln_id,

        group_id=_display_group_id(raw_group_id),
        group_id_source=raw_group_id,
        rule_id=_display_rule_id(raw_rule_id),
        rule_id_source=raw_rule_id,
        rule_version=stig_data.get("rule_ver"),

        title=stig_data.get("rule_title"),
        severity=severity,
        status=status,

        classification=stig_data.get("classification"),
        weight=stig_data.get("weight"),
        discussion=stig_data.get("vuln_discuss"),
        check_content=stig_data.get("check_content"),
        fix_text=stig_data.get("fix_text"),

        finding_details=_text(_first_child(vuln_element, "FINDING_DETAILS")),
        comments=_text(_first_child(vuln_element, "COMMENTS")),

        reference_identifier=stig_data.get("stigref"),
        target_key=stig_data.get("targetkey"),
        check_content_ref=check_reference,

        cci_refs=_split_multivalue(stig_data.get("cci_ref")),
        legacy_ids=_split_multivalue(stig_data.get("legacy_id")),
        group_tree=group_tree,

        override=override,
    )

    return rule, warnings


def _name_value_map(
    parent: ET.Element | None,
    *,
    record_name: str,
    key_name: str,
    value_name: str,
) -> dict[str, str]:
    """
    Convert repeated XML records into a normalized dictionary.

    Example CKL STIG_DATA:

        <STIG_DATA>
            <VULN_ATTRIBUTE>Rule_ID</VULN_ATTRIBUTE>
            <ATTRIBUTE_DATA>SV-12345r1_rule</ATTRIBUTE_DATA>
        </STIG_DATA>
    """
    if parent is None:
        return {}

    values: dict[str, str] = {}

    for record in _children(parent, record_name):
        key = _text(_first_child(record, key_name))
        value = _text(_first_child(record, value_name))

        if key and value is not None:
            values[key.strip().lower()] = value

    return values


def _finding_status(value: str | None) -> FindingStatus:
    if not value:
        return FindingStatus.NOT_REVIEWED

    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")

    status_map = {
        "notafinding": FindingStatus.NOT_A_FINDING,
        "not_a_finding": FindingStatus.NOT_A_FINDING,
        "not_applicable": FindingStatus.NOT_APPLICABLE,
        "notapplicable": FindingStatus.NOT_APPLICABLE,
        "open": FindingStatus.OPEN,
        "not_reviewed": FindingStatus.NOT_REVIEWED,
        "notreviewed": FindingStatus.NOT_REVIEWED,
    }

    return status_map.get(normalized, FindingStatus.NOT_REVIEWED)


def _severity(value: str | None) -> Severity:
    if not value:
        return Severity.UNKNOWN

    normalized = value.strip().lower()

    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,

        # Optional category aliases encountered in some source material.
        "cat iii": Severity.LOW,
        "cat ii": Severity.MEDIUM,
        "cat i": Severity.HIGH,
    }

    return severity_map.get(normalized, Severity.UNKNOWN)


def _display_rule_id(rule_id_source: str | None) -> str | None:
    if not rule_id_source:
        return None

    value = rule_id_source.strip()

    for prefix in (
        "xccdf_mil.disa.stig_rule_",
        "xccdf_mil.disa.stig_rule.",
        "rule_",
    ):
        if value.lower().startswith(prefix):
            return value[len(prefix):]

    return value


def _display_group_id(group_id_source: str | None) -> str | None:
    if not group_id_source:
        return None

    value = group_id_source.strip()

    for prefix in (
        "xccdf_mil.disa.stig_group_",
        "xccdf_mil.disa.stig_group.",
        "group_",
    ):
        if value.lower().startswith(prefix):
            return value[len(prefix):]

    return value


def _split_multivalue(value: str | None) -> list[str]:
    """
    CKL values may contain comma-separated, newline-separated, or
    whitespace-separated identifiers. This is intentionally conservative:
    it preserves each non-empty token without attempting semantic validation.
    """
    if not value:
        return []

    normalized = value.replace("\r", "\n").replace(",", "\n")
    return [item.strip() for item in normalized.split("\n") if item.strip()]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _local_name(tag: str) -> str:
    """Return an XML local name, tolerating namespace-qualified tags."""
    return tag.rsplit("}", 1)[-1]


def _children(parent: ET.Element, name: str) -> list[ET.Element]:
    """Return direct children with a matching local tag name."""
    expected = name.upper()
    return [
        child
        for child in list(parent)
        if _local_name(child.tag).upper() == expected
    ]


def _first_child(parent: ET.Element, name: str) -> ET.Element | None:
    """Return the first direct child with a matching local tag name."""
    children = _children(parent, name)
    return children[0] if children else None


def _text(element: ET.Element | None) -> str | None:
    """Normalize absent and blank XML element text to None."""
    if element is None or element.text is None:
        return None

    value = element.text.strip()
    return value or None