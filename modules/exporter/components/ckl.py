from __future__ import annotations

import re
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any, TYPE_CHECKING
from uuid import UUID
from xml.etree import ElementTree as ET

if TYPE_CHECKING:
    from SAVE.modules.exporter.interface import ExportOptions


XML_INVALID_CHARACTERS = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F]"
)


STATUS_TO_CKL = {
    "not_a_finding": "NotAFinding",
    "notapplicable": "Not_Applicable",
    "not_applicable": "Not_Applicable",
    "open": "Open",
    "not_reviewed": "Not_Reviewed",
    "notreviewed": "Not_Reviewed",
}


def export_ckl(
    checklist: Any,
    destination: str | Path,
    *,
    options: ExportOptions | None = None,
) -> list[str]:
    """
    Export a normalized SAVE Checklist as legacy CKL XML.

    Args:
        checklist:
            A normalized SAVE Checklist object.

        destination:
            Output CKL path.

        options:
            Shared SAVE ExportOptions.

    Returns:
        A list of non-fatal export warnings.

    Notes:
        The unified exporter interface handles atomic writes and destination
        validation. This component only creates the CKL XML document.
    """
    options = options or ExportOptions()
    destination_path = Path(destination)
    warnings: list[str] = []

    root = ET.Element("CHECKLIST")

    _write_asset(
        root=root,
        checklist=checklist,
        include_empty=options.include_empty_fields,
    )

    stigs_element = ET.SubElement(root, "STIGS")

    stigs = _get_attr(
        checklist,
        "stigs",
        default=[],
    ) or []

    if not stigs:
        warnings.append(
            "Checklist contains no STIG records; exported CKL will "
            "contain an empty STIGS element."
        )

    for stig_index, stig in enumerate(stigs):
        _write_stig(
            stigs_element=stigs_element,
            checklist=checklist,
            stig=stig,
            stig_index=stig_index,
            include_empty=options.include_empty_fields,
            warnings=warnings,
        )

    tree = ET.ElementTree(root)

    # ElementTree.indent() is available in Python 3.9+.
    ET.indent(
        tree,
        space="  ",
    )

    tree.write(
        destination_path,
        encoding="utf-8",
        xml_declaration=True,
    )

    return warnings


def _ckl_export_handler(
    checklist: Any,
    destination: Path,
    options: ExportOptions,
) -> list[str]:
    """
    Handler signature expected by SAVE's unified ExportService registry.
    """
    return export_ckl(
        checklist,
        destination,
        options=options,
    )


def _write_asset(
    *,
    root: ET.Element,
    checklist: Any,
    include_empty: bool,
) -> None:
    """
    Write the CKL CHECKLIST/ASSET section.
    """
    asset_element = ET.SubElement(
        root,
        "ASSET",
    )

    asset = _get_attr(
        checklist,
        "asset",
        default=None,
    )

    _add_text(
        asset_element,
        "ROLE",
        _get_attr(asset, "role"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "ASSET_TYPE",
        _get_attr(
            asset,
            "target_type",
            default="Computing",
        ),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "HOST_NAME",
        _get_attr(asset, "host_name"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "HOST_IP",
        _get_attr(asset, "ip_address"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "HOST_MAC",
        _get_attr(asset, "mac_address"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "HOST_FQDN",
        _get_attr(asset, "fqdn"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "TARGET_KEY",
        _get_attr(asset, "target_key"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "TECH_AREA",
        _get_attr(asset, "technology_area"),
        include_empty=True,
    )

    # These values may not be represented in the current normalized Asset
    # model. Emit empty elements so the legacy asset structure remains stable.
    _add_text(
        asset_element,
        "WEB_OR_DATABASE",
        _get_attr(
            asset,
            "is_web_database",
            default=False,
        ),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "WEB_DB_SITE",
        _get_attr(asset, "web_db_site"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "WEB_DB_INSTANCE",
        _get_attr(asset, "web_db_instance"),
        include_empty=True,
    )

    _add_text(
        asset_element,
        "WEB_COMMENTS",
        _get_attr(asset, "comments"),
        include_empty=True,
    )


def _write_stig(
    *,
    stigs_element: ET.Element,
    checklist: Any,
    stig: Any,
    stig_index: int,
    include_empty: bool,
    warnings: list[str],
) -> None:
    """
    Write one STIGS/iSTIG element and all contained VULN elements.
    """
    istig_element = ET.SubElement(
        stigs_element,
        "iSTIG",
    )

    _write_stig_info(
        istig_element=istig_element,
        checklist=checklist,
        stig=stig,
        include_empty=include_empty,
    )

    rules = _get_attr(
        stig,
        "rules",
        default=[],
    ) or []

    stig_id = _get_attr(stig, "stig_id")

    if not stig_id:
        warnings.append(
            f"STIG at index {stig_index} has no stig_id."
        )

    for rule_index, rule in enumerate(rules):
        _write_rule(
            istig_element=istig_element,
            stig=stig,
            stig_id=stig_id,
            rule=rule,
            rule_index=rule_index,
            include_empty=include_empty,
            warnings=warnings,
        )


def _write_stig_info(
    *,
    istig_element: ET.Element,
    checklist: Any,
    stig: Any,
    include_empty: bool,
) -> None:
    """
    Write iSTIG/STIG_INFO/SI_DATA values.

    CKL STIG_INFO records use repeated SI_DATA elements containing SID_NAME
    and SID_DATA children.
    """
    stig_info_element = ET.SubElement(
        istig_element,
        "STIG_INFO",
    )

    stig_uuid = _get_attr(
        stig,
        "stig_uuid",
        "uuid",
    )

    release_info = _get_attr(
        stig,
        "release_info",
    )

    _add_si_data(
        stig_info_element,
        "stigid",
        _get_attr(stig, "stig_id"),
        include_empty=include_empty,
    )

    _add_si_data(
        stig_info_element,
        "title",
        _get_attr(
            stig,
            "stig_name",
            "display_name",
        ),
        include_empty=include_empty,
    )

    _add_si_data(
        stig_info_element,
        "customname",
        _get_attr(stig, "display_name"),
        include_empty=include_empty,
    )

    _add_si_data(
        stig_info_element,
        "releaseinfo",
        release_info,
        include_empty=include_empty,
    )

    _add_si_data(
        stig_info_element,
        "version",
        release_info,
        include_empty=False,
    )

    _add_si_data(
        stig_info_element,
        "uuid",
        stig_uuid,
        include_empty=include_empty,
    )

    _add_si_data(
        stig_info_element,
        "filename",
        _get_attr(checklist, "source_filename"),
        include_empty=False,
    )

    _add_si_data(
        stig_info_element,
        "description",
        _get_attr(stig, "description"),
        include_empty=False,
    )

    _add_si_data(
        stig_info_element,
        "reference_identifier",
        _get_attr(stig, "reference_identifier"),
        include_empty=False,
    )


def _write_rule(
    *,
    istig_element: ET.Element,
    stig: Any,
    stig_id: str | None,
    rule: Any,
    rule_index: int,
    include_empty: bool,
    warnings: list[str],
) -> None:
    """
    Write one VULN record.

    CKL stores both source rule metadata and assessment values in the same
    VULN element.
    """
    vuln_element = ET.SubElement(
        istig_element,
        "VULN",
    )

    vuln_id = _get_attr(
        rule,
        "vuln_id",
        "vuln_num",
    )

    rule_id_source = _get_attr(
        rule,
        "rule_id_source",
        "rule_id_src",
    )

    rule_id = _get_attr(
        rule,
        "rule_id",
    )

    if not vuln_id:
        warnings.append(
            f"Rule {rule_index} in STIG {stig_id or '<unknown>'} "
            "has no vuln_id; CKL VULN_ATTRIBUTE Vuln_Num will be empty."
        )

    group_id_source = _get_attr(
        rule,
        "group_id_source",
        "group_id_src",
    )

    group_title = _get_attr(
        rule,
        "group_title",
    ) or _leaf_group_title(rule)

    severity = _enum_value(
        _get_attr(rule, "severity")
    )

    check_content_ref = _get_attr(
        rule,
        "check_content_ref",
    )

    check_content_ref_value = _get_attr(
        check_content_ref,
        "name",
    ) or _get_attr(
        check_content_ref,
        "href",
    )

    ccis = _get_attr(
        rule,
        "ccis",
        "cci_refs",
        default=[],
    ) or []

    legacy_ids = _get_attr(
        rule,
        "legacy_ids",
        default=[],
    ) or []

    # Required/common source-rule metadata.
    _add_stig_data(
        vuln_element,
        "Vuln_Num",
        vuln_id,
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Severity",
        severity,
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Group_Title",
        group_title,
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Group_ID",
        group_id_source,
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Rule_ID",
        rule_id_source or rule_id,
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Rule_Ver",
        _get_attr(rule, "rule_version"),
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Rule_Title",
        _get_attr(
            rule,
            "title",
            "rule_title",
        ),
        include_empty=True,
    )

    _add_stig_data(
        vuln_element,
        "Vuln_Discuss",
        _get_attr(rule, "discussion"),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "Check_Content",
        _get_attr(
            rule,
            "check_content",
            "checkcontent",
        ),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "Fix_Text",
        _get_attr(
            rule,
            "fix_text",
            "fixtext",
        ),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "Weight",
        _get_attr(rule, "weight"),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "Class",
        _get_attr(rule, "classification"),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "STIGRef",
        _get_attr(
            rule,
            "reference_identifier",
        ) or _get_attr(
            stig,
            "reference_identifier",
        ),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "TargetKey",
        _get_attr(rule, "target_key"),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "Check_Content_Ref",
        check_content_ref_value,
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "CCI_REF",
        _join_values(ccis),
        include_empty=include_empty,
    )

    _add_stig_data(
        vuln_element,
        "LEGACY_ID",
        _join_values(legacy_ids),
        include_empty=include_empty,
    )

    # Assessment-specific CKL values.
    _add_text(
        vuln_element,
        "STATUS",
        _status_to_ckl(
            _get_attr(rule, "status")
        ),
        include_empty=True,
    )

    _add_text(
        vuln_element,
        "FINDING_DETAILS",
        _get_attr(rule, "finding_details"),
        include_empty=True,
    )

    _add_text(
        vuln_element,
        "COMMENTS",
        _get_attr(rule, "comments"),
        include_empty=True,
    )

    override = _get_attr(
        rule,
        "override",
        "overrides",
    )

    override_severity = _enum_value(
        _get_attr(
            override,
            "severity",
        )
    )

    _add_text(
        vuln_element,
        "SEVERITY_OVERRIDE",
        override_severity,
        include_empty=True,
    )

    override_rationale = _get_attr(
        override,
        "rationale",
    )

    if override_rationale:
        warnings.append(
            f"Rule {vuln_id or rule_id_source or rule_index} contains "
            "override rationale text. Legacy CKL does not provide a "
            "dedicated override-rationale field; it was not exported."
        )

    group_tree = _get_attr(
        rule,
        "group_tree",
        default=[],
    ) or []

    if len(group_tree) > 1:
        warnings.append(
            f"Rule {vuln_id or rule_id_source or rule_index} contains a "
            "nested group hierarchy. CKL preserves only the leaf group "
            "identifier and title."
        )


def _add_si_data(
    parent: ET.Element,
    name: str,
    value: Any,
    *,
    include_empty: bool,
) -> None:
    """
    Add one STIG_INFO/SI_DATA entry.
    """
    if value is None and not include_empty:
        return

    si_data_element = ET.SubElement(
        parent,
        "SI_DATA",
    )

    _add_text(
        si_data_element,
        "SID_NAME",
        name,
        include_empty=True,
    )

    _add_text(
        si_data_element,
        "SID_DATA",
        value,
        include_empty=True,
    )


def _add_stig_data(
    vuln_element: ET.Element,
    attribute_name: str,
    attribute_value: Any,
    *,
    include_empty: bool,
) -> None:
    """
    Add one VULN/STIG_DATA entry.
    """
    if attribute_value is None and not include_empty:
        return

    stig_data_element = ET.SubElement(
        vuln_element,
        "STIG_DATA",
    )

    _add_text(
        stig_data_element,
        "VULN_ATTRIBUTE",
        attribute_name,
        include_empty=True,
    )

    _add_text(
        stig_data_element,
        "ATTRIBUTE_DATA",
        attribute_value,
        include_empty=True,
    )


def _add_text(
    parent: ET.Element,
    tag: str,
    value: Any,
    *,
    include_empty: bool,
) -> None:
    """
    Add an XML child element, normalizing model values to safe XML text.
    """
    if value is None and not include_empty:
        return

    child = ET.SubElement(
        parent,
        tag,
    )

    child.text = _xml_text(value)


def _get_attr(
    source: Any,
    *names: str,
    default: Any = None,
) -> Any:
    """
    Read the first non-None matching attribute.

    Alias support makes this component tolerant of model names such as:
      - rule_id_source / rule_id_src
      - group_id_source / group_id_src
      - title / rule_title
    """
    if source is None:
        return default

    for name in names:
        value = getattr(
            source,
            name,
            None,
        )

        if value is not None:
            return value

    return default


def _leaf_group_title(
    rule: Any,
) -> str | None:
    group_tree = _get_attr(
        rule,
        "group_tree",
        default=[],
    ) or []

    if not group_tree:
        return None

    leaf_group = group_tree[-1]

    return _get_attr(
        leaf_group,
        "title",
    )


def _join_values(
    values: list[Any],
) -> str | None:
    if not values:
        return None

    return "\n".join(
        _xml_text(value)
        for value in values
        if value is not None
    )


def _status_to_ckl(
    status: Any,
) -> str:
    """
    Convert SAVE normalized finding status to legacy CKL text.
    """
    normalized = _enum_value(status)

    if normalized is None:
        return "Not_Reviewed"

    key = normalized.strip().lower()

    return STATUS_TO_CKL.get(
        key,
        "Not_Reviewed",
    )


def _enum_value(
    value: Any,
) -> str | None:
    if value is None:
        return None

    if isinstance(value, Enum):
        return str(value.value)

    return str(value)


def _xml_text(
    value: Any,
) -> str:
    """
    Convert model values to XML-safe text.

    XML 1.0 does not permit several ASCII control characters. Remove them
    before passing content to ElementTree.
    """
    if value is None:
        return ""

    if isinstance(value, bool):
        text = "true" if value else "false"

    elif isinstance(value, UUID):
        text = str(value)

    elif isinstance(value, (datetime, date)):
        text = value.isoformat()

    elif isinstance(value, Enum):
        text = str(value.value)

    else:
        text = str(value)

    return XML_INVALID_CHARACTERS.sub(
        "",
        text,
    )