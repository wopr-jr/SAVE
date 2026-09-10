from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from defusedxml import ElementTree as ET

from stig_ingest.model import (
    Asset,
    Checklist,
    ChecklistFormat,
    CheckReference,
    FindingStatus,
    Severity,
    Stig,
    StigGroup,
    StigRule,
)


class XccdfImportError(ValueError):
    """Raised when an XML document cannot be processed as XCCDF."""


@dataclass(slots=True)
class XccdfImportResult:
    checklist: Checklist
    warnings: list[str] = field(default_factory=list)


def import_xccdf(
    source: str | Path,
    *,
    checklist_uuid: UUID | None = None,
    include_test_results: bool = False,
    test_result_id: str | None = None,
) -> XccdfImportResult:
    """
    Import an XCCDF Benchmark into the normalized checklist model.

    Args:
        source:
            Path to an XCCDF XML file.

        checklist_uuid:
            A UUID previously persisted for this logical checklist. If absent,
            a new UUIDv4 is generated.

        include_test_results:
            When True, map XCCDF TestResult rule-result values to normalized
            finding statuses. When False, all imported rules are marked
            NOT_REVIEWED.

        test_result_id:
            Optional XCCDF TestResult @id to import. If omitted and multiple
            TestResult elements exist, the last one in document order is used.

    Notes:
        XCCDF benchmark content is not necessarily an assessment. Avoid
        treating a Benchmark-only file as evidence that rules pass or fail.
    """
    source_path = Path(source)

    if not source_path.is_file():
        raise FileNotFoundError(f"XCCDF file not found: {source_path}")

    warnings: list[str] = []
    source_sha256 = _sha256_file(source_path)
    resolved_checklist_uuid = checklist_uuid or uuid4()

    try:
        root = ET.parse(source_path).getroot()
    except ET.ParseError as exc:
        raise XccdfImportError(
            f"Invalid XML in {source_path.name}: {exc}"
        ) from exc

    if _local_name(root.tag).lower() != "benchmark":
        raise XccdfImportError(
            f"{source_path.name} does not contain an XCCDF Benchmark root element."
        )

    benchmark_id = _optional_string(root.attrib.get("id"))

    benchmark_title = _text(_first_child(root, "title"))
    benchmark_version = _text(_first_child(root, "version"))
    release_info = _release_info(root) or benchmark_version

    benchmark_identity = benchmark_id or benchmark_title or source_path.name

    stig_uuid = uuid5(
        NAMESPACE_URL,
        f"checklist:{resolved_checklist_uuid}:benchmark:{benchmark_identity}",
    )

    result_statuses: dict[str, FindingStatus] = {}
    target_asset: Asset | None = None

    if include_test_results:
        result_statuses, target_asset = _parse_test_results(
            root,
            requested_result_id=test_result_id,
            warnings=warnings,
        )

    rules: list[StigRule] = []

    # XCCDF allows Rule elements directly under Benchmark and nested under
    # one or more Group elements.
    _walk_xccdf_tree(
        parent=root,
        group_tree=[],
        rules=rules,
        checklist_uuid=resolved_checklist_uuid,
        stig_uuid=stig_uuid,
        benchmark_id=benchmark_id,
        result_statuses=result_statuses,
        warnings=warnings,
    )

    if not benchmark_id:
        warnings.append(
            "Benchmark has no id attribute; using title/file identity for generated UUIDs."
        )

    stig = Stig(
        stig_uuid=stig_uuid,
        # Preserve the source benchmark identifier exactly when present.
        stig_id=benchmark_id,
        stig_name=benchmark_title,
        display_name=benchmark_title,
        release_info=release_info,
        reference_identifier=_benchmark_reference(root),
        source_rule_count=len(rules),
        rules=rules,
    )

    checklist = Checklist(
        checklist_uuid=resolved_checklist_uuid,
        title=benchmark_title or source_path.name,
        checklist_format=ChecklistFormat.XCCDF,
        checklist_version=benchmark_version,
        source_filename=source_path.name,
        source_sha256=source_sha256,
        imported_at=datetime.now(timezone.utc),
        asset=target_asset,
        stigs=[stig],
    )

    return XccdfImportResult(
        checklist=checklist,
        warnings=warnings,
    )


def _walk_xccdf_tree(
    *,
    parent: ET.Element,
    group_tree: list[StigGroup],
    rules: list[StigRule],
    checklist_uuid: UUID,
    stig_uuid: UUID,
    benchmark_id: str | None,
    result_statuses: dict[str, FindingStatus],
    warnings: list[str],
) -> None:
    """
    Recursively traverse Benchmark -> Group -> Group -> Rule structure.
    """
    for child in list(parent):
        child_name = _local_name(child.tag).lower()

        if child_name == "group":
            source_id = _optional_string(child.attrib.get("id"))
            title = _text(_first_child(child, "title"))
            description = _text(_first_child(child, "description"))

            current_group = StigGroup(
                source_id=source_id or title or "unnamed-group",
                title=title,
                description=description,
            )

            _walk_xccdf_tree(
                parent=child,
                group_tree=[*group_tree, current_group],
                rules=rules,
                checklist_uuid=checklist_uuid,
                stig_uuid=stig_uuid,
                benchmark_id=benchmark_id,
                result_statuses=result_statuses,
                warnings=warnings,
            )

        elif child_name == "rule":
            rules.append(
                _parse_rule(
                    rule_element=child,
                    group_tree=group_tree,
                    checklist_uuid=checklist_uuid,
                    stig_uuid=stig_uuid,
                    benchmark_id=benchmark_id,
                    result_statuses=result_statuses,
                    rule_index=len(rules),
                    warnings=warnings,
                )
            )


def _parse_rule(
    *,
    rule_element: ET.Element,
    group_tree: list[StigGroup],
    checklist_uuid: UUID,
    stig_uuid: UUID,
    benchmark_id: str | None,
    result_statuses: dict[str, FindingStatus],
    rule_index: int,
    warnings: list[str],
) -> StigRule:
    rule_id_source = _optional_string(rule_element.attrib.get("id"))
    rule_id = _display_rule_id(rule_id_source)

    vuln_id, ccis, legacy_ids = _parse_identifiers(rule_element)

    rule_identity = vuln_id or rule_id_source or f"rule-index-{rule_index}"

    rule_uuid = uuid5(
        NAMESPACE_URL,
        (
            f"checklist:{checklist_uuid}:"
            f"benchmark:{benchmark_id or stig_uuid}:"
            f"rule:{rule_identity}"
        ),
    )

    title = _text(_first_child(rule_element, "title"))
    version = _text(_first_child(rule_element, "version"))
    description = _text(_first_child(rule_element, "description"))

    fix_text = _text(_first_child(rule_element, "fixtext"))
    check_reference = _parse_check_reference(rule_element)

    source_severity = _severity(rule_element.attrib.get("severity"))

    status = result_statuses.get(
        rule_id_source or "",
        FindingStatus.NOT_REVIEWED,
    )

    if not rule_id_source:
        warnings.append(
            f"Rule at index {rule_index} has no XCCDF id attribute."
        )

    group = group_tree[-1] if group_tree else None

    return StigRule(
        rule_uuid=rule_uuid,
        stig_uuid=stig_uuid,

        vuln_id=vuln_id,

        group_id=_display_group_id(group.source_id) if group else None,
        group_id_source=group.source_id if group else None,
        rule_id=rule_id,
        rule_id_source=rule_id_source,
        rule_version=version,

        title=title,
        severity=source_severity,
        status=status,

        weight=_optional_string(rule_element.attrib.get("weight")),
        discussion=_extract_discussion(description),
        check_content=_check_content(rule_element),
        fix_text=fix_text,

        reference_identifier=_rule_reference(rule_element),
        check_content_ref=check_reference,

        ccis=ccis,
        legacy_ids=legacy_ids,
        group_tree=list(group_tree),
    )


def _parse_test_results(
    root: ET.Element,
    *,
    requested_result_id: str | None,
    warnings: list[str],
) -> tuple[dict[str, FindingStatus], Asset | None]:
    """
    Read a selected XCCDF TestResult, if present.

    Rule-result values are mapped as:
      pass           -> NOT_A_FINDING
      fail           -> OPEN
      notapplicable  -> NOT_APPLICABLE
      all others     -> NOT_REVIEWED
    """
    test_results = _children(root, "TestResult")

    if not test_results:
        warnings.append(
            "include_test_results=True, but no TestResult element was found."
        )
        return {}, None

    selected: ET.Element | None = None

    if requested_result_id:
        for candidate in test_results:
            if candidate.attrib.get("id") == requested_result_id:
                selected = candidate
                break

        if selected is None:
            warnings.append(
                f"Requested TestResult id {requested_result_id!r} was not found."
            )
            return {}, None
    else:
        selected = test_results[-1]

        if len(test_results) > 1:
            warnings.append(
                "Multiple TestResult elements found; using the last element "
                "in document order. Supply test_result_id to select explicitly."
            )

    results: dict[str, FindingStatus] = {}

    for result in _children(selected, "rule-result"):
        idref = _optional_string(result.attrib.get("idref"))
        raw_status = _text(_first_child(result, "result"))

        if idref:
            results[idref] = _xccdf_result_status(raw_status)

    target_name = _text(_first_child(selected, "target"))
    target_address = _text(_first_child(selected, "target-address"))

    asset = None

    if target_name or target_address:
        asset = Asset(
            host_name=target_name,
            ip_address=target_address,
        )

    return results, asset


def _parse_identifiers(
    rule_element: ET.Element,
) -> tuple[str | None, list[str], list[str]]:
    vuln_id: str | None = None
    ccis: list[str] = []
    legacy_ids: list[str] = []

    for ident in _children(rule_element, "ident"):
        value = _text(ident)

        if not value:
            continue

        normalized = value.upper()

        if normalized.startswith("CCI-"):
            ccis.append(value)
        elif normalized.startswith("V-"):
            vuln_id = vuln_id or value
        else:
            legacy_ids.append(value)

    return vuln_id, ccis, legacy_ids


def _parse_check_reference(
    rule_element: ET.Element,
) -> CheckReference | None:
    """
    Extract the first Rule/check/check-content-ref reference, if present.
    """
    for check in _children(rule_element, "check"):
        reference = _first_child(check, "check-content-ref")

        if reference is None:
            continue

        name = _optional_string(reference.attrib.get("name"))
        href = _optional_string(reference.attrib.get("href"))

        if name or href:
            return CheckReference(
                name=name or href or "unnamed-reference",
                href=href,
            )

    return None


def _check_content(rule_element: ET.Element) -> str | None:
    """
    Return embedded check-content when available.

    Some XCCDF content uses check-content-ref instead; that data is preserved
    separately in StigRule.check_content_ref.
    """
    for check in _children(rule_element, "check"):
        content = _first_child(check, "check-content")

        if content is not None:
            return _text(content)

    return None


def _release_info(root: ET.Element) -> str | None:
    """
    DISA-style XCCDF content often uses plain-text id='release-info'.
    """
    for plain_text in _children(root, "plain-text"):
        plain_text_id = _optional_string(plain_text.attrib.get("id"))

        if plain_text_id and plain_text_id.lower() in {
            "release-info",
            "release_info",
            "releaseinfo",
        }:
            return _text(plain_text)

    return None


def _benchmark_reference(root: ET.Element) -> str | None:
    reference = _first_child(root, "reference")

    if reference is None:
        return None

    return (
        _optional_string(reference.attrib.get("href"))
        or _text(reference)
    )


def _rule_reference(rule_element: ET.Element) -> str | None:
    reference = _first_child(rule_element, "reference")

    if reference is None:
        return None

    return (
        _optional_string(reference.attrib.get("href"))
        or _text(reference)
    )


def _extract_discussion(description: str | None) -> str | None:
    """
    DISA XCCDF descriptions may contain escaped XML such as:

        <VulnDiscussion>...</VulnDiscussion>

    Return that component when available; otherwise preserve the original
    description text.
    """
    if not description:
        return None

    decoded = unescape(description)

    match = re.search(
        r"<VulnDiscussion>(.*?)</VulnDiscussion>",
        decoded,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return description

    content = match.group(1).strip()

    # Remove any residual markup without attempting to interpret it.
    content = re.sub(r"<[^>]+>", "", content)
    return unescape(content).strip() or None


def _xccdf_result_status(value: str | None) -> FindingStatus:
    normalized = (value or "").strip().lower()

    mapping = {
        "pass": FindingStatus.NOT_A_FINDING,
        "fail": FindingStatus.OPEN,
        "notapplicable": FindingStatus.NOT_APPLICABLE,
        "not_applicable": FindingStatus.NOT_APPLICABLE,
        "fixed": FindingStatus.NOT_A_FINDING,
        "informational": FindingStatus.NOT_REVIEWED,
        "notchecked": FindingStatus.NOT_REVIEWED,
        "notselected": FindingStatus.NOT_REVIEWED,
        "unknown": FindingStatus.NOT_REVIEWED,
        "error": FindingStatus.NOT_REVIEWED,
    }

    return mapping.get(normalized, FindingStatus.NOT_REVIEWED)


def _severity(value: str | None) -> Severity:
    normalized = (value or "").strip().lower()

    mapping = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }

    return mapping.get(normalized, Severity.UNKNOWN)


def _display_rule_id(rule_id_source: str | None) -> str | None:
    if not rule_id_source:
        return None

    for prefix in (
        "xccdf_mil.disa.stig_rule_",
        "xccdf_mil.disa.stig_rule.",
        "rule_",
    ):
        if rule_id_source.lower().startswith(prefix):
            return rule_id_source[len(prefix):]

    return rule_id_source


def _display_group_id(group_id_source: str | None) -> str | None:
    if not group_id_source:
        return None

    for prefix in (
        "xccdf_mil.disa.stig_group_",
        "xccdf_mil.disa.stig_group.",
        "group_",
    ):
        if group_id_source.lower().startswith(prefix):
            return group_id_source[len(prefix):]

    return group_id_source


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as source_file:
        for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _children(parent: ET.Element, name: str) -> list[ET.Element]:
    expected = name.lower()

    return [
        child
        for child in list(parent)
        if _local_name(child.tag).lower() == expected
    ]


def _first_child(parent: ET.Element, name: str) -> ET.Element | None:
    children = _children(parent, name)
    return children[0] if children else None


def _text(element: ET.Element | None) -> str | None:
    if element is None:
        return None

    value = "".join(element.itertext()).strip()
    return value or None


def _optional_string(value: object) -> str | None:
    if value is None:
        return None

    if isinstance(value, str):
        value = value.strip()
        return value or None

    return str(value)

