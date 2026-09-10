from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4


class ChecklistFormat(str, Enum):
    CKL = "ckl"
    CKLB = "cklb"
    CSV = "csv"
    XCCDF = "xccdf"


class Severity(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    NOT_A_FINDING = "not_a_finding"
    NOT_APPLICABLE = "not_applicable"
    OPEN = "open"
    NOT_REVIEWED = "not_reviewed"


@dataclass(slots=True)
class CheckReference:
    name: str
    href: str | None = None


@dataclass(slots=True)
class StigGroup:
    source_id: str
    title: str | None = None
    description: str | None = None


@dataclass(slots=True)
class Asset:
    target_type: str = "Computing"
    host_name: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    target_key: str | None = None
    role: str | None = None
    technology_area: str | None = None
    comments: str | None = None


@dataclass(slots=True)
class RuleOverride:
    severity: Severity | None = None
    rationale: str | None = None


@dataclass(slots=True)
class StigRule:
    rule_uuid: UUID = field(default_factory=uuid4)
    stig_uuid: UUID = field(default_factory=uuid4)

    vuln_id: str | None = None
    group_id: str | None = None
    group_id_source: str | None = None
    rule_id: str | None = None
    rule_id_source: str | None = None
    rule_version: str | None = None

    title: str | None = None
    severity: Severity = Severity.UNKNOWN
    status: FindingStatus = FindingStatus.NOT_REVIEWED

    classification: str | None = None
    weight: str | None = None
    discussion: str | None = None
    check_content: str | None = None
    fix_text: str | None = None

    finding_details: str | None = None
    comments: str | None = None

    reference_identifier: str | None = None
    target_key: str | None = None
    check_content_ref: CheckReference | None = None

    cci_refs: list[str] = field(default_factory=list)
    legacy_ids: list[str] = field(default_factory=list)
    group_tree: list[StigGroup] = field(default_factory=list)

    override: RuleOverride | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


@dataclass(slots=True)
class Stig:
    stig_uuid: UUID = field(default_factory=uuid4)

    stig_id: str | None = None
    stig_name: str | None = None
    display_name: str | None = None
    release_info: str | None = None
    reference_identifier: str | None = None

    source_rule_count: int | None = None
    rules: list[StigRule] = field(default_factory=list)


@dataclass(slots=True)
class Checklist:
    checklist_uuid: UUID = field(default_factory=uuid4)

    title: str | None = None
    checklist_format: ChecklistFormat = ChecklistFormat.CKL
    checklist_version: str | None = None

    source_filename: str | None = None
    source_sha256: str | None = None
    imported_at: datetime | None = None

    asset: Asset | None = None
    stigs: list[Stig] = field(default_factory=list)

    active: bool | None = None
    mode: int | None = None
    has_path: bool | None = None