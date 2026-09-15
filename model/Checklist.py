from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID, uuid4

from SAVE.model.Stig import Stig
from SAVE.model.Asset import Asset

class ChecklistFormat(str, Enum):
    CKL = "ckl"
    CKLB = "cklb"
    CSV = "csv"
    XCCDF = "xccdf"

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