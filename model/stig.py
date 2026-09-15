from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID, uuid4

from SAVE/model/stig_rule import *

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