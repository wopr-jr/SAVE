from __future__ import annotations

from dataclasses import dataclass

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