from __future__ import annotations

from typing import Protocol
import json

from SAVE.modules.exporter.common.export_common import (
    to_primitive,
)

class ChecklistCodec(Protocol):
    """
    Convert between a normalized Checklist object and JSON-compatible data.

    Every persistence backend uses the same codec.
    """

    def encode(self, checklist) -> str:
        """Serialize a normalized Checklist to JSON text."""
        ...

    def decode(self, payload: str):
        """Deserialize JSON text to a normalized Checklist."""
        ...

class JsonChecklistCodec:
    def encode(self, checklist) -> str:
        return json.dumps(
            to_primitive(
                checklist,
                omit_none=False,
            ),
            ensure_ascii=False,
            sort_keys=True,
        )

    def decode(self, payload: str):
        data = json.loads(payload)

        # Implement this after finalizing the normalized dataclass model.
        #
        # return checklist_from_dict(data)

        raise NotImplementedError(
            "Checklist JSON deserialization has not been implemented yet."
        )
