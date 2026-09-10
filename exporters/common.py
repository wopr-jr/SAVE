from __future__ import annotations

from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


def to_primitive(value: Any, *, omit_none: bool = False) -> Any:
    """
    Convert normalized dataclasses into JSON-compatible primitives.
    """
    if is_dataclass(value):
        result: dict[str, Any] = {}

        for field_info in fields(value):
            field_value = getattr(value, field_info.name)

            if omit_none and field_value is None:
                continue

            result[field_info.name] = to_primitive(
                field_value,
                omit_none=omit_none,
            )

        return result

    if isinstance(value, Enum):
        return value.value

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, list):
        return [
            to_primitive(item, omit_none=omit_none)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            to_primitive(item, omit_none=omit_none)
            for item in value
        ]

    if isinstance(value, dict):
        result = {}

        for key, item in value.items():
            if omit_none and item is None:
                continue

            result[str(key)] = to_primitive(
                item,
                omit_none=omit_none,
            )

        return result

    return value