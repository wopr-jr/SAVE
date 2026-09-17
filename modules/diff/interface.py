from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from SAVE.model.checklist import Checklist


class DiffAvailableMethod(str, Enum):
    """
    Registered SAVE checklist comparison methods.
    """

    SEMANTIC = "semantic"


class DiffChangeKind(str, Enum):
    """
    Type of detected difference.
    """

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    UNCHANGED = "unchanged"


class DiffScope(str, Enum):
    """
    Domain object affected by a diff entry.
    """

    CHECKLIST = "checklist"
    ASSET = "asset"
    STIG = "stig"
    RULE = "rule"


class DiffErrorBase(Exception):
    """Base exception for SAVE diff failures."""


class UnsupportedDiffMethodError(DiffErrorBase):
    """Raised when a requested diff method is not registered."""


@dataclass(slots=True)
class FieldChange:
    """
    One changed field on a matched object.

    Values are intentionally JSON-compatible display values rather than
    raw model values such as Enum, UUID, datetime, or nested dataclasses.
    """

    field_name: str
    previous_value: object
    current_value: object


@dataclass(slots=True)
class DiffEntry:
    """
    One added, removed, modified, or unchanged domain object.
    """

    scope: DiffScope
    change_kind: DiffChangeKind
    identity: str
    parent_identity: str | None = None
    field_changes: list[FieldChange] = field(
        default_factory=list
    )


@dataclass(slots=True)
class ChecklistDiffResult:
    """
    Full structured result from comparing two normalized checklists.
    """

    method: DiffAvailableMethod

    previous_checklist_uuid: str
    current_checklist_uuid: str

    entries: list[DiffEntry] = field(
        default_factory=list
    )

    warnings: list[str] = field(
        default_factory=list
    )

    @property
    def added(self) -> list[DiffEntry]:
        return [
            entry
            for entry in self.entries
            if entry.change_kind == DiffChangeKind.ADDED
        ]

    @property
    def removed(self) -> list[DiffEntry]:
        return [
            entry
            for entry in self.entries
            if entry.change_kind == DiffChangeKind.REMOVED
        ]

    @property
    def modified(self) -> list[DiffEntry]:
        return [
            entry
            for entry in self.entries
            if entry.change_kind == DiffChangeKind.MODIFIED
        ]

    @property
    def unchanged(self) -> list[DiffEntry]:
        return [
            entry
            for entry in self.entries
            if entry.change_kind == DiffChangeKind.UNCHANGED
        ]


@dataclass(slots=True)
class DiffOptions:
    """
    Configuration shared by SAVE diff implementations.
    """

    include_unchanged: bool = False

    compare_asset: bool = True
    compare_checklist_metadata: bool = True
    compare_stig_metadata: bool = True
    compare_rule_metadata: bool = True
    compare_assessment_data: bool = True

    # Keep CLI/API diff output manageable when large check/fix text changes.
    max_value_length: int = 500

    # Allow callers to suppress specific semantic fields.
    ignored_fields: set[str] = field(
        default_factory=set
    )


DiffHandler = Callable[
    ["Checklist", "Checklist", DiffOptions],
    ChecklistDiffResult,
]


class DiffService:
    """
    Unified SAVE checklist comparison service.

    The service resolves a comparison method to a registered implementation.
    """

    def __init__(self) -> None:
        self._handlers: dict[
            DiffAvailableMethod,
            DiffHandler,
        ] = {}

    def register_method(
        self,
        method: DiffAvailableMethod,
        handler: DiffHandler,
    ) -> None:
        self._handlers[method] = handler

    def diff(
        self,
        previous: Checklist,
        current: Checklist,
        *,
        method: DiffAvailableMethod | str = (
            DiffAvailableMethod.SEMANTIC
        ),
        options: DiffOptions | None = None,
    ) -> ChecklistDiffResult:
        """
        Compare two normalized Checklist objects.
        """
        resolved_method = self._resolve_method(method)
        options = options or DiffOptions()

        handler = self._handlers.get(resolved_method)

        if handler is None:
            raise UnsupportedDiffMethodError(
                f"SAVE has no diff handler registered for "
                f"{resolved_method.value!r}."
            )

        return handler(
            previous,
            current,
            options,
        )

    @staticmethod
    def _resolve_method(
        method: DiffAvailableMethod | str,
    ) -> DiffAvailableMethod:
        if isinstance(method, DiffAvailableMethod):
            return method

        if not isinstance(method, str):
            raise UnsupportedDiffMethodError(
                f"Unsupported diff method type: "
                f"{type(method).__name__}."
            )

        requested = method.strip().lower()

        for diff_method in DiffAvailableMethod:
            if requested == diff_method.value:
                return diff_method

        supported = ", ".join(
            diff_method.value
            for diff_method in DiffAvailableMethod
        )

        raise UnsupportedDiffMethodError(
            f"Unsupported diff method {method!r}. "
            f"Supported methods: {supported}."
        )


def create_default_diff_service() -> DiffService:
    """
    Build the standard SAVE diff service.
    """
    from SAVE.modules.diff.components.semantic import (
        semantic_checklist_diff,
    )

    service = DiffService()

    service.register_method(
        DiffAvailableMethod.SEMANTIC,
        semantic_checklist_diff,
    )

    return service


default_diff_service = create_default_diff_service()


def diff_checklists(
    previous: Checklist,
    current: Checklist,
    *,
    method: DiffAvailableMethod | str = (
        DiffAvailableMethod.SEMANTIC
    ),
    options: DiffOptions | None = None,
) -> ChecklistDiffResult:
    """
    Convenience entry point for normal CLI, API, and future web use.
    """
    return default_diff_service.diff(
        previous,
        current,
        method=method,
        options=options,
    )