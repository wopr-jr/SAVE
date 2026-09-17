from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from SAVE.modules.model import Checklist
    from SAVE.modules.persistence.codec import ChecklistCodec


class PersistenceTarget(str, Enum):
    """
    Supported or planned persistence backends.
    """

    JSON_FILE = "json-file"
    SQLITE = "sqlite"
    REMOTE_SQL = "remote-sql"


class PersistenceWriteMode(str, Enum):
    """
    Controls behavior when a checklist UUID already exists.
    """

    CREATE = "create"
    REPLACE = "replace"
    UPSERT = "upsert"


class PersistenceErrorBase(Exception):
    """Base exception for SAVE persistence failures."""


class UnsupportedPersistenceTargetError(PersistenceErrorBase):
    """Raised when no backend is registered for a requested target."""


class ChecklistNotFoundError(PersistenceErrorBase):
    """Raised when a requested checklist UUID is absent."""


class ChecklistAlreadyExistsError(PersistenceErrorBase):
    """Raised when CREATE mode encounters an existing checklist UUID."""


class PersistenceConfigurationError(PersistenceErrorBase):
    """Raised for invalid backend configuration or store location."""


@dataclass(slots=True)
class PersistenceOptions:
    """
    Shared configuration for all persistence targets.
    """

    create_parent_directories: bool = False

    # SQLite-specific options.
    sqlite_timeout_seconds: float = 5.0
    sqlite_enable_wal: bool = True

    # Reserved for later backends.
    include_source_metadata: bool = True


@dataclass(slots=True)
class PersistenceResult:
    """
    Result returned after storing a checklist.
    """

    target: PersistenceTarget
    location: str
    checklist_uuid: UUID
    operation: PersistenceWriteMode
    created: bool
    updated: bool
    stored_at: datetime
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ChecklistSummary:
    """
    Lightweight checklist metadata for list/search views.

    Do not load full rule content merely to populate a future
    `save store list` command or web table.
    """

    checklist_uuid: UUID
    title: str | None
    source_format: str | None
    source_filename: str | None
    source_sha256: str | None
    imported_at: datetime | None
    stored_at: datetime


class ChecklistStore(Protocol):
    """
    Common repository contract for every persistence backend.
    """

    target: PersistenceTarget
    location: str

    def initialize(self) -> None:
        """Create or verify required persistence structures."""
        ...

    def save(
        self,
        checklist: Checklist,
        *,
        mode: PersistenceWriteMode = PersistenceWriteMode.UPSERT,
    ) -> PersistenceResult:
        """Create, replace, or upsert a normalized checklist."""
        ...

    def get(
        self,
        checklist_uuid: UUID,
    ) -> Checklist:
        """Return one fully populated normalized Checklist."""
        ...

    def list_summaries(
        self,
        *,
        limit: int | None = None,
    ) -> list[ChecklistSummary]:
        """Return lightweight checklist records."""
        ...

    def delete(
        self,
        checklist_uuid: UUID,
    ) -> None:
        """Delete one checklist by UUID."""
        ...

    def close(self) -> None:
        """Release any backend resources."""
        ...

    def __enter__(self) -> "ChecklistStore":
        ...

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        ...


StoreFactory = Callable[
    [str | Path, PersistenceOptions, ChecklistCodec],
    ChecklistStore,
]


class PersistenceService:
    """
    Unified SAVE persistence service.

    Like ImportService and ExportService, this class resolves a requested
    target to a registered implementation. Unlike exporters, it returns
    an open store object because persistence supports multiple operations.
    """

    def __init__(self) -> None:
        self._factories: dict[
            PersistenceTarget,
            StoreFactory,
        ] = {}

    def register_backend(
        self,
        target: PersistenceTarget,
        factory: StoreFactory,
    ) -> None:
        self._factories[target] = factory

    def open_store(
        self,
        *,
        target: PersistenceTarget | str,
        location: str | Path,
        codec: ChecklistCodec,
        options: PersistenceOptions | None = None,
    ) -> ChecklistStore:
        resolved_target = self._resolve_target(target)
        options = options or PersistenceOptions()

        factory = self._factories.get(resolved_target)

        if factory is None:
            raise UnsupportedPersistenceTargetError(
                f"SAVE has no persistence backend registered for "
                f"{resolved_target.value!r}."
            )

        store = factory(
            location,
            options,
            codec,
        )

        store.initialize()

        return store

    @staticmethod
    def _resolve_target(
        target: PersistenceTarget | str,
    ) -> PersistenceTarget:
        if isinstance(target, PersistenceTarget):
            return target

        if not isinstance(target, str):
            raise UnsupportedPersistenceTargetError(
                f"Unsupported persistence target type: "
                f"{type(target).__name__}."
            )

        requested = target.strip().lower()

        for persistence_target in PersistenceTarget:
            if requested == persistence_target.value:
                return persistence_target

        supported = ", ".join(
            persistence_target.value
            for persistence_target in PersistenceTarget
        )

        raise UnsupportedPersistenceTargetError(
            f"Unsupported persistence target {target!r}. "
            f"Supported targets: {supported}."
        )


def create_default_persistence_service() -> PersistenceService:
    """
    Create the standard SAVE persistence service.

    SQLite is the only registered backend initially. Add JSON-file and
    remote-SQL components later without changing CLI command logic.
    """
    from SAVE.modules.persistence.components.sqlite import (
        create_sqlite_store,
    )

    service = PersistenceService()

    service.register_backend(
        PersistenceTarget.SQLITE,
        create_sqlite_store,
    )

    return service


default_persistence_service = create_default_persistence_service()


def open_store(
    *,
    target: PersistenceTarget | str,
    location: str | Path,
    codec: ChecklistCodec,
    options: PersistenceOptions | None = None,
) -> ChecklistStore:
    """
    Convenience entry point for normal SAVE CLI and service use.
    """
    return default_persistence_service.open_store(
        target=target,
        location=location,
        codec=codec,
        options=options,
    )