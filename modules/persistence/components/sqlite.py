from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from SAVE.modules.persistence.interface import (
    ChecklistAlreadyExistsError,
    ChecklistNotFoundError,
    ChecklistSummary,
    PersistenceConfigurationError,
    PersistenceOptions,
    PersistenceResult,
    PersistenceTarget,
    PersistenceWriteMode,
)


class SQLiteChecklistStore:
    """
    SQLite implementation of SAVE's ChecklistStore contract.

    Version 1 stores each normalized checklist as a canonical JSON snapshot
    plus searchable summary metadata.

    A later schema migration may normalize STIGs, rules, findings, assets,
    artifacts, and audit records into additional relational tables.
    """

    target = PersistenceTarget.SQLITE

    def __init__(
        self,
        location: str | Path,
        options: PersistenceOptions,
        codec,
    ) -> None:
        self._path = Path(location)
        self.location = str(self._path)
        self._options = options
        self._codec = codec
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> "SQLiteChecklistStore":
        self.initialize()
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> None:
        self.close()

    def initialize(self) -> None:
        if self._connection is not None:
            return

        if not self._path.parent.exists():
            if not self._options.create_parent_directories:
                raise PersistenceConfigurationError(
                    f"SQLite parent directory does not exist: "
                    f"{self._path.parent}"
                )

            self._path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

        self._connection = sqlite3.connect(
            self._path,
            timeout=self._options.sqlite_timeout_seconds,
        )

        self._connection.row_factory = sqlite3.Row

        self._connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        if self._options.sqlite_enable_wal:
            self._connection.execute(
                "PRAGMA journal_mode = WAL"
            )

        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS save_schema (
                schema_key TEXT PRIMARY KEY,
                schema_value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS checklists (
                checklist_uuid TEXT PRIMARY KEY,
                title TEXT,
                source_format TEXT,
                source_filename TEXT,
                source_sha256 TEXT,
                imported_at TEXT,
                stored_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_checklists_stored_at
                ON checklists(stored_at DESC);

            CREATE INDEX IF NOT EXISTS idx_checklists_source_sha256
                ON checklists(source_sha256);
            """
        )

        self._connection.execute(
            """
            INSERT INTO save_schema (
                schema_key,
                schema_value
            )
            VALUES (
                'schema_version',
                '1'
            )
            ON CONFLICT(schema_key)
            DO NOTHING;
            """
        )

        self._connection.commit()

    def save(
        self,
        checklist,
        *,
        mode: PersistenceWriteMode = PersistenceWriteMode.UPSERT,
    ) -> PersistenceResult:
        connection = self._require_connection()

        checklist_uuid = str(checklist.checklist_uuid)
        payload_json = self._codec.encode(checklist)
        stored_at = datetime.now(timezone.utc)

        existing = connection.execute(
            """
            SELECT 1
            FROM checklists
            WHERE checklist_uuid = ?
            """,
            (checklist_uuid,),
        ).fetchone()

        exists = existing is not None

        if mode == PersistenceWriteMode.CREATE and exists:
            raise ChecklistAlreadyExistsError(
                f"Checklist already exists: {checklist_uuid}"
            )

        if mode == PersistenceWriteMode.REPLACE and not exists:
            raise ChecklistNotFoundError(
                f"Cannot replace missing checklist: {checklist_uuid}"
            )

        with connection:
            connection.execute(
                """
                INSERT INTO checklists (
                    checklist_uuid,
                    title,
                    source_format,
                    source_filename,
                    source_sha256,
                    imported_at,
                    stored_at,
                    payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(checklist_uuid)
                DO UPDATE SET
                    title = excluded.title,
                    source_format = excluded.source_format,
                    source_filename = excluded.source_filename,
                    source_sha256 = excluded.source_sha256,
                    imported_at = excluded.imported_at,
                    stored_at = excluded.stored_at,
                    payload_json = excluded.payload_json
                """,
                (
                    checklist_uuid,
                    checklist.title,
                    checklist.checklist_format.value,
                    checklist.source_filename,
                    checklist.source_sha256,
                    (
                        checklist.imported_at.isoformat()
                        if checklist.imported_at
                        else None
                    ),
                    stored_at.isoformat(),
                    payload_json,
                ),
            )

        return PersistenceResult(
            target=self.target,
            location=self.location,
            checklist_uuid=checklist.checklist_uuid,
            operation=mode,
            created=not exists,
            updated=exists,
            stored_at=stored_at,
        )

    def get(
        self,
        checklist_uuid: UUID,
    ):
        connection = self._require_connection()

        row = connection.execute(
            """
            SELECT payload_json
            FROM checklists
            WHERE checklist_uuid = ?
            """,
            (str(checklist_uuid),),
        ).fetchone()

        if row is None:
            raise ChecklistNotFoundError(
                f"Checklist not found: {checklist_uuid}"
            )

        return self._codec.decode(
            row["payload_json"]
        )

    def list_summaries(
        self,
        *,
        limit: int | None = None,
    ) -> list[ChecklistSummary]:
        connection = self._require_connection()

        query = """
            SELECT
                checklist_uuid,
                title,
                source_format,
                source_filename,
                source_sha256,
                imported_at,
                stored_at
            FROM checklists
            ORDER BY stored_at DESC
        """

        parameters: tuple = ()

        if limit is not None:
            query += " LIMIT ?"
            parameters = (limit,)

        rows = connection.execute(
            query,
            parameters,
        ).fetchall()

        return [
            ChecklistSummary(
                checklist_uuid=UUID(row["checklist_uuid"]),
                title=row["title"],
                source_format=row["source_format"],
                source_filename=row["source_filename"],
                source_sha256=row["source_sha256"],
                imported_at=_parse_datetime(row["imported_at"]),
                stored_at=_parse_datetime(row["stored_at"]),
            )
            for row in rows
        ]

    def delete(
        self,
        checklist_uuid: UUID,
    ) -> None:
        connection = self._require_connection()

        with connection:
            cursor = connection.execute(
                """
                DELETE FROM checklists
                WHERE checklist_uuid = ?
                """,
                (str(checklist_uuid),),
            )

        if cursor.rowcount == 0:
            raise ChecklistNotFoundError(
                f"Checklist not found: {checklist_uuid}"
            )

    def close(self) -> None:
        if self._connection is None:
            return

        self._connection.close()
        self._connection = None

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise PersistenceConfigurationError(
                "SQLite store is not initialized."
            )

        return self._connection


def create_sqlite_store(
    location: str | Path,
    options: PersistenceOptions,
    codec,
) -> SQLiteChecklistStore:
    """
    Factory registered by create_default_persistence_service().
    """
    return SQLiteChecklistStore(
        location=location,
        options=options,
        codec=codec,
    )


def _parse_datetime(
    value: str | None,
) -> datetime | None:
    if value is None:
        return None

    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )