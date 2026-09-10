from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable


from SAVE.exporters.cklb import export_cklb
from SAVE.exporters.csv_exporter import export_csv
from SAVE.exporters.normalized_json import export_normalized_json


class ExportFormat(str, Enum):
    """
    Supported SAVE output formats.

    Add future formats here as their exporters are implemented:
      - CKL
      - XLSX
      - HTML
      - PDF report
      - ARF
    """

    CKLB = "cklb"
    CSV = "csv"
    NORMALIZED_JSON = "normalized-json"


class ExportErrorBase(Exception):
    """Base exception for SAVE export failures."""


class UnsupportedExportFormatError(ExportErrorBase):
    """Raised when SAVE has no exporter for a requested format."""


class DestinationExistsError(ExportErrorBase):
    """Raised when export would overwrite a file without permission."""


@dataclass(slots=True)
class ExportOptions:
    """
    Common export configuration.

    Format-specific fields remain here so the CLI, future API, and batch jobs
    can use one shared request contract.
    """

    overwrite: bool = False
    create_parent_directories: bool = False
    atomic_write: bool = True

    # CKLB-specific options.
    cklb_version: str = "1.0"

    # Reserved for future exporter behavior.
    include_empty_fields: bool = False
    include_source_metadata: bool = True


@dataclass(slots=True)
class ExportResult:
    """
    Common output returned by all SAVE exporters.
    """

    destination: Path
    export_format: ExportFormat
    bytes_written: int
    warnings: list[str] = field(default_factory=list)


ExporterHandler = Callable[
    [Any, Path, ExportOptions],
    list[str] | None,
]


class ExportService:
    """
    Unified SAVE export service.

    Responsibilities:
      - Validate output format and destination.
      - Dispatch a normalized Checklist to the appropriate exporter.
      - Optionally write through a temporary file and atomically replace the
        final destination.
      - Return consistent export metadata.

    Non-responsibilities:
      - Format detection.
      - Importing source files.
      - SQLite persistence.
      - Normalized-model validation policy.
    """

    def __init__(self) -> None:
        self._handlers: dict[ExportFormat, ExporterHandler] = {
            ExportFormat.CKLB: self._export_cklb,
            ExportFormat.CSV: self._export_csv,
            ExportFormat.NORMALIZED_JSON: self._export_normalized_json,
        }

    def export_file(
        self,
        checklist: Any,
        destination: str | Path,
        *,
        export_format: ExportFormat | str,
        options: ExportOptions | None = None,
    ) -> ExportResult:
        """
        Export a normalized SAVE Checklist to a requested destination.

        Example:
            export_service.export_file(
                checklist,
                "output.cklb",
                export_format=ExportFormat.CKLB,
            )
        """
        options = options or ExportOptions()
        destination_path = Path(destination)
        resolved_format = self._resolve_format(export_format)

        self._validate_destination(
            destination_path,
            options=options,
        )

        handler = self._handlers.get(resolved_format)

        if handler is None:
            raise UnsupportedExportFormatError(
                f"SAVE has no exporter registered for "
                f"{resolved_format.value!r}."
            )

        warnings = self._extension_warnings(
            destination_path,
            resolved_format,
        )

        if options.atomic_write:
            handler_warnings = self._export_atomically(
                handler=handler,
                checklist=checklist,
                destination=destination_path,
                options=options,
            )
        else:
            handler_warnings = handler(
                checklist,
                destination_path,
                options,
            )

        if handler_warnings:
            warnings.extend(handler_warnings)

        return ExportResult(
            destination=destination_path,
            export_format=resolved_format,
            bytes_written=destination_path.stat().st_size,
            warnings=warnings,
        )

    def register_exporter(
        self,
        export_format: ExportFormat,
        handler: ExporterHandler,
    ) -> None:
        """
        Register a future SAVE exporter.

        Example:
            export_service.register_exporter(
                ExportFormat.CKL,
                export_ckl_adapter,
            )
        """
        self._handlers[export_format] = handler

    def _export_cklb(
        self,
        checklist: Any,
        destination: Path,
        options: ExportOptions,
    ) -> list[str]:
        export_cklb(
            checklist,
            destination,
            cklb_version=options.cklb_version,
        )

        return []

    def _export_csv(
        self,
        checklist: Any,
        destination: Path,
        options: ExportOptions,
    ) -> list[str]:
        export_csv(
            checklist,
            destination,
        )

        return []

    def _export_normalized_json(
        self,
        checklist: Any,
        destination: Path,
        options: ExportOptions,
    ) -> list[str]:
        export_normalized_json(
            checklist,
            destination,
        )

        return []

    def _export_atomically(
        self,
        *,
        handler: ExporterHandler,
        checklist: Any,
        destination: Path,
        options: ExportOptions,
    ) -> list[str] | None:
        """
        Write to a temporary file in the destination directory, then replace
        the final file only after the exporter completes successfully.
        """
        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)

            warnings = handler(
                checklist,
                temporary_path,
                options,
            )

            os.replace(
                temporary_path,
                destination,
            )

            return warnings

        except Exception:
            if temporary_path and temporary_path.exists():
                temporary_path.unlink(missing_ok=True)

            raise

    @staticmethod
    def _resolve_format(
        export_format: ExportFormat | str,
    ) -> ExportFormat:
        if isinstance(export_format, ExportFormat):
            return export_format

        try:
            return ExportFormat(export_format)
        except ValueError as exc:
            supported = ", ".join(
                format_type.value
                for format_type in ExportFormat
            )

            raise UnsupportedExportFormatError(
                f"Unsupported output format {export_format!r}. "
                f"Supported formats: {supported}."
            ) from exc

    @staticmethod
    def _validate_destination(
        destination: Path,
        *,
        options: ExportOptions,
    ) -> None:
        if destination.exists() and not options.overwrite:
            raise DestinationExistsError(
                f"Destination already exists: {destination}. "
                "Use overwrite=True to replace it."
            )

        if destination.parent.exists():
            return

        if not options.create_parent_directories:
            raise FileNotFoundError(
                f"Destination directory does not exist: "
                f"{destination.parent}"
            )

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    @staticmethod
    def _extension_warnings(
        destination: Path,
        export_format: ExportFormat,
    ) -> list[str]:
        expected_extensions = {
            ExportFormat.CKLB: {".cklb"},
            ExportFormat.CSV: {".csv"},
            ExportFormat.NORMALIZED_JSON: {".json"},
        }

        expected = expected_extensions[export_format]
        suffix = destination.suffix.lower()

        if suffix and suffix not in expected:
            return [
                f"Destination extension {suffix!r} does not normally match "
                f"requested format {export_format.value!r}. Expected one of: "
                f"{', '.join(sorted(expected))}."
            ]

        return []


default_export_service = ExportService()


def export_file(
    checklist: Any,
    destination: str | Path,
    *,
    export_format: ExportFormat | str,
    options: ExportOptions | None = None,
) -> ExportResult:
    """
    Convenience wrapper for normal CLI, script, and future API use.
    """
    return default_export_service.export_file(
        checklist,
        destination,
        export_format=export_format,
        options=options,
    )