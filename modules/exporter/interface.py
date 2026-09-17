from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from SAVE.modules.exporter.common.export_common import (
    ExportAvailableFormat,
)

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
    export_format: ExportAvailableFormat
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
        self._handlers: dict[ExportAvailableFormat, ExporterHandler] = {
        }

    def export_file(
        self,
        checklist: Any,
        destination: str | Path,
        *,
        export_format: ExportAvailableFormat | str,
        options: ExportOptions | None = None,
    ) -> ExportResult:
        """
        Export a normalized SAVE Checklist to a requested destination.

        Example:
            export_service.export_file(
                checklist,
                "output.cklb",
                export_format=ExportAvailableFormat.CKLB,
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
        export_format: ExportAvailableFormat,
        handler: ExporterHandler,
    ) -> None:
        """
        Register a future SAVE exporter.

        Example:
            export_service.register_exporter(
                ExportAvailableFormat.CKL,
                export_ckl_adapter,
            )
        """
        self._handlers[export_format] = handler

    

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
        export_format: ExportAvailableFormat | str,
    ) -> ExportAvailableFormat:
        """
        Resolve only canonical SAVE export-format names.

        Accepted examples:
            ExportAvailableFormat.CKLB
            "cklb"
            "csv"
            "normalized-json"
        """
        if isinstance(export_format, ExportAvailableFormat):
            return export_format

        if not isinstance(export_format, str):
            raise UnsupportedExportFormatError(
                f"Unsupported output format type: "
                f"{type(export_format).__name__}."
            )

        requested = export_format.strip().lower()

        for format_type in ExportAvailableFormat:
            if requested == format_type.value.lower():
                return format_type

        supported = ", ".join(
            format_type.value
            for format_type in ExportAvailableFormat
        )

        raise UnsupportedExportFormatError(
            f"Unsupported output format {export_format!r}. "
            f"Supported formats: {supported}."
        )

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
        export_format: ExportAvailableFormat,
    ) -> list[str]:
        expected = {
            extension.lower()
            for extension in export_format.extensions
        }

        suffix = destination.suffix.lower()

        if suffix not in expected:
            return [
                f"Destination extension {suffix!r} does not normally match "
                f"requested format {export_format.value!r}. Expected one of: "
                f"{', '.join(sorted(expected))}."
            ]

        return []

def create_default_export_service() -> ExportService:
    """
    Create an ExportService configured with all standard SAVE exporters.
    """
    from SAVE.modules.exporter.components.ckl import (
        _ckl_export_handler,
    )
    from SAVE.modules.exporter.components.cklb import (
        _cklb_export_handler,
    )
    from SAVE.modules.exporter.components.csv import (
        _csv_export_handler,
    )
    from SAVE.modules.exporter.components.normalized_json import (
        _normalized_json_export_handler,
    )
    from SAVE.modules.exporter.components.xlsx import (
        _xlsx_export_handler,
    )

    service = ExportService()

    service.register_exporter(
        ExportAvailableFormat.CKLB,
        _cklb_export_handler,
    )

    service.register_exporter(
        ExportAvailableFormat.CSV,
        _csv_export_handler,
    )

    service.register_exporter(
        ExportAvailableFormat.NORMALIZED_JSON,
        _normalized_json_export_handler,
    )

    service.register_exporter(
        ExportAvailableFormat.CKL,
        _ckl_export_handler,
    )

    service.register_exporter(
        ExportAvailableFormat.XLSX,
        _xlsx_export_handler,
    )

    return service

default_export_service = create_default_export_service()

def export_file(
    checklist: Any,
    destination: str | Path,
    *,
    export_format: ExportAvailableFormat | str,
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