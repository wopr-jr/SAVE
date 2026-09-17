from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from uuid import UUID

from defusedxml import ElementTree as ET

from SAVE.model.Asset import Asset
from SAVE.model.Checklist import Checklist


if TYPE_CHECKING:
    from SAVE.modules.importer.components.csv_importer import (
        CsvColumnMap,
    )


class ImportFormat(str, Enum):
    AUTO = "auto"
    CKL = "ckl"
    CKLB = "cklb"
    CSV = "csv"
    XCCDF = "xccdf"


class ImportErrorBase(Exception):
    """Base exception for SAVE import failures."""


class UnsupportedFormatError(ImportErrorBase):
    """Raised when SAVE cannot identify or support a source format."""


class FormatDetectionError(ImportErrorBase):
    """Raised when a file appears malformed for its claimed format."""


@dataclass(slots=True)
class DetectionResult:
    """
    Result of content-based source-format detection.
    """

    format: ImportFormat
    confidence: str
    evidence: str


@dataclass(slots=True)
class ImportOptions:
    """
    Options shared by the unified import service.

    Most fields are only used by one importer type. Keeping them here allows
    the CLI, future API, and batch importer to use one request contract.
    """

    format_hint: ImportFormat = ImportFormat.AUTO
    checklist_uuid: UUID | None = None

    # CSV-specific options.
    csv_delimiter: str = ","
    csv_encoding: str = "utf-8-sig"
    csv_column_map: CsvColumnMap | None = None
    default_stig_id: str | None = None
    default_stig_name: str | None = None
    default_asset: Asset | None = None

    # XCCDF-specific options.
    include_xccdf_test_results: bool = False
    xccdf_test_result_id: str | None = None

    # Basic local-file safety limit. Set to None to disable.
    max_file_bytes: int | None = 100 * 1024 * 1024


@dataclass(slots=True)
class UnifiedImportResult:
    """
    Common result returned regardless of source format.
    """

    checklist: Checklist
    detected_format: ImportFormat
    detection: DetectionResult
    source_path: Path
    warnings: list[str] = field(default_factory=list)


ImporterHandler = Callable[
    [
        Path,
        ImportOptions,
        DetectionResult,
    ],
    UnifiedImportResult,
]


ComponentImporter = Callable[
    [
        Path,
        ImportOptions,
    ],
    Any,
]


class ImportService:
    """
    Unified SAVE file-ingestion service.

    Responsibilities:
      - Validate local file inputs.
      - Detect source format by content.
      - Dispatch to a registered importer adapter.
      - Return a consistent UnifiedImportResult.

    Non-responsibilities:
      - SQLite persistence.
      - Export.
      - CLI argument parsing.
      - Server/API transport behavior.

    A newly instantiated ImportService has no registered importers.
    Use create_default_import_service() for the standard SAVE configuration.
    """

    def __init__(self) -> None:
        self._handlers: dict[
            ImportFormat,
            ImporterHandler,
        ] = {}

    def import_file(
        self,
        source: str | Path,
        *,
        options: ImportOptions | None = None,
    ) -> UnifiedImportResult:
        """
        Detect and import a supported source file into the normalized model.
        """
        source_path = Path(source)
        options = options or ImportOptions()

        self._validate_source(
            source_path,
            options,
        )

        detection = self.detect_format(
            source_path,
            format_hint=options.format_hint,
        )

        handler = self._handlers.get(
            detection.format,
        )

        if handler is None:
            raise UnsupportedFormatError(
                f"SAVE has no importer registered for "
                f"{detection.format.value!r}."
            )

        result = handler(
            source_path,
            options,
            detection,
        )

        normalized_format = result.checklist.checklist_format.value

        if normalized_format != detection.format.value:
            result.warnings.append(
                "Importer output format does not match detected format: "
                f"detected={detection.format.value!r}, "
                f"normalized={normalized_format!r}."
            )

        return result

    def register_importer(
        self,
        source_format: ImportFormat,
        handler: ImporterHandler,
    ) -> None:
        """
        Register an importer without modifying ImportService internals.

        Future importer registrations may include:
          - ARF
          - OVAL
          - Nessus
          - ZIP package dispatcher
          - XLSX assessment tracker
        """
        if source_format == ImportFormat.AUTO:
            raise ValueError(
                "Cannot register an importer for AUTO format."
            )

        self._handlers[source_format] = handler

    def detect_format(
        self,
        source: str | Path,
        *,
        format_hint: ImportFormat = ImportFormat.AUTO,
    ) -> DetectionResult:
        """
        Detect a source format by content when possible.
        """
        source_path = Path(source)

        if format_hint != ImportFormat.AUTO:
            return DetectionResult(
                format=format_hint,
                confidence="caller-supplied",
                evidence="Format was explicitly supplied by caller.",
            )

        prefix = self._read_prefix(source_path)

        if prefix.startswith(b"PK\x03\x04"):
            raise UnsupportedFormatError(
                "ZIP archive detected. A SAVE package/ZIP dispatcher has "
                "not been registered yet."
            )

        stripped = prefix.lstrip()

        if stripped.startswith(b"{") or stripped.startswith(b"["):
            return self._detect_json(source_path)

        if stripped.startswith(b"<"):
            return self._detect_xml(source_path)

        if self._looks_like_csv(
            source_path,
            prefix,
        ):
            return DetectionResult(
                format=ImportFormat.CSV,
                confidence="medium",
                evidence="Delimited text header detected.",
            )

        suffix = source_path.suffix.lower()

        suffix_map = {
            ".ckl": ImportFormat.CKL,
            ".cklb": ImportFormat.CKLB,
            ".csv": ImportFormat.CSV,
            ".tsv": ImportFormat.CSV,
            ".xccdf": ImportFormat.XCCDF,
        }

        if suffix in suffix_map:
            return DetectionResult(
                format=suffix_map[suffix],
                confidence="low",
                evidence=(
                    "Fallback based on filename extension "
                    f"{suffix!r}."
                ),
            )

        raise UnsupportedFormatError(
            f"Could not identify a supported format for "
            f"{source_path.name!r}. Specify a format hint or provide "
            "CKL, CKLB, CSV, or XCCDF input."
        )

    def _detect_json(
        self,
        source: Path,
    ) -> DetectionResult:
        try:
            with source.open(
                "r",
                encoding="utf-8-sig",
            ) as source_file:
                document = json.load(source_file)

        except UnicodeDecodeError as exc:
            raise FormatDetectionError(
                f"{source.name} appears to be JSON but is not UTF-8 text."
            ) from exc

        except json.JSONDecodeError as exc:
            raise FormatDetectionError(
                f"{source.name} appears to be JSON but cannot be parsed: "
                f"{exc}"
            ) from exc

        if not isinstance(document, dict):
            raise UnsupportedFormatError(
                "JSON source must contain an object at the document root."
            )

        if "cklb_version" in document and "stigs" in document:
            return DetectionResult(
                format=ImportFormat.CKLB,
                confidence="high",
                evidence="JSON contains cklb_version and stigs fields.",
            )

        raise UnsupportedFormatError(
            "JSON document is not recognized as CKLB. "
            "No supported JSON importer matched its structure."
        )

    def _detect_xml(
        self,
        source: Path,
    ) -> DetectionResult:
        try:
            root = ET.parse(source).getroot()

        except ET.ParseError as exc:
            raise FormatDetectionError(
                f"{source.name} appears to be XML but cannot be parsed: "
                f"{exc}"
            ) from exc

        root_name = root.tag.rsplit(
            "}",
            1,
        )[-1].lower()

        if root_name == "checklist":
            return DetectionResult(
                format=ImportFormat.CKL,
                confidence="high",
                evidence="XML root element is CHECKLIST.",
            )

        if root_name == "benchmark":
            return DetectionResult(
                format=ImportFormat.XCCDF,
                confidence="high",
                evidence="XML root element is Benchmark.",
            )

        raise UnsupportedFormatError(
            f"XML root element {root_name!r} is not currently supported."
        )

    @staticmethod
    def _validate_source(
        source: Path,
        options: ImportOptions,
    ) -> None:
        if not source.exists():
            raise FileNotFoundError(
                f"Source file does not exist: {source}"
            )

        if not source.is_file():
            raise ValueError(
                f"Source path is not a regular file: {source}"
            )

        if options.max_file_bytes is None:
            return

        source_size = source.stat().st_size

        if source_size > options.max_file_bytes:
            raise ValueError(
                f"Source file is {source_size:,} bytes, exceeding the "
                f"configured limit of {options.max_file_bytes:,} bytes."
            )

    @staticmethod
    def _read_prefix(
        source: Path,
        *,
        bytes_to_read: int = 16 * 1024,
    ) -> bytes:
        with source.open("rb") as source_file:
            return source_file.read(bytes_to_read)

    @staticmethod
    def _looks_like_csv(
        source: Path,
        prefix: bytes,
    ) -> bool:
        """
        Conservative CSV detection.

        CSV is inherently ambiguous, so an explicit format hint remains
        preferable when possible.
        """
        suffix = source.suffix.lower()

        if suffix in {".csv", ".tsv"}:
            return True

        try:
            text = prefix.decode("utf-8-sig")
        except UnicodeDecodeError:
            return False

        lines = text.splitlines()

        if not lines:
            return False

        first_line = lines[0]

        if not first_line:
            return False

        delimiters = (
            ",",
            "\t",
            ";",
            "|",
        )

        return any(
            delimiter in first_line
            for delimiter in delimiters
        )


def _create_component_handler(
    *,
    source_format: ImportFormat,
    component_importer: ComponentImporter,
) -> ImporterHandler:
    """
    Wrap a format-specific component importer in SAVE's common result type.

    Component importers return their own result objects containing at least:
        imported.checklist
        imported.warnings
    """

    def handler(
        source: Path,
        options: ImportOptions,
        detection: DetectionResult,
    ) -> UnifiedImportResult:
        imported = component_importer(
            source,
            options,
        )

        return UnifiedImportResult(
            checklist=imported.checklist,
            detected_format=source_format,
            detection=detection,
            source_path=source,
            warnings=list(
                getattr(
                    imported,
                    "warnings",
                    [],
                )
            ),
        )

    return handler


def create_default_import_service() -> ImportService:
    """
    Create ImportService configured with standard SAVE import components.

    Component imports occur inside this factory rather than at module load
    time. This mirrors the exporter factory pattern and prevents circular
    imports between the common interface and format-specific components.
    """
    from SAVE.modules.importer.components.ckl import (
        import_ckl,
    )
    from SAVE.modules.importer.components.cklb import (
        import_cklb,
    )
    from SAVE.modules.importer.components.csv_importer import (
        import_csv,
    )
    from SAVE.modules.importer.components.xccdf import (
        import_xccdf,
    )

    service = ImportService()

    def import_ckl_adapter(
        source: Path,
        options: ImportOptions,
    ) -> Any:
        return import_ckl(
            source,
            checklist_uuid=options.checklist_uuid,
        )

    def import_cklb_adapter(
        source: Path,
        options: ImportOptions,
    ) -> Any:
        return import_cklb(
            source,
            checklist_uuid=options.checklist_uuid,
        )

    def import_csv_adapter(
        source: Path,
        options: ImportOptions,
    ) -> Any:
        return import_csv(
            source,
            checklist_uuid=options.checklist_uuid,
            delimiter=options.csv_delimiter,
            encoding=options.csv_encoding,
            column_map=options.csv_column_map,
            default_stig_id=options.default_stig_id,
            default_stig_name=options.default_stig_name,
            default_asset=options.default_asset,
        )

    def import_xccdf_adapter(
        source: Path,
        options: ImportOptions,
    ) -> Any:
        return import_xccdf(
            source,
            checklist_uuid=options.checklist_uuid,
            include_test_results=(
                options.include_xccdf_test_results
            ),
            test_result_id=options.xccdf_test_result_id,
        )

    service.register_importer(
        ImportFormat.CKL,
        _create_component_handler(
            source_format=ImportFormat.CKL,
            component_importer=import_ckl_adapter,
        ),
    )

    service.register_importer(
        ImportFormat.CKLB,
        _create_component_handler(
            source_format=ImportFormat.CKLB,
            component_importer=import_cklb_adapter,
        ),
    )

    service.register_importer(
        ImportFormat.CSV,
        _create_component_handler(
            source_format=ImportFormat.CSV,
            component_importer=import_csv_adapter,
        ),
    )

    service.register_importer(
        ImportFormat.XCCDF,
        _create_component_handler(
            source_format=ImportFormat.XCCDF,
            component_importer=import_xccdf_adapter,
        ),
    )

    return service


default_import_service = create_default_import_service()


def import_file(
    source: str | Path,
    *,
    options: ImportOptions | None = None,
) -> UnifiedImportResult:
    """
    Convenience entry point for CLI, scripts, and future API use.
    """
    return default_import_service.import_file(
        source,
        options=options,
    )