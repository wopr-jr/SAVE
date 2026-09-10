from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable
from uuid import UUID

from defusedxml import ElementTree as ET

from save_core.model import Asset, Checklist, ChecklistFormat
from save_core.importers.ckl import import_ckl
from save_core.importers.cklb import import_cklb
from save_core.importers.csv_importer import CsvColumnMap, import_csv
from save_core.importers.xccdf import import_xccdf


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


ImporterHandler = Callable[[Path, ImportOptions], UnifiedImportResult]


class ImportService:
    """
    SAVE's unified file-ingestion service.

    Responsibilities:
      - Validate local file inputs.
      - Detect source format by content.
      - Dispatch to the proper format-specific importer.
      - Return one common normalized result type.

    Non-responsibilities:
      - SQLite persistence.
      - Export.
      - CLI argument parsing.
      - Server/API transport behavior.
    """

    def __init__(self) -> None:
        self._handlers: dict[ImportFormat, ImporterHandler] = {
            ImportFormat.CKL: self._import_ckl,
            ImportFormat.CKLB: self._import_cklb,
            ImportFormat.CSV: self._import_csv,
            ImportFormat.XCCDF: self._import_xccdf,
        }

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

        self._validate_source(source_path, options)

        detection = self.detect_format(
            source_path,
            format_hint=options.format_hint,
        )

        handler = self._handlers.get(detection.format)

        if handler is None:
            raise UnsupportedFormatError(
                f"SAVE has no importer registered for "
                f"{detection.format.value!r}."
            )

        result = handler(source_path, options)

        # Defend against an importer returning inconsistent metadata.
        if result.checklist.checklist_format.value != detection.format.value:
            result.warnings.append(
                "Importer output format does not match detected format: "
                f"detected={detection.format.value!r}, "
                f"normalized={result.checklist.checklist_format.value!r}."
            )

        return result

    def detect_format(
        self,
        source: str | Path,
        *,
        format_hint: ImportFormat = ImportFormat.AUTO,
    ) -> DetectionResult:
        """
        Detect a format by content when possible.

        A caller-supplied format hint is honored, but obvious malformed input
        is still rejected by the eventual format-specific importer.
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
                "ZIP archive detected. A SAVE package/ZIP dispatcher has not "
                "been registered yet."
            )

        stripped = prefix.lstrip()

        if stripped.startswith(b"{") or stripped.startswith(b"["):
            return self._detect_json(source_path)

        if stripped.startswith(b"<"):
            return self._detect_xml(source_path)

        if self._looks_like_csv(source_path, prefix):
            return DetectionResult(
                format=ImportFormat.CSV,
                confidence="medium",
                evidence="Delimited text header detected.",
            )

        suffix = source_path.suffix.lower()

        # Filename extension is only a fallback, never the primary signal.
        suffix_map = {
            ".ckl": ImportFormat.CKL,
            ".cklb": ImportFormat.CKLB,
            ".csv": ImportFormat.CSV,
            ".xccdf": ImportFormat.XCCDF,
        }

        if suffix in suffix_map:
            return DetectionResult(
                format=suffix_map[suffix],
                confidence="low",
                evidence=f"Fallback based on filename extension {suffix!r}.",
            )

        raise UnsupportedFormatError(
            f"Could not identify a supported format for {source_path.name!r}. "
            "Specify a format hint or provide CKL, CKLB, CSV, or XCCDF input."
        )

    def register_importer(
        self,
        source_format: ImportFormat,
        handler: ImporterHandler,
    ) -> None:
        """
        Register a new importer without modifying ImportService internals.

        Example future registrations:
          - ARF
          - OVAL
          - Nessus
          - ZIP package dispatcher
        """
        if source_format == ImportFormat.AUTO:
            raise ValueError("Cannot register an importer for AUTO format.")

        self._handlers[source_format] = handler

    def _import_ckl(
        self,
        source: Path,
        options: ImportOptions,
    ) -> UnifiedImportResult:
        imported = import_ckl(
            source,
            checklist_uuid=options.checklist_uuid,
        )

        return UnifiedImportResult(
            checklist=imported.checklist,
            detected_format=ImportFormat.CKL,
            detection=DetectionResult(
                format=ImportFormat.CKL,
                confidence="high",
                evidence="CKL importer selected.",
            ),
            source_path=source,
            warnings=list(imported.warnings),
        )

    def _import_cklb(
        self,
        source: Path,
        options: ImportOptions,
    ) -> UnifiedImportResult:
        imported = import_cklb(
            source,
            checklist_uuid=options.checklist_uuid,
        )

        return UnifiedImportResult(
            checklist=imported.checklist,
            detected_format=ImportFormat.CKLB,
            detection=DetectionResult(
                format=ImportFormat.CKLB,
                confidence="high",
                evidence="CKLB importer selected.",
            ),
            source_path=source,
            warnings=list(imported.warnings),
        )

    def _import_csv(
        self,
        source: Path,
        options: ImportOptions,
    ) -> UnifiedImportResult:
        imported = import_csv(
            source,
            checklist_uuid=options.checklist_uuid,
            delimiter=options.csv_delimiter,
            encoding=options.csv_encoding,
            column_map=options.csv_column_map,
            default_stig_id=options.default_stig_id,
            default_stig_name=options.default_stig_name,
            default_asset=options.default_asset,
        )

        return UnifiedImportResult(
            checklist=imported.checklist,
            detected_format=ImportFormat.CSV,
            detection=DetectionResult(
                format=ImportFormat.CSV,
                confidence="high",
                evidence="CSV importer selected.",
            ),
            source_path=source,
            warnings=list(imported.warnings),
        )

    def _import_xccdf(
        self,
        source: Path,
        options: ImportOptions,
    ) -> UnifiedImportResult:
        imported = import_xccdf(
            source,
            checklist_uuid=options.checklist_uuid,
            include_test_results=options.include_xccdf_test_results,
            test_result_id=options.xccdf_test_result_id,
        )

        return UnifiedImportResult(
            checklist=imported.checklist,
            detected_format=ImportFormat.XCCDF,
            detection=DetectionResult(
                format=ImportFormat.XCCDF,
                confidence="high",
                evidence="XCCDF importer selected.",
            ),
            source_path=source,
            warnings=list(imported.warnings),
        )

    def _detect_json(
        self,
        source: Path,
    ) -> DetectionResult:
        try:
            with source.open("r", encoding="utf-8-sig") as source_file:
                document = json.load(source_file)
        except UnicodeDecodeError as exc:
            raise FormatDetectionError(
                f"{source.name} appears to be JSON but is not UTF-8 text."
            ) from exc
        except json.JSONDecodeError as exc:
            raise FormatDetectionError(
                f"{source.name} appears to be JSON but cannot be parsed: {exc}"
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
                f"{source.name} appears to be XML but cannot be parsed: {exc}"
            ) from exc

        root_name = root.tag.rsplit("}", 1)[-1].lower()

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
            raise FileNotFoundError(f"Source file does not exist: {source}")

        if not source.is_file():
            raise ValueError(f"Source path is not a regular file: {source}")

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

        CSV is inherently ambiguous, so use an extension or explicit hint
        when practical. This check only recognizes common delimited headers.
        """
        suffix = source.suffix.lower()

        if suffix in {".csv", ".tsv"}:
            return True

        try:
            text = prefix.decode("utf-8-sig")
        except UnicodeDecodeError:
            return False

        first_line = text.splitlines()[0] if text.splitlines() else ""

        if not first_line:
            return False

        delimiters = (",", "\t", ";", "|")

        return any(
            delimiter in first_line
            for delimiter in delimiters
        )


default_import_service = ImportService()


def import_file(
    source: str | Path,
    *,
    options: ImportOptions | None = None,
) -> UnifiedImportResult:
    """
    Convenience function for CLI and simple callers.
    """
    return default_import_service.import_file(
        source,
        options=options,
    )