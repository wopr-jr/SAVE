from __future__ import annotations

import argparse
import sys

from SAVE.cli.cli_common import ExitCode

from SAVE.cli.parsers.import_options import (
    build_import_options,
)

from SAVE.cli.parsers.persistence_options import (
    build_persistence_options,
)

from SAVE.modules.importer.interface import (
    ImportErrorBase,
    UnsupportedFormatError,
    import_file,
)

from SAVE.modules.persistence.codec import (
    JsonChecklistCodec,
)

from SAVE.modules.persistence.interface import (
    PersistenceErrorBase,
    PersistenceTarget,
    PersistenceWriteMode,
    UnsupportedPersistenceTargetError,
    open_store,
)


def command_import_file(
    *,
    args: argparse.Namespace,
) -> ExitCode:
    """
    Import a source file, normalize it into a Checklist, and persist it.

    This command does not export a new artifact. It creates or updates an
    internal SAVE persistence record.
    """
    try:
        import_result = import_file(
            args.source,
            options=build_import_options(args),
        )

    except UnsupportedFormatError as exc:
        print(
            f"Unsupported source format: {exc}",
            file=sys.stderr,
        )
        return ExitCode.UNSUPPORTED_FORMAT

    except (ImportErrorBase, OSError, ValueError) as exc:
        print(
            f"Import failed: {exc}",
            file=sys.stderr,
        )
        return ExitCode.IMPORT_ERROR

    if import_result.warnings and args.fail_on_warning:
        print(
            "Import completed with warnings; persistence was skipped "
            "because --fail-on-warning was specified.",
            file=sys.stderr,
        )

        for warning in import_result.warnings:
            print(
                f"IMPORT WARNING: {warning}",
                file=sys.stderr,
            )

        return ExitCode.WARNINGS

    try:
        persistence_target = PersistenceTarget(
            args.store_target,
        )

        write_mode = PersistenceWriteMode(
            args.write_mode,
        )

        persistence_options = build_persistence_options(args)

        # JsonChecklistCodec.encode() is sufficient for the initial save
        # operation. Its decode() method is required later for inspect/export
        # operations that retrieve a Checklist from persistence.
        codec = JsonChecklistCodec()

        with open_store(
            target=persistence_target,
            location=args.store_location,
            codec=codec,
            options=persistence_options,
        ) as store:
            persistence_result = store.save(
                import_result.checklist,
                mode=write_mode,
            )

    except UnsupportedPersistenceTargetError as exc:
        print(
            f"Unsupported persistence target: {exc}",
            file=sys.stderr,
        )
        return ExitCode.PERSISTENCE_ERROR

    except (PersistenceErrorBase, OSError, ValueError) as exc:
        print(
            f"Persistence failed: {exc}",
            file=sys.stderr,
        )
        return ExitCode.PERSISTENCE_ERROR

    print("SAVE Import Complete")
    print("=" * 72)
    print(f"Source file:          {args.source}")
    print(
        f"Detected format:      "
        f"{import_result.detected_format.value}"
    )
    print(
        f"Checklist UUID:       "
        f"{persistence_result.checklist_uuid}"
    )
    print(
        f"Persistence target:   "
        f"{persistence_result.target.value}"
    )
    print(
        f"Store location:       "
        f"{persistence_result.location}"
    )
    print(
        f"Write mode:           "
        f"{persistence_result.operation.value}"
    )

    if persistence_result.created:
        print("Persistence result:   Created")

    elif persistence_result.updated:
        print("Persistence result:   Updated")

    else:
        print("Persistence result:   Completed")

    all_warnings = [
        *import_result.warnings,
        *persistence_result.warnings,
    ]

    if all_warnings:
        print(
            f"\nWarnings ({len(all_warnings)}):",
            file=sys.stderr,
        )

        for warning in all_warnings:
            print(
                f"  - {warning}",
                file=sys.stderr,
            )

        return ExitCode.WARNINGS

    return ExitCode.SUCCESS