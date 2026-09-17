from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from SAVE.cli.cli_common import ExitCode
from SAVE.cli.parsers.main_parser import build_parser

from SAVE.cli.commands.convert import command_convert_file
from SAVE.cli.commands.import_file import command_import_file
from SAVE.cli.commands.inspect import command_inspect_stored_checklist


class ChecklistRepository(Protocol):
    """
    Minimal interface required by CLI commands that operate on stored
    checklists.

    Your future SQLite repository should implement this contract.
    """

    def get_checklist(self, checklist_uuid):
        ...

    def save_checklist(self, checklist):
        ...


@dataclass(slots=True)
class CliContext:
    """
    Shared dependencies available to CLI command handlers.

    This keeps main() as the application's composition root.
    """

    checklist_repository: ChecklistRepository | None = None


def create_context(
    *,
    database_path: Path | None,
) -> CliContext:
    """
    Create CLI dependencies.

    Once the SQLite repository exists, replace the placeholder section with
    the actual repository import and constructor.
    """
    if database_path is None:
        return CliContext()

    # Future implementation example:
    #
    # from SAVE.persistence.sqlite_repository import (
    #     SqliteChecklistRepository,
    # )
    #
    # return CliContext(
    #     checklist_repository=SqliteChecklistRepository(database_path),
    # )

    raise NotImplementedError(
        "SQLite checklist repository has not been implemented yet."
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        match args.command:
            case "convert":
                # File -> unified importer -> normalized Checklist -> exporter.
                return command_convert_file(args=args)

            case "import":
                # File -> unified importer -> normalized Checklist -> SQLite.
                context = create_context(
                    database_path=args.database,
                )

                return command_import_file(
                    args=args,
                    checklist_repository=context.checklist_repository,
                )

            case "inspect":
                # SQLite -> normalized Checklist -> inspection summary.
                context = create_context(
                    database_path=args.database,
                )

                return command_inspect_stored_checklist(
                    args=args,
                    checklist_repository=context.checklist_repository,
                )

            case _:
                parser.error(
                    f"Unknown command: {args.command}"
                )
                return ExitCode.USAGE_ERROR

    except NotImplementedError as exc:
        print(
            f"Feature unavailable: {exc}",
            file=sys.stderr,
        )
        return ExitCode.DATABASE_ERROR

    except KeyboardInterrupt:
        print(
            "\nOperation cancelled.",
            file=sys.stderr,
        )
        return 130

    except Exception as exc:
        print(
            f"Unexpected SAVE error: {exc}",
            file=sys.stderr,
        )
        return ExitCode.INTERNAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())