from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from SAVE.cli.commands.convert_file import command_convert_file
from SAVE.cli.commands.import_file import command_import_file
from SAVE.cli.commands.inspect import command_inspect_stored_checklist

from SAVE.cli.cli_common import ExitCode
from SAVE.cli.parsers.main_parser import build_parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    match args.command:
        case "convert":
            return command_convert_file(args=args)

        case "import":
            return command_import_file(args=args)

        case "inspect":
            return command_inspect_stored_checklist(args=args)

        case _:
            parser.error(
                f"Unknown command: {args.command}"
            )
            return ExitCode.USAGE_ERROR


if __name__ == "__main__":
    raise SystemExit(main())