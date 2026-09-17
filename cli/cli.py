from __future__ import annotations

import argparse
import sys
from pathlib import Path

from SAVE.cli.parsers.build_parsers import build_parser
from SAVE.cli.cli_common import *
from SAVE.cli.commands.import import command_import_file
from SAVE.cli.commands.inspect import command_inspect_checklist
from SAVE.cli.commands.convert import command_convert_file
def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
  
    match args.command:
        case "import":
            return command_import_file(args=args)

        case "inspect":
            return command_inspect_checklist(args=args)

        case "convert":
            return command_convert_file(args=args)

       """ case "export":
            return command_export_file(args=args)
        case "diff":
            return command_diff_checklists(args=args) """

        case _:
            print(
                f"Unknown command : {args.command}",
                file=sys.stderr,
            )
            return EXIT_UNKNOWN_COMMAND
        
if __name__ == "__main__":
    sys.exit(main())