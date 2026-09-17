from __future__ import annotations

import argparse
from pathlib import Path


def add_database_argument(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("save.db"),
        help=(
            "SQLite database path. "
            "Default: save.db"
        ),
    )