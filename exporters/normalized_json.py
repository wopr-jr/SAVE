from __future__ import annotations

import json
from pathlib import Path

from stig_ingest.model import Checklist
from stig_ingest.exporters.common import to_primitive


NORMALIZED_SCHEMA_VERSION = "0.1"


def export_normalized_json(
    checklist: Checklist,
    destination: str | Path,
) -> None:
    """
    Export the normalized internal model for inspection, regression testing,
    and comparison between importers.
    """
    destination_path = Path(destination)

    payload = {
        "format": "stig-ingest-normalized",
        "schema_version": NORMALIZED_SCHEMA_VERSION,
        "checklist": to_primitive(
            checklist,
            omit_none=False,
        ),
    }

    with destination_path.open("w", encoding="utf-8") as output_file:
        json.dump(
            payload,
            output_file,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        output_file.write("\n")