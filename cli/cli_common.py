

EXIT_SUCCESS = 0
EXIT_WARNINGS = 1
EXIT_IMPORT_ERROR = 2
EXIT_UNSUPPORTED_FORMAT = 3
EXIT_EXPORT_ERROR = 4
EXIT_UNKNOWN_COMMAND = 5

def print_summary(
    *,
    checklist,
    detected_format: ImportFormat,
    detection_confidence: str,
    detection_evidence: str,
    warnings: list[str],
) -> None:
    rule_count = sum(
        len(stig.rules)
        for stig in checklist.stigs
    )

    status_counts = {
        "open": 0,
        "not_a_finding": 0,
        "not_applicable": 0,
        "not_reviewed": 0,
    }

    for stig in checklist.stigs:
        for rule in stig.rules:
            status_counts[rule.status.value] = (
                status_counts.get(rule.status.value, 0) + 1
            )

    print("SAVE file Summary")
    print(f"  Source file:          {checklist.source_filename}")
    print(f"  Detected format:      {detected_format.value}")
    print(f"  Detection confidence: {detection_confidence}")
    print(f"  Detection evidence:   {detection_evidence}")
    print(f"  Checklist UUID:       {checklist.checklist_uuid}")
    print(f"  Source SHA-256:       {checklist.source_sha256}")
    print(f"  Title:                {checklist.title or '<unspecified>'}")
    print(f"  STIG count:           {len(checklist.stigs)}")
    print(f"  Rule count:           {rule_count}")

    if checklist.asset:
        print(
            "  Target:               "
            f"{checklist.asset.host_name or '<unspecified>'}"
        )

        if checklist.asset.ip_address:
            print(f"  Target IP:            {checklist.asset.ip_address}")

    print()
    print("Finding Status Totals")
    print(f"  Open:                 {status_counts.get('open', 0)}")
    print(
        "  Not a Finding:        "
        f"{status_counts.get('not_a_finding', 0)}"
    )
    print(
        "  Not Applicable:       "
        f"{status_counts.get('not_applicable', 0)}"
    )
    print(
        "  Not Reviewed:         "
        f"{status_counts.get('not_reviewed', 0)}"
    )

    if warnings:
        print()
        print(f"Warnings ({len(warnings)}):")

        for warning in warnings:
            print(f"  - {warning}")
