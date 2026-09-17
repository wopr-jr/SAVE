from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    WARNINGS = 1
    USAGE_ERROR = 2
    UNSUPPORTED_FORMAT = 3
    IMPORT_ERROR = 4
    EXPORT_ERROR = 5
    PERSISTENCE_ERROR = 6
    INTERNAL_ERROR = 7

def print_summary(
    *,
    checklist,
    inspection,
) -> None:
    print("SAVE Checklist Inspection")
    print("=" * 72)

    print()
    print("Checklist")
    print("-" * 72)

    print(f"Title:                {checklist.title or '<unspecified>'}")
    print(f"Checklist UUID:       {checklist.checklist_uuid}")
    print(f"Source format:        {checklist.checklist_format.value}")
    print(
        f"Source filename:      "
        f"{checklist.source_filename or '<unknown>'}"
    )
    print(
        f"Source SHA-256:       "
        f"{checklist.source_sha256 or '<unknown>'}"
    )

    if checklist.asset:
        print()
        print("Target Asset")
        print("-" * 72)

        print(
            f"Host name:            "
            f"{checklist.asset.host_name or '<unspecified>'}"
        )

        if checklist.asset.fqdn:
            print(f"FQDN:                 {checklist.asset.fqdn}")

        if checklist.asset.ip_address:
            print(f"IP address:           {checklist.asset.ip_address}")

    print()
    print("Rule Summary")
    print("-" * 72)

    print(f"STIG count:           {inspection.stig_count}")
    print(f"Rule count:           {inspection.rule_count}")
    print(f"Open:                 {inspection.open_count}")
    print(f"Not a Finding:        {inspection.not_a_finding_count}")
    print(f"Not Applicable:       {inspection.not_applicable_count}")
    print(f"Not Reviewed:         {inspection.not_reviewed_count}")

    print()
    print("Severity Summary")
    print("-" * 72)

    print(f"Critical:             {inspection.critical_count}")
    print(f"High:                 {inspection.high_count}")
    print(f"Medium:               {inspection.medium_count}")
    print(f"Low:                  {inspection.low_count}")
    print(f"Unknown:              {inspection.unknown_severity_count}")
