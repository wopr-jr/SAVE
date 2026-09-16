    try:
        export_checklist(
            checklist=checklist,
            destination=args.destination,
            output_format=args.output_format,
        )

    except (OSError, ValueError) as exc:
        print(f"Export failed: {exc}", file=sys.stderr)
        return EXIT_EXPORT_ERROR

    print_summary(
        checklist=checklist,
        detected_format=result.detected_format,
        detection_confidence=result.detection.confidence,
        detection_evidence=result.detection.evidence,
        warnings=result.warnings,
    )

    print()
    print(f"Exported {args.output_format} to: {args.destination}")

    if args.fail_on_warning and result.warnings:
        return EXIT_WARNINGS

    return EXIT_SUCCESS