def add_common_export_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    

    parser.add_argument(
        "destination",
        type=Path,
        help="Output file path.",
    )

    parser.add_argument(
        "--output-format",
        required=True,
        choices=(
            "normalized-json",
            "csv",
            "cklb",
        ),
        help="Requested output format.",
    )

    