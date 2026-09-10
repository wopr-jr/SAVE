import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class ValidationError(Exception):
    """Raised when input/output path or conversion validation fails."""
    pass


def validate_file_conversion(input_path: Path, output_path: Path) -> None:
    """
    Validates that the conversion is supported and the paths are valid.

    :raises ValidationError: on any failure
    """
    if input_path.resolve() == output_path.resolve():
        raise ValidationError(
            f"Input and output files cannot be the same: {input_path}"
        )

    input_ext = input_path.suffix[1:].lower()
    output_ext = output_path.suffix[1:].lower()

    if input_ext not in _SUPPORTED_CONVERSIONS:
        valid = ", ".join(_SUPPORTED_CONVERSIONS)
        raise ValidationError(
            f"Unsupported input type '{input_ext}'. Supported: {valid}"
        )
    if output_ext not in _SUPPORTED_CONVERSIONS[input_ext]:
        valid = ", ".join(_SUPPORTED_CONVERSIONS[input_ext])
        raise ValidationError(
            f"Cannot convert '{input_ext}' → '{output_ext}'. Valid outputs: {valid}"
        )

    if not input_path.is_file():
        raise ValidationError(f"Input file does not exist: {input_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)


class STIGConverter:
    """Converts STIG Checklists to/from various file formats (CSV, JSON, CKL, Markdown)."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.input_file_path: Path = args.input
        self.output_file_path: Path = args.output
        self.project_name: Optional[str] = getattr(args, "name", None)
        self.template_ckl: Optional[Path] = getattr(args, "template_ckl", None)
        self.date: str = datetime.now().strftime("%Y%m%d")

    def update_filename(self, filename: str) -> str:
        """
        Update or append a YYYYMMDD datestamp in a filename.

        Examples:
            stig_checklist-20210723.ckl  →  stig_checklist-<today>.ckl
            stig_checklist.ckl           →  stig_checklist-<today>.ckl
        """
        match = re.search(r"-(\d{8})", filename)
        if match:
            return filename.replace(match.group(1), self.date)
        p = Path(filename)
        return str(p.with_name(f"{p.stem}-{self.date}{p.suffix}"))

    _DISPATCH: dict = {
        ("ckl",  "csv"):  "_ckl_to_csv",
        ("ckl",  "json"): "_ckl_to_json",
        ("ckl",  "md"):   "_ckl_to_md",
        ("ckl",  "cklb"): "_ckl_to_cklb",
        ("cklb", "ckl"):  "_cklb_to_ckl",
        ("csv",  "json"): "_csv_to_json",
        ("json", "ckl"):  "_json_to_ckl",
        ("json", "md"):   "_json_to_md",
        ("xml",  "ckl"):  "_xccdf_to_ckl",
        ("xml",  "cklb"): "_xccdf_to_cklb",
    }

    def convert(self) -> str:
        """Dispatch conversion based on input/output file extensions."""
        input_ext = self.input_file_path.suffix[1:].lower()
        output_ext = self.output_file_path.suffix[1:].lower()
        method_name = self._DISPATCH.get((input_ext, output_ext))
        if not method_name:
            raise ValidationError(f"Unsupported conversion: {input_ext} → {output_ext}")
        return getattr(self, method_name)()

    # ------------------------------------------------------------------
    # Private conversion methods
    # ------------------------------------------------------------------

    def _ckl_to_csv(self) -> str:
        from stig_converter.converters.ckl_to_csv import convert_ckl_to_csv
        return convert_ckl_to_csv(self.input_file_path, self.output_file_path)

    def _ckl_to_json(self) -> str:
        from stig_converter.converters.ckl_to_json import convert_ckl_to_json
        return convert_ckl_to_json(self.input_file_path, self.output_file_path)

    def _csv_to_json(self) -> str:
        from stig_converter.converters.csv_to_json import convert_csv_to_json
        return convert_csv_to_json(self.input_file_path, self.output_file_path)

    def _json_to_ckl(self) -> str:
        if not self.template_ckl:
            raise ValidationError("--template-ckl is required for JSON → CKL conversion")
        from stig_converter.converters.json_to_ckl import convert_json_to_ckl
        return convert_json_to_ckl(
            self.input_file_path, self.output_file_path, self.template_ckl
        )

    def _json_to_md(self) -> str:
        from stig_converter.converters.json_to_markdown import convert_json_to_md
        return convert_json_to_md(self.input_file_path, self.output_file_path)

    def _ckl_to_md(self) -> str:
        from stig_converter.converters.ckl_to_markdown import convert_ckl_to_md
        return convert_ckl_to_md(self.input_file_path, self.output_file_path)

    def _ckl_to_cklb(self) -> str:
        from stig_converter.converters.ckl_to_cklb import convert_ckl_to_cklb
        return convert_ckl_to_cklb(self.input_file_path, self.output_file_path)

    def _cklb_to_ckl(self) -> str:
        from stig_converter.converters.cklb_to_ckl import convert_cklb_to_ckl
        return convert_cklb_to_ckl(self.input_file_path, self.output_file_path)

    def _xccdf_to_ckl(self) -> str:
        from stig_converter.converters.xccdf_to_ckl import convert_xccdf_to_ckl
        return convert_xccdf_to_ckl(self.input_file_path, self.output_file_path)

    def _xccdf_to_cklb(self) -> str:
        from stig_converter.converters.xccdf_to_cklb import convert_xccdf_to_cklb
        return convert_xccdf_to_cklb(self.input_file_path, self.output_file_path)


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------




def main() -> None:
    
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Ingests STIG data and normalizes it.")
    parser.add_argument("-i", "--input", required=True, help="The input can be a checklist file, a zip file, or a directory")
    args = parser.parse_args()
    
   
    try:
        if args.command == "convert":
            converter = STIGConverter(args)
            converter.convert()
        elif args.command == "fetch":
            from stig_converter.get_new_stigs import get_stig_json, get_stig_zip
            if args.fetch_json:
                get_stig_json(args.fetch_json)
            else:
                get_stig_zip(args.fetch_zip, stig_sys=args.stig_sys, stig_ver=args.stig_ver)
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except ValidationError as e:
        print(f"[X] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[X] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
