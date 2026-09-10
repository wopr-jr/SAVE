## Assuming custom headers of Vulnerability ID,Requirement,Assessment Result,Analyst Notes,Evidence

from stig_ingest.importers.csv_importer import (
    CsvColumnMap,
    import_csv,
)

mapping = CsvColumnMap(
    columns={
        "vuln_id": "Vulnerability ID",
        "rule_title": "Requirement",
        "status": "Assessment Result",
        "comments": "Analyst Notes",
        "finding_details": "Evidence",
    }
)

result = import_csv(
    "custom_assessment.csv",
    column_map=mapping,
    default_stig_id="RHEL_9_STIG",
)