from stig_ingest.importers.csv_importer import import_csv

result = import_csv(
    "assessment_export.csv",
    default_stig_id="RHEL_9_STIG",
    default_stig_name="Red Hat Enterprise Linux 9 Security Technical Implementation Guide",
)

checklist = result.checklist

print(checklist.checklist_uuid)
print(checklist.title)
print(checklist.source_sha256)

for stig in checklist.stigs:
    print(f"{stig.stig_id}: {len(stig.rules)} rules")

for warning in result.warnings:
    print(f"WARNING: {warning}")