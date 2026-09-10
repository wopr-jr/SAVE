from pathlib import Path
from stig_ingest.importers.ckl import import_ckl

result = import_ckl(Path("RHEL_9_STIG_Checklist.ckl"))

checklist = result.checklist

print(checklist.checklist_uuid)
print(checklist.source_sha256)
print(checklist.asset.host_name if checklist.asset else None)

for stig in checklist.stigs:
    print(stig.stig_id, stig.stig_name)

    for rule in stig.rules:
        print(
            rule.vuln_id,
            rule.rule_id,
            rule.status.value,
            rule.severity.value,
        )

for warning in result.warnings:
    print(f"WARNING: {warning}")