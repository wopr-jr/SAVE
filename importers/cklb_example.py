from stig_ingest.importers.cklb import import_cklb

result = import_cklb("RHEL_9_STIG_Assessment.cklb")

checklist = result.checklist

print(checklist.checklist_uuid)
print(checklist.title)
print(checklist.checklist_version)
print(checklist.source_sha256)

for stig in checklist.stigs:
    print(f"{stig.stig_id}: {len(stig.rules)} rules")

    for rule in stig.rules:
        print(
            rule.vuln_id,
            rule.rule_id,
            rule.status.value,
            rule.severity.value,
        )

for warning in result.warnings:
    print(f"WARNING: {warning}")