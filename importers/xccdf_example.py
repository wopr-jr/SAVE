from stig_ingest.importers.xccdf import import_xccdf



### This is the benchmark only version
result = import_xccdf("U_RHEL_9_STIG_V1R1_Manual-xccdf.xml")

checklist = result.checklist

print(checklist.checklist_uuid)
print(checklist.stigs[0].stig_id)
print(checklist.stigs[0].stig_name)
print(len(checklist.stigs[0].rules))

for rule in checklist.stigs[0].rules[:5]:
    print(
        rule.vuln_id,
        rule.rule_id,
        rule.status.value,      # not_reviewed
        rule.severity.value,
    )

### This includes results

result = import_xccdf(
    "scan-results.xccdf.xml",
    include_test_results=True,
    test_result_id="result-2026-09-10",
)