import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Create CVE Host table from running: !prisma-cloud-compute-vulnerabilities-impacted-resources-list and setting to indicator (custom script)

if "indicator" in demisto.args():
    cve = demisto.args()["indicator"]["value"]
else:
    cve = demisto.args().get("cve")

markdownField = demisto.args().get("markdownField", "prismacloudcomputeimpacttable")

try:
    results = demisto.executeCommand("prisma-cloud-compute-vulnerabilities-impacted-resources-list",
                                     {"cve": cve})[0]["HumanReadable"]
except:
    return_results("Nothing found in Prisma Cloud Compute!")

demisto.executeCommand("setIndicator", {"value": cve, markdownField: results})

# TODO pretty format of md table in warroom results
result = CommandResults(
    readable_output=results
)

return_results(result)
