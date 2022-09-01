import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# Create CVE Host table from running: !prisma-cloud-compute-vulnerabilities-impacted-resources-list
# and setting to indicator (custom script)


def main():
    dArgs = demisto.args()

    if "indicator" in dArgs:
        cve = dArgs.get("indicator").get("value")
    else:
        cve = dArgs.get("cve")
    markdownField = dArgs.get("markdownField", "prismacloudcomputeimpacttable")
    try:
        results = demisto.executeCommand("prisma-cloud-compute-vulnerabilities-impacted-resources-list",
                                         {"cve": cve})[0]["HumanReadable"]
    except Exception:
        return_results("Nothing found in Prisma Cloud Compute!")

    demisto.executeCommand("setIndicator", {"value": cve, markdownField: results})

    # TODO pretty format of md table in warroom results
    result = CommandResults(
        readable_output=results
    )

    return_results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
