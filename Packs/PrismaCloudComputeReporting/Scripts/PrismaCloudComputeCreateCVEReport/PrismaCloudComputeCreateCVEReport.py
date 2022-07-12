import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# ${CreatedIndicator.Value}
# cve = "CVE-2021-42379"


def main(cves):
    md = "# Prisma Cloud Compute Vulnerability Report\n\n"
    for cve in cves:
        data = demisto.executeCommand("findIndicators", {"value": cve})[0]["Contents"][0]["CustomFields"]

        md += f"## {cve}\n"
        md += f"**CVSS**: {data['cvss']}\n\n"
        md += f"**Description**: {data['cvedescription']}\n\n"
        md += f"{data['prismacloudcomputeimpacttable']}\n\n"

    result = CommandResults(
        readable_output=md
    )

    if argToBoolean(demisto.args().get("HTMLOutput", False)):
        html = demisto.executeCommand("mdToHtml", {"text": md})[0]["Contents"]
        demisto.results(fileResult("Report.html", html))
    return_results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    cves = argToList(demisto.args().get("cves"))
    main(cves)
