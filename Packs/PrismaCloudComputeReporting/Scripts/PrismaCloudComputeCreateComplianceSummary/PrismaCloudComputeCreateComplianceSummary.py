import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_compliance_summary(images):
    compliance_issues = {}  # type: ignore
    for image in images:
        if image.get('complianceIssues') is not None:
            for compliance_issue in image.get('complianceIssues', []):
                # demisto.results(compliance_issue)
                if not compliance_issues.get(str(compliance_issue.get('id'))):
                    compliance_issues[str(compliance_issue.get('id'))] = compliance_issue
                    compliance_issues[str(compliance_issue.get('id'))]['failed_resources'] = []
                # TODO: instances are not deduped here, they should be.
                compliance_issues[str(compliance_issue.get('id'))]['failed_resources'] += image.get('instances')
    return compliance_issues


def main(images, compliance_issues):
    html = ""

    for issue, data in compliance_issues.items():
        md = f"## {compliance_issues[issue]['title']}\n\n"
        md += f"**Description**: {compliance_issues[issue]['description']}\n\n"
        # demisto.results(str(md))
        md += tableToMarkdown("Failing Resources", compliance_issues[issue]["failed_resources"])
        html += md
        return_results(CommandResults(readable_output=md))

    if argToBoolean(demisto.args().get("HTMLOutput", False)):
        html = demisto.executeCommand("mdToHtml", {"text": html})[0]["Contents"]
        demisto.results(fileResult("Report.html", html))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    images = argToList(demisto.args().get("ReportsImagesScan"))
    compliance_issues = create_compliance_summary(images)

    main(images, compliance_issues)
