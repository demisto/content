from CommonServerPython import *

# Fetch reports based on from_address
filter_by = "{\"from_address\":\"" + demisto.get(demisto.args(), 'email') + "\"}"
reports = demisto.executeCommand('cofense-report-list', {'filter_by': filter_by})

results = []

try:
    if not reports[0]["Contents"] or not reports[0]["HumanReadable"]:
        # No records found for argument email.
        demisto.results(reports[0])
    else:
        # Download report for each report
        reports = reports[0]["Contents"]["data"]
        for report in reports:
            report_id = report.get("id")
            result = demisto.executeCommand('cofense-report-download', {'id': report_id})
            results.append(result[0])

        demisto.results(results)
except Exception as _:
    demisto.results(reports[0])


