import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import csv
import io
import json
from datetime import date, timedelta


def main():   # pragma: no cover
    # get the file type
    file_type = demisto.args().get("output")

    # set time back for fetching
    fetch_back_date = date.today() - timedelta(days=int(demisto.args().get("days_back")))
    fetch_from = fetch_back_date.strftime("%Y-%m-%dT00:00:00Z")
    file_date = fetch_back_date.strftime("%Y-%m-%d")

    # body of the request
    body = {
        'fromDate': fetch_from,
        'query': "",
        'page': 0,
        'size': 100
    }

    # get the logs
    res = demisto.executeCommand("demisto-api-post", {"uri": "/settings/audits", "body": body})[0]["Contents"][
        "response"]

    # set the initial counts
    total = res.get('total', 0)
    audits = res.get('audits', [])
    count = 1

    # if there are more events than the default size, page through and get them all
    while len(audits) < total:
        body['page'] = count
        res = demisto.executeCommand("demisto-api-post", {"uri": "/settings/audits", "body": body})[0]["Contents"][
            "response"]
        audits.extend(res.get('audits', []))
        count += 1
        # break if this goes crazy, if there are more than 100 pages of audit log entries.
        if count == 100:
            break

    if file_type == "csv":
        # write the results to a CSV
        si = io.StringIO()
        cw = csv.writer(si)

        # write header row
        cw.writerow(["Log"])

        # write the rows for each asset
        for audit in audits:
            cw.writerow([audit, ])

        # return the file
        data = si.getvalue().strip('\r\n')
        demisto.results(fileResult(f"xsoar-audit-logs-{file_date}.csv", data.encode('utf-8')))
    else:
        demisto.results(fileResult(f"xsoar-audit-logs-{file_date}.json", json.dumps(audits)))

    # return the results
    demisto.results(f"Fetched {len(audits)} audit log events since {fetch_from}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
