import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import csv
import io
import json
from datetime import date, timedelta


def get_audit_logs(res: Dict):

    def get_xsoar6_audit_logs():
        return res.get('audits') or []

    def get_xsoar8_audit_logs():
        return (res.get('reply') or {}).get('data') or []

    return get_xsoar6_audit_logs() or get_xsoar8_audit_logs()


def get_audit_logs_count(res: Dict):
    def get_xsoar6_audit_logs_count():
        return res.get('total') or 0

    def get_xsoar8_audit_logs_count():
        return res.get('total_count') or 0

    return arg_to_number(get_xsoar6_audit_logs_count() or get_xsoar8_audit_logs_count())


def main():   # pragma: no cover
    # get the file type
    file_type = demisto.args().get("output")

    # set time back for fetching
    fetch_back_date = date.today() - timedelta(days=int(demisto.args().get("days_back")))
    fetch_from = fetch_back_date.strftime("%Y-%m-%dT00:00:00Z")

    demisto_version: str = get_demisto_version().get("version")
    demisto.debug(f'The version of XSOAR is: {demisto_version}')
    if not demisto_version:
        raise ValueError('Could not get the version of XSOAR')

    page_num = 0
    size = 100

    if demisto_version.startswith("6"):  # xsoar 6
        uri = "/settings/audits"
        body = {
            'fromDate': fetch_from,
            'query': "",
            'page': page_num,
            'size': size
        }
    else:  # xsoar 8
        uri = "/public_api/v1/audits/management_logs"
        body = {
            "request_data": {
                "search_from": page_num,
                "search_to": size,
                "filters": [
                    {
                        'field': 'timestamp',
                        'operator': 'gte',
                        'value': date_to_timestamp(fetch_back_date)
                    },
                ]
            }
        }

    args = {"uri": uri, "body": body}
    res = demisto.executeCommand("core-api-post", args)
    demisto.debug(f'core-api-post with {args} returned {res}')
    if is_error(res):
        raise DemistoException(f'error occurred when trying to retrieve the audit logs using {args=}, error: {res}')

    response = res[0]["Contents"]["response"]

    # set the initial counts
    total = get_audit_logs_count(response)
    audits = get_audit_logs(response)
    page_num += 1

    # if there are more events than the default size, page through and get them all
    while len(audits) < total:
        if demisto_version.startswith("6"):  # pagination for xsoar-6
            body["page"] = page_num
        else:  # pagination for xsoar-8
            body["request_data"]["search_from"] = page_num  # type: ignore[index]
        args = {"uri": uri, "body": body}
        res = demisto.executeCommand("core-api-post", args)
        demisto.debug(f'core-api-post with {args} returned {res}')
        if is_error(res):
            raise DemistoException(f'error occurred when trying to retrieve the audit logs using {args=}, error: {res}')
        response = res[0]["Contents"]["response"]
        audits.extend(get_audit_logs(response))
        page_num += 1
        # break if this goes crazy, if there are more than 100 pages of audit log entries.
        if page_num == 100:
            break

    file_date = fetch_back_date.strftime("%Y-%m-%d")

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
