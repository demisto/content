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
        return res.get('total', 0)

    def get_xsoar8_audit_logs_count():
        return res.get('total_count', 0)

    return arg_to_number(get_xsoar6_audit_logs_count() or get_xsoar8_audit_logs_count())


def main():   # pragma: no cover
    # get the file type
    file_type = demisto.args().get("output")

    # set time back for fetching
    fetch_back_date = date.today() - timedelta(days=int(demisto.args().get("days_back")))
    fetch_from = fetch_back_date.strftime("%Y-%m-%dT00:00:00Z")

    demisto_version: str = get_demisto_version().get("version")
    demisto.debug(f'{demisto_version=}')
    if not demisto_version:
        raise ValueError(f'Could not get the version of XSOAR')

    page = 0
    size = 100

    if demisto_version.startswith("6"):  # xsoar 6
        uri = "/settings/audits"
        body = {
            'fromDate': fetch_from,
            'query': "",
            'page': page,
            'size': size
        }
    else:  # xsoar 8
        uri = "/public_api/v1/audits/management_logs"
        body = {
            "request_data": {
                "search_from": page,
                "search_to": size,
                "filters": [
                    {
                        'field': 'timestamp',
                        'operator': 'gte',
                        'value': date_to_timestamp(fetch_back_date)
                    },
                ]
                # "page": page
            }
        }

    args = {"uri": uri, "body": body}
    demisto.log(f'{args=}')
    res = demisto.executeCommand("demisto-api-post", args)[0]["Contents"]["response"]
    if is_error(res):
        raise DemistoException(f'error occurred when trying to retrieve the audit logs using {args=}, error: {res}')

    # set the initial counts
    total = get_audit_logs_count(res)
    audits = get_audit_logs(res)
    count = 1

    # if there are more events than the default size, page through and get them all
    while len(audits) < total:
        if 'page' in body:  # pagination for xsoar-6
            body['page'] = count
        else:  # pagination for xsoar-8
            body["request_data"]["search_from"] = count
        args = {"uri": uri, "body": body}
        res = demisto.executeCommand("demisto-api-post", args)[0]["Contents"]["response"]
        audits.extend(get_audit_logs(res))
        count += 1
        # break if this goes crazy, if there are more than 100 pages of audit log entries.
        if count == 100:
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
