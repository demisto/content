from CommonServerPython import *


''' STANDALONE FUNCTION '''


def get_report_list(args: Dict[str, Any]) -> list:
    """
    Executes cofense-report-list command for given arguments.
    :type args: ``Dict[str, Any]``
    :param args: The script arguments provided by the user.

    :return: List of responses.
    :rtype: ``list``
    """

    # Fetch reports based on from_address
    filter_by = "{\"from_address\":\"" + args.get('email', '') + "\"}"
    reports = execute_command('cofense-report-list', {'filter_by': filter_by}, extract_contents=False)

    # Populate response
    return reports


def download_reports(reports: list) -> list:
    """
    Executes cofense-report-download command for each report.
    :type reports: ``List``
    :param reports: List of reports.

    :return: List of responses.
    :rtype: ``list``
    """
    results = []
    if not reports[0]["Contents"] or not reports[0]["HumanReadable"]:
        # No records found for argument email.
        return reports[0]
    else:
        # Download report for each report
        reports = reports[0]["Contents"]["data"]
        for report in reports:
            report_id = report.get("id")
            result = execute_command('cofense-report-download', {'id': report_id}, extract_contents=False)
            results.append(result[0])

        return results


''' MAIN FUNCTION '''


def main():
    try:
        reports = get_report_list(demisto.args())
        results = download_reports(reports)
        return_results(results)
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CofenseTriageReportDownload. Error: {str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
