import dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from enum import Enum
from requests import Response

# Disable insecure warnings
urllib3.disable_warnings()


DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
DEFAULT_MAX_FETCH = 5000
VENDOR = "cybelangel"
PRODUCT = "platform"
DEFAULT_FIRST_FETCH = "30 days"


class LastRun(str, Enum):
    LATEST_REPORT_TIME = "latest_report_time"
    LATEST_FETCHED_REPORTS_IDS = "latest_fetched_reports_ids"


class Client(BaseClient):

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(
        self,
        method: str,
        url_suffix: str,
        data: dict | None = None,
        params: dict[str, Any] | None = None,
        pdf: bool = False,
        cve: bool = False,
    ) -> dict[str, Any] | Response:
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": (
                "application/json"
                if not pdf
                else "application/pdf, application/json"
            ),
        }

        demisto.debug(f'Running http-request with URL {url_suffix} and {params=}')

        response = self._http_request(
            method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            json_data=data,
            resp_type="response",
            ok_codes=(401, 403, 200, 201, 302),
        )
        if response.status_code == 200 or response.status_code == 201:
            return response.json() if not pdf else response

        if response.status_code == 302 and cve:
            cve_response = requests.get(url=response.text)
            return cve_response

        else:
            demisto.debug('Access token has expired, retrieving new access token')

        token = self.get_access_token(create_new_token=True)
        headers["Authorization"] = f'Bearer {token}'

        return self._http_request(method, url_suffix=url_suffix, headers=headers, params=params, json_data=data)

    def get_reports(self, start_date: str, end_date: str, limit: int = DEFAULT_MAX_FETCH) -> List[dict[str, Any]]:
        """
        Get manual reports from Cybel Angel Collector.

        Note:
            The order of the events returned is random, hence need to sort them out to return the oldest events first.
        """
        params = {
            "start-date": start_date,
            "end-date": end_date
        }
        reports = self.http_request(method='GET', url_suffix="/api/v2/reports", params=params).get("reports") or []
        for report in reports:
            if updated_at := report.get("updated_at"):
                _time_field = updated_at
            else:
                _time_field = report["created_at"]

            report["_time"] = _time_field

        reports = sorted(
            reports, key=lambda _report: dateparser.parse(_report["_time"])  # type: ignore[arg-type, return-value]
        )
        return reports[:limit]

    def get_access_token(self, create_new_token: bool = False) -> str:
        """
       Obtains access and refresh token from CybleAngel server.
       Access token is used and stored in the integration context until expiration time.
       After expiration, new refresh token and access token are obtained and stored in the
       integration context.

        Returns:
            str: the access token.
       """
        integration_context = get_integration_context()
        current_access_token = integration_context.get('access_token')
        if current_access_token and not create_new_token:
            return current_access_token
        new_access_token = self.get_token_request()
        integration_context = {
            'access_token': new_access_token,
        }
        demisto.debug(f'updating access token at {datetime.now()}')
        set_integration_context(context=integration_context)
        return new_access_token

    def get_token_request(self) -> str:
        """
        Sends request to retrieve token.

        Returns:
           tuple[str, str]: token and its expiration date
        """
        url = 'https://auth.cybelangel.com/oauth/token'

        token_response = self._http_request(
            'POST',
            full_url=url,
            json_data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": "https://platform.cybelangel.com/",
                "grant_type": "client_credentials"
            }
        )
        if access_token := token_response.get("access_token"):
            return access_token
        raise RuntimeError(f"Could not retrieve token from {url}, access-token returned is empty")


def dedup_fetched_events(
    events: List[dict],
    last_run_fetched_event_ids: Set[str],
) -> List[dict]:
    """
    Dedup events, removes events which were already fetched.
    """
    un_fetched_events = []

    for event in events:
        event_id = event.get("id")
        if event_id not in last_run_fetched_event_ids:
            demisto.debug(f'event with ID {event_id} has not been fetched.')
            un_fetched_events.append(event)
        else:
            demisto.debug(f'event with ID {event_id} for has been fetched')

    demisto.debug(f'{un_fetched_events=}')
    return un_fetched_events


def get_latest_event_time_and_ids(reports: List[Dict[str, Any]]) -> tuple[str, List[str]]:
    """
    Returns the latest event time and all the events that were fetched in the latest event time
    """
    latest_report_time = reports[-1]["_time"]
    return latest_report_time, [report["id"] for report in reports if report["_time"] == latest_report_time]


def test_module(client: Client) -> str:
    """
    Tests that the authentication to the api is ok.
    """
    client.get_reports(
        start_date=(datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT),
        end_date=datetime.now().strftime(DATE_FORMAT)
    )
    return "ok"


def fetch_events(client: Client, first_fetch: str, last_run: dict, max_fetch: int) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    """
    Fetches reports from Cybel Angel

    Args:
        client: Cybel Angel client
        first_fetch: since when to start to takes reports
        last_run: the last run object
        max_fetch: maximum number of reports

    Fetch logic:
    1. Get the latest report time from last fetch or start from fetch in case its a the first time fetching
    2. get all the reports since the last fetch or first fetch
    3. remove any reports which where already fetched
    4. if there are no reports after dedup, keep the last run the same and return
    5. if there are reports after dedup, update the last run to the latest report time, save all the report IDs which
       occurred in the last event time
    6. return all the fetched events

    """
    last_run_time = last_run.get(LastRun.LATEST_REPORT_TIME)
    if not last_run_time:
        last_run_time = dateparser.parse(first_fetch).strftime(DATE_FORMAT)  # type: ignore[union-attr]
        if not last_run_time:
            demisto.error(f'First fetch {first_fetch} is not valid')
            raise ValueError(f'First fetch {first_fetch} not valid')
    else:
        last_run_time = dateparser.parse(last_run_time).strftime(DATE_FORMAT)  # type: ignore[union-attr]
    now = datetime.now()
    reports = client.get_reports(start_date=last_run_time, end_date=now.strftime(DATE_FORMAT), limit=max_fetch)
    reports = dedup_fetched_events(reports, last_run_fetched_event_ids=last_run.get(LastRun.LATEST_FETCHED_REPORTS_IDS) or set())
    if not reports:
        demisto.debug(f'No reports found when last run is {last_run}')
        return [], {
            LastRun.LATEST_REPORT_TIME: last_run_time,
            LastRun.LATEST_FETCHED_REPORTS_IDS: last_run.get(LastRun.LATEST_FETCHED_REPORTS_IDS)
        }

    latest_report_time, latest_fetched_report_ids = get_latest_event_time_and_ids(reports)
    demisto.debug(f'latest-report-time: {latest_report_time}')
    demisto.debug(f'latest-fetched-report-ids {latest_fetched_report_ids}')

    last_run.update(
        {
            LastRun.LATEST_REPORT_TIME: latest_report_time,
            LastRun.LATEST_FETCHED_REPORTS_IDS: latest_fetched_report_ids
        }
    )
    return reports, last_run


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get events from Cybel Angel, used mainly for debugging purposes
    """
    if end := args.get("end_date"):
        end_date = dateparser.parse(end).strftime(DATE_FORMAT)  # type: ignore[union-attr]
    else:
        end_date = datetime.now().strftime(DATE_FORMAT)

    reports = client.get_reports(
        dateparser.parse(args["start_date"]).strftime(DATE_FORMAT),  # type: ignore[union-attr]
        end_date=end_date,
        limit=arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    )

    return CommandResults(
        outputs_prefix="CybleAngel.Events",
        outputs_key_field="id",
        outputs=reports,
        raw_response=reports,
        readable_output=tableToMarkdown("Reports", reports, headers=["id", "created_at", "updated_at"], removeNull=True)
    )


def cybelangel_report_list_command(client: Client, args):

    start_date = arg_to_datetime(args.get("start_date"))
    end_date = arg_to_datetime(args.get("end_date"))

    response = client.http_request(
        "GET",
        "/api/v2/reports",
        params={"start-date": start_date, "end-date": end_date},
    )
    return CommandResults(
        outputs_prefix="CybelAngel.Report",
        outputs=response,
        readable_output="All reports retrieved.",
    )


def cybelangel_report_get_command(client: Client, args):

    report_id = args.get("report_id")
    pdf = argToBoolean(args.get("pdf", "false"))

    response = client.http_request("GET", f"/api/v2/reports/{report_id}")
    if pdf:
        pdf_response = client.http_request(
            "GET", f"/api/v1/reports/{report_id}/pdf", pdf=True
        )
        if pdf_response:
            return fileResult(
                f"cybelangel_report_{report_id}.pdf",
                pdf_response.content,
                file_type=EntryType.ENTRY_INFO_FILE,
            )
    return CommandResults(
        outputs_prefix="CybelAngel.Report",
        outputs=response,
        readable_output=f"Report ID {report_id} retrieved.",
    )


def cybelangel_mirror_report_get_command(client: Client, args):
    report_id = args.get("report_id")
    csv = argToBoolean(args.get("csv", "false"))

    endpoint = (
        f"/api/v1/reports/{report_id}/mirror/csv"
        if csv
        else f"/api/v1/reports/{report_id}/mirror"
    )
    response = client.http_request("GET", endpoint, cve=True)

    if csv:
        return fileResult(
            f"cybelangel_mirror_report_{report_id}.csv",
            response.content,
            file_type=EntryType.ENTRY_INFO_FILE,
        )

    return CommandResults(
        outputs_prefix="CybelAngel.ReportMirror",
        outputs=response,
        readable_output=f"Mirror details for Report ID {report_id} retrieved.",
    )


def cybelangel_archive_report_by_id_get_command(client: Client, args):
    report_id = args.get("report_id")

    endpoint = f"/api/v1/reports/{report_id}/mirror/archive"
    response = client.http_request("GET", endpoint, cve=True)

    return fileResult(
        f"cybelangel_archive_report_{report_id}.zip",
        response.content,
        file_type=EntryType.ENTRY_INFO_FILE,
    )


def cybelangel_report_status_update_command(client: Client, args):
    report_ids = argToList(args.get("report_ids"))
    status = args.get("status")

    if len(report_ids) == 1:
        client.http_request(
            "PUT", f"/api/v1/reports/{report_ids[0]}/status", data={"status": status}
        )
    else:
        client.http_request(
            "POST", "/api/v1/reports/status", data={"ids": report_ids, "status": status}
        )

    return CommandResults(
        readable_output=f"Status of {', '.join(report_ids)} was successfully updated."
    )


def cybelangel_report_comments_get_command(client: Client, args):
    report_id = args.get("report_id")

    endpoint = f"/api/v1/reports/{report_id}/comments"
    response = client.http_request("GET", endpoint)

    return CommandResults(
        outputs_prefix="CybelAngel.Report.Comments",
        outputs=response,
        readable_output=f"Comments for Report ID {report_id} retrieved.",
    )


def cybelangel_report_comment_create_command(client: Client, args):
    report_id = args.get("report_id")
    content = args.get("content")
    parent_id = args.get("parent_id")
    assigned = argToBoolean(args.get("assigned", "false"))

    comments_response = client.http_request(
        "GET", f"/api/v1/reports/{report_id}/comments"
    )
    discussion_id = comments_response.get("comments", [])[0].get("discussion_id")
    if not discussion_id:
        raise ValueError("Unable to retrieve tenant ID")

    data = {
        "content": content,
        "discussion_id": discussion_id,
        "parent_id": parent_id,
        "assigned": assigned if assigned == "True" else "",
    }
    remove_nulls_from_dictionary(data)

    response = client.http_request(
        "POST", f"/api/v1/reports/{report_id}/comments", data=data
    )

    return CommandResults(
        outputs_prefix="CybelAngel.Report.Comments",
        outputs=response,
        readable_output=f"Comment added to Report ID {report_id}.",
    )


def cybelangel_report_attachment_get_command(client: Client, args):
    report_id = args.get("report_id")
    attachment_id = args.get("attachment_id")

    response = client.http_request(
        "GET", f"/api/v1/reports/{report_id}/attachments/{attachment_id}", pdf=True
    )

    return fileResult(
        f"cybelangel_report_{report_id}_attachment_{attachment_id}.csv",
        response.text,
        file_type=EntryType.ENTRY_INFO_FILE,
    )
    # return CommandResults(
    #     outputs_prefix="CybelAngel.Report.Attachment",
    #     outputs=response.text,
    #     readable_output=f"Attachment ID {attachment_id} for Report ID {report_id} retrieved."
    # )


def cybelangel_report_remediation_request_create_command(client: Client, args):
    report_id = args.get("report_id")
    requestor_email = args.get("requestor_email")
    requestor_fullname = args.get("requestor_fullname")

    endpoint = "/api/v1/reports/remediation-request"
    data = {
        "report_id": report_id,
        "requester_email": requestor_email,
        "requester_fullname": requestor_fullname,
    }

    client.http_request("POST", endpoint, data=data)

    return CommandResults(
        readable_output=f"Remediation request was created for {report_id}."
    )


''' MAIN FUNCTION '''


def main() -> None:

    params = demisto.params()
    args = demisto.args()
    client_id: str = params.get('credentials', {}).get('identifier', '')
    client_secret: str = params.get('credentials', {}).get('password', '')
    base_url: str = params.get('url', '').rstrip('/')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    first_fetch = params.get("first_fetch") or DEFAULT_FIRST_FETCH

    commands = {
        "cybelangel-report-list": cybelangel_report_list_command,
        "cybelangel-report-get": cybelangel_report_get_command,
        "cybelangel-mirror-report-get": cybelangel_mirror_report_get_command,
        "cybelangel-archive-report-by-id-get": cybelangel_archive_report_by_id_get_command,
        "cybelangel-report-status-update": cybelangel_report_status_update_command,
        "cybelangel-report-comments-get": cybelangel_report_comments_get_command,
        "cybelangel-report-comment-create": cybelangel_report_comment_create_command,
        "cybelangel-report-attachment-get": cybelangel_report_attachment_get_command,
        "cybelangel-report-remediation-request-create": cybelangel_report_remediation_request_create_command,
    }

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'fetch-events':
            events, last_run = fetch_events(client, first_fetch=first_fetch, last_run=demisto.getLastRun(), max_fetch=max_fetch)
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent event {[event.get("id") for event in events]} IDs to XSIAM')
            demisto.setLastRun(last_run)
        elif command == "cybelangel-get-events":
            return_results(get_events_command(client, demisto.args()))
        elif command in commands:
            return_results(commands[command](client, args))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
