import dateparser

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any
from requests import Response
from datetime import datetime, timedelta

# Disable insecure warnings
urllib3.disable_warnings()


DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

CREDENTIALS = "Credential watchlist"
REPORT = "Reports"
DOMAIN = "Domain watchlist"

DEFAULT_LIMITS = {
    REPORT: 5000,
    CREDENTIALS: 50,
    DOMAIN: 500,
}

URL = {
    REPORT: "/api/v2/reports",
    CREDENTIALS: "/api/v1/credentials",
    DOMAIN: "/api/v1/domains",
}

ID_KEYS = {
    REPORT: "id",
    CREDENTIALS: "stream_id",
    DOMAIN: "stream",
}

TIME_FIELDS = {
    REPORT: "updated_at",
    CREDENTIALS: "last_detection_date",
    DOMAIN: "detection_date",  # TODO might be creation_date check with Meital
}

VENDOR = "cybelangel"
PRODUCT = "platform"

LATEST_TIME = "latest_time"
LATEST_FETCHED_IDS = "latest_fetched_ids"


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        verify: bool,
        proxy: bool,
        **kwargs,
    ):
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
        csv: bool = False,
    ) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": ("application/json" if not pdf else "application/pdf, application/json"),
        }

        demisto.debug(f"Running http-request with URL {url_suffix} and {params=}")

        response = self._http_request(
            method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            json_data=data,
            resp_type="response",
            ok_codes=(401, 403, 200, 201, 302, 404),
        )
        if response.status_code in (200, 201):
            return response.json() if not pdf else response

        if response.status_code == 302 and csv:
            cve_response = requests.get(url=response.text)
            return cve_response

        else:
            demisto.debug("Access token has expired, retrieving new access token")

        token = self.get_access_token(create_new_token=True)
        headers["Authorization"] = f"Bearer {token}"

        return self._http_request(
            method,
            url_suffix=url_suffix,
            headers=headers,
            params=params,
            json_data=data,
            ok_codes=(200, 201, 302, 404),
        )

    def get_reports(
        self,
        start_date: str,
        end_date: str,
        limit: int = DEFAULT_LIMITS[REPORT],
    ) -> List[dict[str, Any]]:
        """
        Get manual reports from Cybel Angel Collector.

        Note:
            The order of the events returned is random, hence need to sort them out to return the oldest events first.
        """
        params = {"start-date": start_date, "end-date": end_date}
        demisto.debug("Calling get reports list")
        reports = self.get_reports_list(params)

        demisto.debug(f"Get reports list returned {len(reports)} reports.")
        reports = add_fields_to_events(reports, REPORT)
        reports = sorted(
            reports,
            key=lambda _report: dateparser.parse(_report["_time"]),  # type: ignore[arg-type, return-value]
        )
        return reports

    def get_credentials_watchlist(
        self,
        start_date: str,
        end_date: str,
        limit: int = DEFAULT_LIMITS[CREDENTIALS],
    ) -> List[dict[str, Any]]:
        """
        Fetch credential-watchlist events from CybelAngel and prepare them for ingestion into XSIAM.
        This will request up to `limit` credentials ordered by `last_detection_date` ascending,
        then tag each record with `_time` and `SOURCE_LOG_TYPE`.

        Args:
            start_date (str): ISO-formatted lower bound for `last_detection_date` (e.g. "2025-05-01T00:00:00").
            end_date   (str): ISO-formatted upper bound for `last_detection_date` (e.g. "2025-05-11T14:00:00").
            limit      (int): Maximum number of credential entries to retrieve (default: DEFAULT_MAX_FETCH_CREDS).

        Returns:
            List[dict[str, Any]]: A list of credential-watchlist events, each containing:
            - all original API fields
            - `_time` set to the value of `TIME_FIELDS[CREDENTIALS]`
            - `SOURCE_LOG_TYPE` = `CREDENTIALS`

            The list is returned in ascending order by detection date.
        """
        params = {
            "sort_by": "last_detection_date",
            "limit": limit,
            "order": "asc",
            "start": start_date,
            "end": end_date,
        }
        response = self.http_request(method="GET", url_suffix=URL[CREDENTIALS], params=params) or []

        if not isinstance(response, list):
            demisto.debug("Type return error in credentials request")
            return []

        return add_fields_to_events(response, CREDENTIALS)

    def get_domain_watchlist(
        self,
        start_date: str,
        end_date: str,
        limit: int = DEFAULT_LIMITS[DOMAIN],
    ) -> List[dict[str, Any]]:
        """
        Fetch domain-watchlist events from CybelAngel, handling pagination when more than `limit` events exist.

        CybelAngel’s API returns events in descending order by detection date. This method:
        1. Requests up to `limit` events.
        2. If the API reports more exist, requests the remaining events using `skip`/`limit`.
        3. Combines both pages.
        4. Reverses the combined list so that events are in ascending order by detection date.
        5. Annotates each record with `_time` and `SOURCE_LOG_TYPE`.

        Args:
            start_date (str): ISO-formatted lower bound for `detection_date`.
            end_date   (str): ISO-formatted upper bound for `detection_date`.
            limit      (int): Maximum number of domain entries to retrieve (default: DEFAULT_MAX_FETCH_DOMAINS).

        Returns:
            List[dict[str, Any]]: Domain-watchlist events sorted in ascending order by
            detection date, each containing:
            - all original API fields
            - `_time`: copied from `TIME_FIELDS[DOMAIN]`
            - `SOURCE_LOG_TYPE`: set to `DOMAIN`
        """
        params = {
            "min-date": start_date,
            "max-date": end_date,
            "limit": limit,
        }

        response = self.http_request(method="GET", url_suffix=URL[DOMAIN], params=params) or {}
        if not isinstance(response, dict):
            demisto.debug("Type error: expected dict from domain request")
            return []

        events = response.get("results", [])
        total = response.get("total", 0)
        demisto.debug(f"Fetched {len(events)} / {total} domain events on first call")

        if total > len(events):
            remaining = total - len(events)
            demisto.debug(f"{remaining} more events available; fetching skip={len(events)}")
            params.update({"limit": remaining, "skip": len(events)})
            second_response = self.http_request(method="GET", url_suffix=URL[DOMAIN], params=params) or {}

            if not isinstance(second_response, dict):
                demisto.debug("Type error: expected dict from second domain request")
                return []
            more_events = second_response.get("results", [])
            demisto.debug(f"Fetched {len(more_events)} domain events on second call")
            events.extend(more_events)

        events.reverse()

        return add_fields_to_events(events, DOMAIN)

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
        current_access_token = integration_context.get("access_token")
        if current_access_token and not create_new_token:
            return current_access_token
        new_access_token = self.get_token_request()
        integration_context = {
            "access_token": new_access_token,
        }
        demisto.debug(f"updating access token at {datetime.now()}")
        set_integration_context(context=integration_context)
        return new_access_token

    def get_token_request(self) -> str:
        """
        Sends request to retrieve token.

        Returns:
           tuple[str, str]: token and its expiration date
        """
        url = "https://auth.cybelangel.com/oauth/token"

        token_response = self._http_request(
            "POST",
            full_url=url,
            json_data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": "https://platform.cybelangel.com/",
                "grant_type": "client_credentials",
            },
        )
        if access_token := token_response.get("access_token"):
            return access_token
        raise RuntimeError(f"Could not retrieve token from {url}, access-token returned is empty")

    def get_reports_list(self, params: dict) -> list:
        """
        Retrieves a list of reports from the CybelAngel API.

        Args:
            params (dict): required parameters to filter the reports.
            start_date (str) and end_date (str)

        Returns:
            List: List of reports, or an empty list if no reports are found.
        """
        return self.http_request(method="GET", url_suffix=URL[REPORT], params=params).get("reports") or []  # type: ignore

    def get_report_by_id(self, id: str, pdf: bool) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Retrieves a report by its ID.

        Args:
            id (str): The ID of the report.
            pdf (bool): Whether to retrieve the report in PDF format.

        Returns:
            dict[str, Any] | Response: The report data or response object.
        """
        endpoint = f"/api/v1/reports/{id}"
        endpoint += "/pdf" if pdf else ""
        return self.http_request("GET", endpoint, pdf=pdf)

    def get_mirror_report(self, id: str, csv: bool) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Retrieves a mirrored report by its ID.

        Args:
            id (str): The ID of the report.
            csv (bool): Whether to retrieve the report in CSV format.

        Returns:
            dict[str, Any] | Response: The mirrored report data or response object.
        """
        endpoint = f"/api/v1/reports/{id}/mirror"
        endpoint += "/csv" if csv else ""
        return self.http_request("GET", endpoint, csv=True)

    def get_archive_report(self, id: str) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Retrieves an archived mirrored report by its ID.

        Args:
            id (str): The ID of the report.

        Returns:
            dict[str, Any] | Response: The archived report data or response object.
        """
        endpoint = f"/api/v1/reports/{id}/mirror/archive"
        return self.http_request("GET", endpoint, csv=True)

    def status_update(self, reports_ids: list, status: str):
        """
        Updates the status of multiple reports.

        Args:
            reports_ids (list): A list of report IDs to update.
            status (str): The new status to apply.

        Returns:
            dict[str, Any] | Response: The response from the API.
        """
        data = {"ids": reports_ids, "status": status}
        return self.http_request("POST", "/api/v1/reports/status", data=data)

    def get_report_comment(self, id: str, data: dict = {}) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Retrieves or creates a comment for a report.

        Args:
            id (str): The ID of the report.
            data (dict, optional): The comment data to create. Defaults to an empty dictionary.

        Returns:
            dict[str, Any] | Response: The report comment data or response object.
        """
        # Using POST method to create new comment
        method = "POST" if data else "GET"
        return self.http_request(method, f"/api/v1/reports/{id}/comments", data=data)

    def get_report_attachment(self, report_id: str, attachment_id: str) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Retrieves an attachment from a report.

        Args:
            report_id (str): The ID of the report.
            attachment_id (str): The ID of the attachment.

        Returns:
            dict[str, Any] | Response: The report attachment data or response object.
        """
        return self.http_request("GET", f"/api/v1/reports/{report_id}/attachments/{attachment_id}", pdf=True)

    def post_report_remediation_request(self, data: dict) -> dict[str, Any] | Response | list[dict[str, Any]]:
        """
        Submits a remediation request for a report.

        Args:
            data (dict): The remediation request data.

        Returns:
            dict[str, Any] | Response: The response from the API.
        """
        return self.http_request("POST", "/api/v1/reports/remediation-request", data=data)


def add_fields_to_events(events: list, event_type: str):
    for event in events:
        if event_type == REPORT:
            if updated_at := event.get("updated_at"):
                _time_field = updated_at
            else:
                _time_field = event["created_at"]
        else:
            _time_field = event.get(TIME_FIELDS[event_type])

        event["_time"] = _time_field
        event["source_log_type"] = event_type
    return events


def dedup_fetched_events(events: List[dict], last_run_fetched_event_ids: Set[str], event_type: str) -> List[dict]:
    """
    Deduplicate fetch results by filtering out events that have already been processed.

    Args:
        events (List[dict]): A list of event dictionaries as returned by the API.
        last_run_fetched_event_ids (Set[str]): A set of event IDs that were fetched in the previous run.
        type (str): The event type we are working one (e.g., REPORT, CREDS, DOMAIN).

    Returns:
        List[dict]: A list of event after deduplication.
    """
    id_key = ID_KEYS[event_type]

    un_fetched_events = []

    for event in events:
        event_id = event.get(id_key)
        if event_id not in last_run_fetched_event_ids:
            demisto.debug(f"event with ID {event_id} has not been fetched.")
            un_fetched_events.append(event)
        else:
            demisto.debug(f"event with ID {event_id} for has been fetched")

    return un_fetched_events


def get_latest_event_time_and_ids(
    events: List[Dict[str, Any]], event_type: str, last_run_time: str, last_run_ids: list[str]
) -> tuple[str, List[str]]:
    """
    Determine the latest event timestamp and assemble the corresponding IDs.
    This function assumes that `events` is sorted by `_time` in ascending order.
    It will:
      1. Take the `_time` value from the last event as `latest_time`.
      2. Collect all IDs for events whose `_time` equals `latest_time`.
      3. If `latest_time` matches `last_run_time`, extends the previous run’s IDs

    Args:
        reports     (List[Dict]): A list of event dicts, each containing an `_time` key and the relevant ID field.
        type               (str): The category of events (REPORT, CREDENTIALS, or DOMAIN).
        last_run_time      (str): The timestamp string recorded in the previous run.
        last_run_ids (List[str]): The list of IDs recorded in the previous run.

    Returns:
        tuple[str, List[str]]: A tuple where:
            - latest_time: the `_time` string of the most recent event
            - latest_ids: list of event IDs for all events whose `_time` matches that latest timestamp.
    """
    id_key = ID_KEYS[event_type]

    latest_time = events[-1]["_time"]

    latest_ids = [event[id_key] for event in events if event["_time"] == latest_time]

    if latest_time == last_run_time:
        latest_ids.extend(last_run_ids)

    return latest_time, latest_ids


def test_module(client: Client) -> str:
    """
    Tests that the authentication to the api is ok.
    """
    client.get_reports(
        start_date=(datetime.now() - timedelta(days=1)).strftime(DATE_FORMAT),
        end_date=datetime.now().strftime(DATE_FORMAT),
        limit=100,
    )
    return "ok"


def fetch_events(client: Client, max_fetch: dict, events_type_to_fetch: list[str]) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    """
    Fetch and deduplicate events across multiple types from CybelAngel, updating last-run state.

    For each event type, this function:
      1. Retrieves the previous run's timestamp and IDs via `get_last_run()`.
      2. Fetch events foreach type using the relevant command:
        2.1 For REPORT fetches all events in the time interval.
        2.2 For DOMAIN/CREDENTIALS fetches up `max_fetch[type] + previous_count`.
      3. Removes any events already fetched.
      4. If no new events remain:
         - Sets this type's last-run timestamp to now and clears its ID list.
      5. Otherwise:
         - Truncates to `max_fetch[type]` events.
         - Determines the latest timestamp and corresponding IDs via `get_latest_event_time_and_ids()`.
         - Updates this type's last-run record.
    All newly fetched events (across all types) are concatenated and returned alongside the updated last-run map.

    Args:
        client                  (Client): CybelAngel API client instance.
        max_fetch       (Dict[str, int]): Maximum number of events to return per event type.
        event_types_to_fetch (List[str]): List of event-type keys to fetch (REPORT, DOMAIN, CREDENTIALS).

    Returns:
        Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
            - all_events: List of deduplicated event dicts fetched across all types.
            - last_run: Mapping from each event type to its updated:
                {
                  LATEST_TIME: "<ISO timestamp>",
                  LATEST_FETCHED_IDS: [<str>, ...]
                }
    """
    now = datetime.now()
    last_run = get_last_run(now, events_type_to_fetch)
    all_events = []

    event_fetch_function = {
        DOMAIN: client.get_domain_watchlist,
        CREDENTIALS: client.get_credentials_watchlist,
        REPORT: client.get_reports,
    }
    for event_type in events_type_to_fetch:
        demisto.debug(f"Fetching {event_type}")
        last_time = last_run.get(event_type, {}).get(LATEST_TIME)
        last_ids = last_run.get(event_type, {}).get(LATEST_FETCHED_IDS, [])
        demisto.debug(f"Last run for {event_type}: time={last_time}, ids={len(last_ids)}")

        fetch_func = event_fetch_function.get(event_type)
        if not fetch_func:
            demisto.debug(f"No fetch function for event type '{event_type}'")
            continue

        events = fetch_func(start_date=last_time, end_date=now.strftime(DATE_FORMAT), limit=max_fetch[event_type] + len(last_ids))

        demisto.debug(f"Fetched {len(events)} raw events for {event_type}")

        events = dedup_fetched_events(events=events, last_run_fetched_event_ids=set(last_ids), event_type=event_type)
        demisto.debug(f"{len(events)} events remain after dedup for {event_type}")

        if events:
            events = events[: max_fetch[event_type]]

        if not events:
            demisto.debug(f"No new {event_type} events; resetting last_run timestamp")
            last_run[event_type] = {LATEST_TIME: now.strftime(DATE_FORMAT), LATEST_FETCHED_IDS: []}
        else:
            latest_time, latest_ids = get_latest_event_time_and_ids(events, event_type, last_time, last_ids)
            demisto.debug(f"{event_type} latest time: {latest_time}, latest IDs: {latest_ids}")

            last_run[event_type] = {LATEST_TIME: latest_time, LATEST_FETCHED_IDS: latest_ids}
            all_events.extend(events)

    demisto.debug(f"Total events fetched across all types: {len(all_events)}")
    return all_events, last_run


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get events from Cybel Angel, used mainly for debugging purposes
    """
    event_type = args.get("event_type", REPORT)
    limit = int(args.get("limit", 50))
    demisto.debug(f"Int:{isinstance(limit,int)}, str:{isinstance(limit,str)}")
    now = datetime.now()
    end_date = args.get("end_date") or now.strftime(DATE_FORMAT)
    end_dt = dateparser.parse(end_date) or now

    start_date = args.get("start_date") or (end_dt - timedelta(minutes=1)).strftime(DATE_FORMAT)

    event_fetch_function = {
        DOMAIN: client.get_domain_watchlist,
        CREDENTIALS: client.get_credentials_watchlist,
        REPORT: client.get_reports,
    }
    events = []
    fetch_func = event_fetch_function.get(event_type)
    if fetch_func:
        events = fetch_func(start_date=start_date, end_date=end_date, limit=limit)
    events = events[:limit]
    demisto.debug("Prepapring command result")
    if argToBoolean(args.get("is_fetch_events") or False):
        send_events_to_xsiam(vendor=VENDOR, product=PRODUCT, events=events)
        demisto.debug(f"Successfully send {len(events)} to XSIAM.")
    return CommandResults(
        outputs_prefix="CybleAngel.Events",
        outputs_key_field="id",
        outputs=events,
        raw_response=events,
        readable_output=tableToMarkdown(
            f"{event_type}", events, headers=["_time", "SOURCE_LOG_TYPE", ID_KEYS[event_type]], removeNull=True
        ),
    )


def cybelangel_report_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of reports within the specified date range.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes optional `start_date` and `end_date`.

    Returns:
        CommandResults: Report list in table format.
    """
    start_date = arg_to_datetime(args.get("start_date"))
    end_date = arg_to_datetime(args.get("end_date"))

    response = client.get_reports_list({"start-date": start_date, "end-date": end_date})
    human_readable = tableToMarkdown(
        "Reports list",
        response,
        headers=[
            "id",
            "url",
            "report_type",
            "sender",
            "severity",
            "status",
            "updated_at",
            "report_content",
        ],
    )
    return CommandResults(
        outputs_prefix="CybelAngel.Report",
        outputs_key_field="id",
        outputs=response,
        readable_output=human_readable,
    )


def cybelangel_report_get_command(client: Client, args: dict) -> CommandResults | dict:
    """
    Retrieves a report by ID, optionally as a PDF.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id` (required) and `pdf` (optional).

    Returns:
        CommandResults: Report details, or a PDF file result.
    """
    report_id = args.get("report_id", "")
    pdf = argToBoolean(args.get("pdf", "false"))
    response = client.get_report_by_id(report_id, pdf=pdf)
    if pdf:
        return fileResult(f"cybelangel_report_{report_id}.pdf", response.content, EntryType.ENTRY_INFO_FILE)  # type: ignore
    human_readable = tableToMarkdown(
        f"Report ID {report_id} details",
        response,
        headers=[
            "id",
            "url",
            "report_type",
            "sender",
            "severity",
            "status",
            "updated_at",
            "report_content",
        ],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="CybelAngel.Report",
        outputs_key_field="id",
        outputs=response,
        readable_output=human_readable,
    )


def cybelangel_mirror_report_get_command(client: Client, args: dict) -> CommandResults | dict:
    """
    Retrieves mirror details for a report, optionally as a CSV file.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id` (required) and `csv` (optional).

    Returns:
        CommandResults: Mirror report details or a CSV file result.
    """
    report_id = args.get("report_id", "")
    csv = argToBoolean(args.get("csv", "false"))
    response = client.get_mirror_report(report_id, csv)

    if isinstance(response, dict) and "title" in response:
        return CommandResults(raw_response=response, readable_output=f"{response.get('title')}")

    if csv:
        return fileResult(
            f"cybelangel_mirror_report_{report_id}.csv",
            response.content,  # type: ignore
            file_type=EntryType.ENTRY_INFO_FILE,
        )
    human_readable = tableToMarkdown(
        f"Mirror details for Report ID {report_id}",
        response,
        headers=["report_id", "created_at", "available_files_count", "updated_at"],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="CybelAngel.ReportMirror",
        outputs_key_field="report_id",
        outputs=response,
        readable_output=human_readable,
    )


def cybelangel_archive_report_by_id_get_command(client: Client, args: dict) -> CommandResults | dict:
    """
    Retrieves the archived mirror of a report as a ZIP file.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id` (required).

    Returns:
        CommandResults: Archive report as a ZIP file or a raw response with the report title.
    """
    report_id = args.get("report_id", "")

    response = client.get_archive_report(report_id)
    if isinstance(response, dict) and "title" in response:
        return CommandResults(raw_response=response, readable_output=f"{response.get('title')}")

    return fileResult(
        f"cybelangel_archive_report_{report_id}.zip",
        response.content,  # type: ignore
        file_type=EntryType.ENTRY_INFO_FILE,
    )


def cybelangel_report_status_update_command(client: Client, args: dict) -> CommandResults:  # pragma: no cover
    """
    Updates the status of one or more reports.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_ids` (required) and `status` (required).

    Returns:
        CommandResults: Success message with the count of updated reports.
    """
    report_ids = argToList(args.get("report_ids"))
    status = args.get("status", "")

    client.status_update(report_ids, status)

    return CommandResults(
        readable_output=f"The status of the following reports {report_ids} has been successfully updated to {status}"
    )


def cybelangel_report_comments_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves comments for a specific report by its ID.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id` (required).

    Returns:
        CommandResults: Comments related to the report in a structured table format.
    """
    report_id = args.get("report_id", "")

    response = client.get_report_comment(report_id)

    if not response.get("comments"):  # type: ignore
        return CommandResults(readable_output=f"There are no comments for report ID: {report_id}")
    if isinstance(response, dict):
        response["id"] = report_id
        response["Comment"] = response.pop("comments")
    hr_response = [
        {**comment, "author_firstname": comment["author"]["firstname"], "author_lastname": comment["author"]["lastname"]}
        for comment in response.get("Comment", [])  # type: ignore
    ]
    human_readable = tableToMarkdown(
        f"Comments for Report ID {report_id}",
        hr_response,
        headers=[
            "content",
            "created_at",
            "parent_id",
            "discussion_id",
            "assigned",
            "author_firstname",
            "author_lastname",
            "last_updated_at",
        ],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="CybelAngel.Report",
        outputs_key_field="id",
        outputs=response,
        readable_output=human_readable,
    )


def cybelangel_report_comment_create_command(client: Client, args: dict) -> CommandResults:
    """
    Adds a comment to a specific report.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id` (required), `content` (required), `parent_id` (optional), and `assigned` (optional).

    Returns:
        CommandResults: Success message indicating comment creation.
    """
    discussion_id = args.get("discussion_id", "")
    if ":" not in discussion_id:
        raise ValueError("Invalid discussion_id format. Expected format: 'report_id:tenant_id'.")
    report_id = discussion_id.split(":")[0]
    content = args.get("content")
    parent_id = args.get("parent_id")
    assigned = argToBoolean(args.get("assigned", "false"))

    data = {"content": content, "discussion_id": discussion_id}
    if parent_id:
        data["parent_id"] = parent_id
    if assigned:
        data["assigned"] = assigned

    client.get_report_comment(report_id, data=data)

    return CommandResults(
        readable_output=f"Comment created successfully for report ID: {report_id}",
    )


def cybelangel_report_attachment_get_command(client: Client, args: dict) -> dict | CommandResults:
    """
    Retrieves a specific attachment from a report.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id` (required) and `attachment_id` (required).

    Returns:
        dict | CommandResults: Attachment content as a file or raw response with attachment title.
    """
    report_id = args.get("report_id", "")
    attachment_id = args.get("attachment_id", "")

    response = client.get_report_attachment(report_id, attachment_id)
    if isinstance(response, dict) and "title" in response:
        return CommandResults(raw_response=response, readable_output=f"{response.get('title')}")

    return fileResult(
        f"cybelangel_report_{report_id}_attachment_{attachment_id}.csv",
        response.text,  # type: ignore
        file_type=EntryType.ENTRY_INFO_FILE,
    )


def cybelangel_report_remediation_request_create_command(client: Client, args: dict) -> CommandResults:  # pragma: no cover
    """
    Creates a remediation request for a report.

    Args:
        client (Client): CybelAngel API client.
        args (dict): Includes `report_id`, `requestor_email`, and `requestor_fullname` (all required).

    Returns:
        CommandResults: Success message indicating the remediation request creation.
    """
    report_id = args.get("report_id")
    requestor_email = args.get("requestor_email")
    requestor_fullname = args.get("requestor_fullname")

    data = {
        "report_id": report_id,
        "requester_email": requestor_email,
        "requester_fullname": requestor_fullname,
    }

    response = client.post_report_remediation_request(data)

    return CommandResults(
        outputs_prefix="CybelAngel.RemediationRequest",
        outputs_key_field="report_id",
        outputs=response,
        readable_output=f"Remediation request was created for {report_id}",
    )


def get_last_run(now: datetime, events_type_to_fetch: list[str]) -> dict:
    """
    Retrieve and initialize the “last run” timestamps for a set of event types.
    This function loads the existing last‐run state via `demisto.getLastRun()`.
    For any event type that is missing or newly requested, it sets:
      - `LATEST_TIME` to one minute before `now`.
      - `LATEST_FETCHED_IDS` to an empty list

    Args:
        now (datetime): Reference time for computing initial fetch timestamps.
        events_to_fetch (List[str]): Names of event types that should be tracked this run.

    Returns:
        Dict[str, Dict[str, Any]]: A mapping of each event type to its last-run info:
            {
                "<EVENT_TYPE>": {
                    LATEST_TIME: "<ISO-formatted timestamp string>",
                    LATEST_FETCHED_IDS: List[str]
                },
            }
    """
    last_run = demisto.getLastRun()
    last_time = now - timedelta(minutes=1)
    if not last_run:
        last_run = {}
        last_time = now - timedelta(days=60)  # TODO
        demisto.debug("First run")
    for event_type in [REPORT, DOMAIN, CREDENTIALS]:
        if event_type not in last_run or (event_type in last_run and event_type not in events_type_to_fetch):
            last_run[event_type] = {LATEST_TIME: last_time.strftime(DATE_FORMAT), LATEST_FETCHED_IDS: []}

    return last_run


""" MAIN FUNCTION """


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    client_id: str = params.get("credentials", {}).get("identifier", "")
    client_secret: str = params.get("credentials", {}).get("password", "")
    base_url: str = params.get("url", "").rstrip("/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    events_type_to_fetch = argToList(params.get("events_type_to_fetch", [CREDENTIALS, DOMAIN, REPORT]))
    demisto.debug(f"Event types to fetch: {events_type_to_fetch}")
    max_fetch_reports = int(params.get("max_fetch", DEFAULT_LIMITS[REPORT]))
    max_fetch_creds = int(params.get("max_fetch_creds", DEFAULT_LIMITS[CREDENTIALS]))
    max_fetch_domain = int(params.get("max_fetch_domain", DEFAULT_LIMITS[DOMAIN]))
    max_fetch = {REPORT: max_fetch_reports, CREDENTIALS: max_fetch_creds, DOMAIN: max_fetch_domain}
    demisto.debug(f"Max fetch: {max_fetch}")

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
    demisto.info(f"Command being called is {command}")
    try:
        client = Client(
            client_id=client_id, client_secret=client_secret, base_url=base_url, verify=verify_certificate, proxy=proxy
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-events":
            events, last_run = fetch_events(client, max_fetch, events_type_to_fetch)
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


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
