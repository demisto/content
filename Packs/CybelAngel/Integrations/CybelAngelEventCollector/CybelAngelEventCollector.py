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

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"

VENDOR = "cybelangel"
PRODUCT = "platform"


class EventType:
    """
    This class defines a CybelAngel API Event - used to dynamically store
    per-type settings for fetching and deduplicating events.
    """

    def __init__(
        self,
        name: str,
        url_suffix: str,
        id_key: Union[str, List[str]],
        ascending_order: bool,
        time_field: str,
        source_log_type: str,
        default_max_fetch: int,
    ):
        """
        Args:
            name                     (str): Human-friendly name of the event type, as in the params names..
            url_suffix               (str): URL suffix of the CybelAngel API endpoint.
            id_key (Union[str, List[str]]): Key or list of keys used to uniquely identify an event.
            ascending_order         (bool): Events sorted by ascending/descending order after returning from get function.
            time_field               (str): Field name in the event used for timestamp mapping (`_time`).
            source_log_type          (str): Value to assign to each event's `source_log_type` field in XSIAM.
            default_max_fetch        (int): Default max_fetch limit.
        """
        self.name = name
        self.url_suffix = url_suffix
        self.max_fetch = 1
        self.id_key = id_key
        self.ascending_order = ascending_order
        self.max_index = -1 if ascending_order else 0
        self.time_field = time_field
        self.source_log_type = source_log_type
        self.default_max_fetch = default_max_fetch

    def get_id(self, event: Dict[str, Any]) -> str:
        """Return unique id by the id_key fields"""
        if isinstance(self.id_key, list):
            return "".join(str(event[k]) for k in self.id_key)
        return str(event.get(self.id_key, ""))


REPORT = EventType(
    name="Reports",
    url_suffix="/api/v2/reports",
    id_key="id",
    ascending_order=True,
    time_field="updated_at",
    source_log_type="Report",
    default_max_fetch=5000,
)
CREDENTIALS = EventType(
    name="Credential watchlist",
    url_suffix="/api/v1/credentials",
    id_key=["last_detection_date", "email"],
    ascending_order=True,
    time_field="last_detection_date",
    source_log_type="Credential watchlist",
    default_max_fetch=50,
)
DOMAIN = EventType(
    name="Domain watchlist",
    url_suffix="/api/v1/domains",
    id_key=["detection_date", "domain"],
    ascending_order=False,
    time_field="detection_date",
    source_log_type="Domain watchlist",
    default_max_fetch=500,
)

EVENT_TYPE = {"Reports": REPORT, "Credential watchlist": CREDENTIALS, "Domain watchlist": DOMAIN}

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
        limit: int,
    ) -> List[dict[str, Any]]:
        """
        Get manual reports from Cybel Angel Collector.
        The order of the events returned is random, hence need to sort them out to return the oldest events first.

        Args:
            start_date       (str): DATE_FORMAT lower bound (e.g. "2025-05-01T00:00:00.000Z").
            end_date         (str): DATE_FORMAT upper bound (e.g. "2025-05-11T14:00:00.000Z").

        Returns:
            List[dict[str, Any]]: A list of reports events, each containing:
            - all original API fields
            - `_time` set to the value of `REPORT.time_field`
            - `source_log_type` = `REPORT.source_log_type`

            The list is returned in ascending order by detection date.
        """

        params = {"start-date": start_date, "end-date": end_date}
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
        limit: int,
    ) -> List[dict[str, Any]]:
        """
        Fetch credential-watchlist events from CybelAngel and prepare them for ingestion into XSIAM.
        This will request up to `limit` credentials ordered by `last_detection_date` ascending,
        then tag each record with `_time` and `SOURCE_LOG_TYPE`.

        Args:
            start_date       (str): DATE_FORMAT lower bound (e.g. "2025-05-01T00:00:00.000Z").
            end_date         (str): DATE_FORMAT upper bound (e.g. "2025-05-11T14:00:00.000Z").
            limit            (int): Maximum number of credential entries to retrieve (default: DEFAULT_MAX_FETCH_CREDS).

        Returns:
            List[dict[str, Any]]: A list of credential-watchlist events, each containing:
            - all original API fields
            - `_time` set to the value of `CREDENTIALS.time_field`
            - `source_log_type` = `CREDENTIALS.source_log_type`

            The list is returned in ascending order by detection date.
        """
        params = {
            "sort_by": "last_detection_date",
            "limit": limit,
            "order": "asc",
            "start": start_date,
            "end": end_date,
        }
        response = self.http_request(method="GET", url_suffix=CREDENTIALS.url_suffix, params=params) or []

        return add_fields_to_events(response, CREDENTIALS)  # type: ignore

    def get_domain_watchlist(
        self,
        start_date: str,
        end_date: str,
        limit: int,
    ) -> List[dict[str, Any]]:
        """
        Fetch domain-watchlist events from CybelAngel, handling pagination when more than `limit` events exist.
        API return in descending order, in order the fetch the oldeset we fetch the whole time interval first.

        CybelAngel's API returns events in descending order by detection date.
        In order the fetch the first 'limit' events we do as follow:
        1. Requests up to `limit` events.
        2. If the API reports more events exists, requests the remaining events using `skip`/`limit`.
        3. Combines both pages.
        4. Annotates each record with `_time` and `SOURCE_LOG_TYPE`.

        Args:
            start_date       (str): DATE_FORMAT lower bound (e.g. "2025-05-01T00:00:00.000Z").
            end_date         (str): DATE_FORMAT upper bound (e.g. "2025-05-11T14:00:00.000Z").
            limit      (int): Maximum number of domain entries to retrieve (default: DEFAULT_MAX_FETCH_DOMAINS).

        Returns:
            List[dict[str, Any]]: Domain-watchlist events sorted in ascending order by
            detection date, each containing:
            - all original API fields
            - `_time` set to the value of `DOMAIN.time_field`
            - `source_log_type` = `DOMAIN.source_log_type`
        """
        params = {
            "min-date": start_date,
            "max-date": end_date,
            "limit": limit,
        }

        response = self.http_request(method="GET", url_suffix=DOMAIN.url_suffix, params=params) or {}

        events = response.get("results", {})  # type:ignore
        total = response.get("total", 0)  # type:ignore
        demisto.debug(f"Fetched {len(events)} / {total} domain events on first call")

        if total > len(events):
            remaining = total - len(events)
            demisto.debug(f"{remaining} more events available; fetching skip={len(events)}")
            params.update({"limit": remaining, "skip": len(events)})
            second_response = self.http_request(method="GET", url_suffix=DOMAIN.url_suffix, params=params) or {}
            events.extend(second_response.get("results", []))  # type: ignore

        demisto.debug(f"Total fetched {len(events)} domain events.")

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
        return self.http_request(method="GET", url_suffix=REPORT.url_suffix, params=params).get("reports") or []  # type: ignore

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


def add_fields_to_events(events: List[Dict[str, Any]], event_type: EventType) -> List[Dict[str, Any]]:
    """
    Annotate each event with:
      - `_time`: from its configured time_fields.
      - `SOURCE_LOG_TYPE`: the event type name.
    """
    for event in events:
        if event_type.name == REPORT.name:
            if updated_at := event.get("updated_at"):
                _time_field = updated_at
            else:
                _time_field = event["created_at"]
        else:
            _time_field = event.get(event_type.time_field)
        event["_time"] = _time_field
        event["SOURCE_LOG_TYPE"] = event_type.source_log_type
    return events


def dedup_fetched_events(events: List[dict], last_run_fetched_event_ids: Set[str], event_type: EventType) -> List[dict]:
    """
    Deduplicate fetch results by filtering out events that have already been processed.

    Args:
        events (List[dict]): A list of event dictionaries as returned by the API.
        last_run_fetched_event_ids (Set[str]): A set of event IDs that were fetched in the previous run.
        event_type (EventType): The event type we are working one (e.g., REPORT, CREDENTIALS, DOMAIN).

    Returns:
        List[dict]: A list of event after deduplication.
    """
    un_fetched_events = []

    for event in events:
        event_id = event_type.get_id(event)
        if event_id not in last_run_fetched_event_ids:
            demisto.debug(f"event with ID {event_id} has not been fetched.")
            un_fetched_events.append(event)
        else:
            demisto.debug(f"event with ID {event_id} for has been fetched")

    return un_fetched_events


def get_latest_event_time_and_ids(
    events: List[Dict[str, Any]],
    event_type: EventType,
    last_run_time: str,
    last_run_ids: list[str],
) -> tuple[str, List[str]]:
    """
    Determine the latest event timestamp and assemble the corresponding IDs.
    This function assumes that `events` is sorted by `_time` in ascending/descending order depend on the type.

    Args:
        reports     (List[Dict]): A list of event dicts, each containing an `_time` key and the relevant ID field.
        event_type   (EventType): The event type.
        last_run_time      (str): The timestamp string recorded in the previous run.
        last_run_ids (List[str]): The list of IDs recorded in the previous run.

    Returns:
        tuple[str, List[str]]: A tuple where:
            - latest_time: the `_time` string of the most recent event
            - latest_ids: list of event IDs for all events whose `_time` matches that latest timestamp.
    """

    latest_time = events[event_type.max_index]["_time"]

    latest_ids = [event_type.get_id(event) for event in events if event["_time"] == latest_time]

    if latest_time == last_run_time:
        latest_ids.extend(last_run_ids)

    return latest_time, latest_ids


def test_module(client: Client, events_type_to_fetch: list[EventType]) -> str:
    """
    Tests that the authentication to the api is ok.
    """
    start_time = (datetime.now() - timedelta(minutes=30)).strftime(DATE_FORMAT)
    end_time = datetime.now().strftime(DATE_FORMAT)
    event_fetch_function = {
        DOMAIN.name: client.get_domain_watchlist,
        CREDENTIALS.name: client.get_credentials_watchlist,
        REPORT.name: client.get_reports,
    }
    for event_type in events_type_to_fetch:
        event_fetch_function[event_type.name](start_date=start_time, end_date=end_time, limit=1)

    return "ok"


def fetch_events(client: Client, events_type_to_fetch: list[EventType]) -> tuple[List[dict[str, Any]], dict[str, Any]]:
    """
    Fetch and deduplicate events across multiple types from CybelAngel, updating last-run state.

    For each event type, this function:
      1. Retrieves the previous run's timestamp and IDs via `get_last_run()`.
      2. Fetch events for each type using the relevant command.
      3. Removes any events already fetched.
      4. If no new events remain:
         - Sets this type's last-run timestamp to now and clears its ID list.
      5. Otherwise:
         - Truncates to `event_type.max_fetch` events.
         - Determines the latest timestamp and corresponding IDs via `get_latest_event_time_and_ids()`.
         - Updates this type's last-run record.
    All newly fetched events (across all types) are concatenated and returned alongside the updated last-run map.

    Args:
        client                  (Client): CybelAngel API client instance.
        event_types_to_fetch (List[EventType]): List of event-type keys to fetch (REPORT, DOMAIN, CREDENTIALS).

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
        DOMAIN.name: client.get_domain_watchlist,
        CREDENTIALS.name: client.get_credentials_watchlist,
        REPORT.name: client.get_reports,
    }

    for event_type in events_type_to_fetch:
        demisto.debug(f"Fetching {event_type.name}")

        last_time = last_run[event_type.name][LATEST_TIME]
        last_ids = last_run[event_type.name][LATEST_FETCHED_IDS]
        demisto.debug(f"Last run for {event_type.name}: time={last_time}, ids={len(last_ids)}")

        events = event_fetch_function[event_type.name](
            start_date=last_time,
            end_date=now.strftime(DATE_FORMAT),
            limit=event_type.max_fetch + len(last_ids),
        )
        demisto.debug(f"Fetched {len(events)} raw events for {event_type.name}")

        events = dedup_fetched_events(events=events, last_run_fetched_event_ids=set(last_ids), event_type=event_type)
        demisto.debug(f"{len(events)} events remain after dedup for {event_type.name}")

        if events:
            events = events[: event_type.max_fetch] if event_type.ascending_order else events[-event_type.max_fetch :]
            latest_time, latest_ids = get_latest_event_time_and_ids(events, event_type, last_time, last_ids)
            demisto.debug(f"{event_type.name} latest time: {latest_time}, latest IDs: {latest_ids}")

            last_run[event_type.name] = {LATEST_TIME: normalize_date_format(latest_time), LATEST_FETCHED_IDS: latest_ids}
            all_events.extend(events)

        else:
            demisto.debug(f"No new {event_type.name} events; resetting last_run timestamp")
            last_run[event_type.name] = {LATEST_TIME: now.strftime(DATE_FORMAT), LATEST_FETCHED_IDS: []}

    demisto.debug(f"Total events fetched across all types: {len(all_events)}")
    return all_events, last_run


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get events from Cybel Angel, used mainly for debugging purposes
    """
    event_type = EVENT_TYPE.get(args.get("events_type_to_fetch", "")) or REPORT
    limit = int(args.get("limit", 50))

    now = datetime.now()
    end_date = args.get("end_date") or now.strftime(DATE_FORMAT)
    end_dt = dateparser.parse(end_date) or now
    start_date = args.get("start_date") or (end_dt - timedelta(minutes=1)).strftime(DATE_FORMAT)

    events = []

    event_fetch_function = {
        DOMAIN.name: client.get_domain_watchlist,
        CREDENTIALS.name: client.get_credentials_watchlist,
        REPORT.name: client.get_reports,
    }

    events = event_fetch_function[event_type.name](start_date=start_date, end_date=end_date, limit=limit)
    events = events[:limit]
    if argToBoolean(args.get("should_push_events") or False):
        send_events_to_xsiam(vendor=VENDOR, product=PRODUCT, events=events)
        demisto.debug(f"Successfully send {len(events)} to XSIAM.")
    return CommandResults(
        readable_output=tableToMarkdown(event_type.name, events, removeNull=False),
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


def cybelangel_report_comments_get_command(client: Client, args: dict) -> CommandResults:  # pragma: no cover
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


def get_last_run(now: datetime, events_type_to_fetch: list[EventType]) -> dict[str, Any]:
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
                    LATEST_TIME: String date formatted as DATE_FORMAT,
                    LATEST_FETCHED_IDS: List[str]
                },
            }
    """
    last_run = demisto.getLastRun()
    last_time = now - timedelta(minutes=1)
    if not last_run:
        last_run = {}
        demisto.debug("First run")
    for event_type in [REPORT, DOMAIN, CREDENTIALS]:
        if event_type.name not in last_run or (event_type.name in last_run and event_type not in events_type_to_fetch):
            last_run[event_type.name] = {
                LATEST_TIME: last_time.strftime(DATE_FORMAT),
                LATEST_FETCHED_IDS: [],
            }

    return last_run


def normalize_date_format(date_string: str) -> str:
    """
    Normalizes a date string to a consistent UTC format ending with 'Z'.

    This function handles three specific input formats:
    1. 2025-05-18T06:10:37Z (already in a valid format)
    2. 2024-08-14T08:48:51.380211 (missing timezone)
    3. 2020-05-15T12:30:25+00:00 (UTC offset format)

    Args:
        date_string: The input date string.

    Returns:
        The normalized date string ending with 'Z'.
    """
    if date_string.endswith("+00:00"):
        return date_string[:-6] + "Z"

    if date_string.endswith("Z"):
        return date_string

    return date_string + "Z"


def set_event_type_fetch_limit(params: dict[str, Any]) -> list[EventType]:
    """
    Parses the event types to fetch from parameters and returns a dictionary mapping
    each selected event type's suffix to its corresponding max fetch limit.

    Args:
        params (Dict[str, Any]): Integration parameters.

    Returns:
        list[EventType]: List of event type to fetch from the api call.
    """
    event_type_names = [et.strip() for et in argToList(params.get("event_types_to_fetch", [REPORT.name]))]
    demisto.debug(f"List:{event_type_names}, list length:{len(event_type_names)}")
    fetch_limits = {
        REPORT.name: arg_to_number(params.get("max_fetch")) or REPORT.default_max_fetch,
        CREDENTIALS.name: arg_to_number(params.get("max_fetch_creds")) or CREDENTIALS.default_max_fetch,
        DOMAIN.name: arg_to_number(params.get("max_fetch_domain")) or DOMAIN.default_max_fetch,
    }
    event_types = []
    for event_type in EVENT_TYPE.values():
        if event_type.name in event_type_names:
            event_type.max_fetch = fetch_limits[event_type.name]
            event_types.append(event_type)

    return event_types


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    client_id: str = params.get("credentials", {}).get("identifier", "")
    client_secret: str = params.get("credentials", {}).get("password", "")
    base_url: str = params.get("url", "").rstrip("/")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

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
            return_results(test_module(client, set_event_type_fetch_limit(params)))
        elif command == "fetch-events":
            events, last_run = fetch_events(client, set_event_type_fetch_limit(params))
            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f'Successfully sent event {[event.get("id") for event in events]} IDs to XSIAM')
            demisto.setLastRun(last_run)
        elif command == "cybelangel-get-events":
            return_results(get_events_command(client, args))
        elif command in commands:
            return_results(commands[command](client, args))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\ntype:{type(e)}, error:{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
