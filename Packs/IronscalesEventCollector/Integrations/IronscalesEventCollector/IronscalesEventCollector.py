import copy

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401


# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "ironscales"
PRODUCT = "ironscales"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 1000
DEFAULT_LIMIT = 10
DATEPARSER_SETTINGS = {
    "RETURN_AS_TIMEZONE_AWARE": True,
    "TIMEZONE": "UTC",
}


""" CLIENT CLASS """


class Client(BaseClient):  # pragma: no cover
    def __init__(
        self,
        company_id: str,
        base_url: str,
        verify_certificate: bool,
        proxy: bool,
        api_key: str,
        scopes: List[str],
        all_incident: bool,
    ) -> None:
        self.company_id = company_id
        super().__init__(base_url, verify_certificate, proxy)
        self.all_incident = all_incident
        self._headers = {"Authorization": f"JWT {self.get_jwt_token(api_key, scopes)}"}

    def client_error_handler(self, res) -> Any:
        try:
            err_msg = f"Error in API call [{res.status_code}] - {res.json().get('message')}"
            raise DemistoException(err_msg, res=res)
        except ValueError:
            super().client_error_handler(res)

    def get_jwt_token(self, api_key: str, scopes: list) -> dict[str, Any]:
        try:
            jwt_key = self._http_request(
                method="POST",
                url_suffix="/get-token/",
                json_data={"key": api_key, "scopes": scopes},
            )
            return jwt_key["jwt"]
        except DemistoException as e:
            if "No company found for API key" in str(e):
                raise DemistoException("Authorization Error: make sure the API Key is set correctly")
            raise e

    def get_incident(self, incident_id: int) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/incident/{self.company_id}/details/{incident_id}",
        )

    def get_incident_ids(self, start_time: datetime, max_fetch: int, last_id: Optional[int]) -> List[int]:
        """
        Navigate to the correct endpoint
        """

        demisto.debug("Test-IronScales: going in get_incident_ids")
        if self.all_incident:
            demisto.debug("Test-IronScales: all_incidents is marked as True. going in get_all_incident_ids")
            return self.get_all_incident_ids(start_time)
        return self.get_open_incident_ids()

    def get_open_incident_ids(self) -> List[int]:
        return (
            self._http_request(
                method="GET",
                url_suffix=f"/incident/{self.company_id}/open/",
            ).get("incident_ids")
            or []
        )

    def convert_time_iso_format(self, time):
        demisto.debug("Test-IronScales: Going in convert_time_iso_format")
        time = time.isoformat()  # convert to iso format
        demisto.debug("Test-IronScales: time format to ISO success")
        return time

    ######## Debugging Area ########

    def debug_function(self, response):
        total_pages = response.get("total_pages")
        if response.get("error_message"):
            demisto.debug(
                f'Test-IronScales: HTTP request failed with exit code 400, error message:\
                    {response.get("error_message")}'
            )
        elif response.get("page"):
            demisto.debug(f'Test-IronScales: HTTP request success with exit code 200. important info:\n\
                page num = {str(response.get("page"))},\n\
                total pages = {str(total_pages)},\n\
                num of incidents = {str(len(response.get("incidents",[])))}')
        else:
            demisto.debug("Test-IronScales: HTTP request went wrong and went wrong with no exit code")

    ######## End Debugging Area ########

    def get_all_incident_ids(self, start_time: datetime) -> List[int]:
        """
        Summary:
            Pull all the incident IDs from the API, using pagination mechanizm with respect to max_fetch
        Args:
            start_time: from what time to start pulling
            max_fetch: max number of incidents to fetch
            last_id: last id from the last run
        Returns:
            List of incident IDs
        """
        demisto.debug("Test-IronScales: going in get_all_incident_ids")
        try:
            demisto.debug("Test-IronScales: going in get_all_incident_ids")
            curr_time = datetime.now(timezone.utc)  # Get the current datetime with UTC timezone
            demisto.debug(f"Test-IronScales: curr_time is {str(curr_time)}")
            curr_time = self.convert_time_iso_format(curr_time)
            demisto.debug("Test-IronScales: curr time converted successfully. converting start time...")
            start = self.convert_time_iso_format(start_time)
            demisto.debug("Test-IronScales: start time converted successfully. Prepare for pulling")

            page = 1
            total_pages = 1
            params = {
                "reportType": "all",
                "state": "all",
                "created_start_time": start,
                "created_end_time": curr_time,
                "order": "asc",
            }
            incidents: List = []
            # handle paging
            demisto.debug("Test-IronScales: pulling loop start")
            while page <= total_pages:
                demisto.debug(f"Test-IronScales: page num is {str(page)}, starting loop")
                params["page"] = page
                demisto.debug(f"Test-IronScales: sending http request with params: {str(params)}")
                response = self._http_request(
                    method="GET", url_suffix=f"/incident/{self.company_id}/list/", params=params, retries=4, backoff_factor=5
                )
                total_pages = response.get("total_pages")
                ######## Debugging Area ########
                self.debug_function(response)
                ################################
                new_incidents = response.get("incidents", [])
                demisto.debug(f"Test-IronScales: new incidents for page num {str(page)}, incidents ids: \
                              {str([incident.get('incidentID') for incident in response.get('incidents', [])])}")
                page += 1
                if new_incidents:
                    demisto.debug(
                        f"Test-IronScales: first and last incidents ids for page num {str(page-1)}:\
                        {str(new_incidents[0].get('incidentID'))}, {str(new_incidents[-1].get('incidentID'))}"
                    )
                incidents.extend(new_incidents)
            demisto.debug(f"Test-IronScales: loop ended. fetched {str(len(incidents))} new ids")
            incidents_sorted_by_time = sorted(
                incidents,
                key=lambda incident: datetime.strptime(incident.get("created", "2019-08-24T14:15:22Z"), "%Y-%m-%dT%H:%M:%SZ"),
            )
            incidents_ids_sorted_by_time = [incident.get("incidentID") for incident in incidents_sorted_by_time]
            return incidents_ids_sorted_by_time
        except Exception as e:
            demisto.debug(f"Test-IronScales: Exception message:{e}")
            raise Exception("An error occured in get_all_incident_ids. check logs to see why")


""" HELPER FUNCTIONS """


def get_incident_ids_by_time(
    client: Client,
    incident_ids: List[int],
    start_time: datetime,
    start_idx: int = 0,
    end_idx: Optional[int] = None,
) -> List[int]:
    """Uses binary search to determine the incident ID to start fetching from.
    This method will be called only in the first fetch.

    Args:
        client (Client): The client object
        incident_ids (List[int]): List of all incident IDs
        start_time (datetime): Time to start the fetch from
        start_idx (int): Start index for the binary search
        end_idx (int): End index for the binary search

    Returns:
        List[int]: The list of all incident IDs to fetch.
    """
    demisto.debug("Test-IronScales: going in get_incident_ids_by_time. (note - recursive function)")
    if end_idx is None:
        end_idx = len(incident_ids) - 1

    current_idx = (start_idx + end_idx) // 2

    incident = client.get_incident(incident_ids[current_idx])
    incident_time = arg_to_datetime(incident.get("first_reported_date", ""), settings=DATEPARSER_SETTINGS)
    assert isinstance(incident_time, datetime)

    if incident_time > start_time:
        if current_idx == start_idx:
            return incident_ids[start_idx:]
        return get_incident_ids_by_time(
            client,
            incident_ids,
            start_time,
            start_idx=start_idx,
            end_idx=current_idx - 1,
        )
    if incident_time < start_time:
        if current_idx == start_idx:
            return incident_ids[end_idx:]
        return get_incident_ids_by_time(
            client,
            incident_ids,
            start_time,
            start_idx=current_idx + 1,
            end_idx=end_idx,
        )
    return incident_ids[current_idx:]


def get_incident_ids_to_fetch(
    client: Client,
    first_fetch: datetime,
    last_id: Optional[int],
    max_fetch,
) -> List[int]:
    demisto.debug(f"Test-IronScales: going in get_incident_ids_to_fetch with param: first_fetch = {str(first_fetch)},\
                  last_id = {str(last_id)},\
                  max_fetch = max_fetch")
    incident_ids: List[int] = client.get_incident_ids(first_fetch, max_fetch, last_id)
    if not incident_ids:
        demisto.debug("Test-IronScales: no new incident! returning empty list")
        return []
    if client.all_incident:
        # if we pulled all incidents we already pulled by timestamp
        return incident_ids
    if isinstance(last_id, int):
        # We filter out only events with ID greater than the last_id
        return list(filter(lambda i: i > last_id, incident_ids))  # type: ignore
    return get_incident_ids_by_time(
        client,
        incident_ids,
        start_time=first_fetch,
    )


def incident_to_events(incident: dict[str, Any]) -> List[dict[str, Any]]:
    """Creates an event for each report in the current incident.
    Returns the list of events.
    """

    def report_to_event(report_data: dict[str, Any]) -> dict[str, Any]:
        """Transforms a single report data of the incident to an event."""
        event = copy.deepcopy(incident)
        event["_time"] = event["first_reported_date"]
        del event["reports"]
        return event | report_data

    return [report_to_event(event) for event in incident.get("reports", [])]


""" COMMAND FUNCTIONS """


def get_events_command(client: Client, args: dict[str, Any]) -> tuple[CommandResults, List[dict[str, Any]]]:
    demisto.debug("Test-IronScales: going in get_events")
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    since_time = arg_to_datetime(args.get("since_time") or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
    assert isinstance(since_time, datetime)
    events, _, _ = fetch_events_command(client, since_time, limit)
    message = "All Incidents" if client.all_incident else "Open Incidents"
    result = CommandResults(
        readable_output=tableToMarkdown(message, events),
        raw_response=events,
    )
    return result, events


def get_new_last_id(last_timestamp, incident, new_last_ids):
    incident_time = arg_to_datetime(incident.get("_time"))
    if not new_last_ids:  # first fetch case
        new_last_ids.append(incident.get("incident_id"))
        last_timestamp = incident_time
    else:
        if incident_time > last_timestamp:  # new timestamp - new last_ids list
            new_last_ids = [incident.get("incident_id")]
            last_timestamp = incident_time
        elif incident_time == last_timestamp:
            new_last_ids.append(incident.get("incident_id"))
    return last_timestamp, new_last_ids


def all_incidents_trimmer(incident_ids, client, max_fetch, last_timestamp_ids, last_timestamp, last_id):
    """
    In all_incidents case, we will save a list of the ids that share the same timestamp as the last id.
    That way we will not return duplicates in each run.

    Args:
        incident_ids (_type_): the new ids that we pulled
        client (_type_): client
        max_fetch (_type_): max fetch
        last_timestamp_ids (_type_): Ids that we already seen
        last_timestamp (_type_): the last timestamp that we pulled
    """
    events: List[dict[str, Any]] = []
    new_last_ids: list[int] = []  # the new ids to save for the next run
    if last_timestamp_ids:
        last_timestamp_ids = set(last_timestamp_ids)  # for better runtime
    for i in incident_ids:
        # remove ids that already pulled
        if last_timestamp_ids and i in last_timestamp_ids:
            continue
        try:
            incident = client.get_incident(i)  # get incident details
            events.extend(incident_to_events(incident))
        except Exception:
            demisto.debug(f"Test-IronScales: Error in getting incident id {i} details")
            # todo - need to print message to the customer
            continue
        last_timestamp, new_last_ids = get_new_last_id(last_timestamp, incident, new_last_ids)
        if len(events) >= max_fetch:
            break
    return events, new_last_ids[-1] if new_last_ids else last_id, new_last_ids


def open_incidents_trimmer(incident_ids, client, max_fetch, last_id):
    events: List[dict[str, Any]] = []
    for i in incident_ids:
        incident = client.get_incident(i)
        events.extend(incident_to_events(incident))
        last_id = max(i, last_id)
        if len(events) >= max_fetch:
            break
    return events, last_id, []


def fetch_events_command(
    client: Client,
    first_fetch: datetime,
    max_fetch: int,
    last_id: Optional[int] = None,
    last_timestamp_ids: Optional[List] = None,
) -> tuple[List[dict[str, Any]], int, list[Any] | None]:
    """Fetches IRONSCALES incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.

    Args:
        client (Client): The client object.
        first_fetch (datetime): First fetch time.
        max_fetch (int): Maximum number of events to fetch.
        last_id (Optional[int]): The ID of the most recent incident ingested in previous runs. Defaults to None.

    Returns:
        Tuple[List[Dict[str, Any]], int]:
            - A list of new events.
            - ID of the most recent incident ingested in the current run.
    """
    demisto.debug("Test-IronScales: going in fetch_events")
    incident_ids: List[int] = get_incident_ids_to_fetch(
        client=client, first_fetch=first_fetch, last_id=last_id, max_fetch=max_fetch
    )
    demisto.debug(f"Test-IronScales: returned from get_incident_ids_to_fetch with {str(len(incident_ids))} new incidents")
    last_id = last_id or -1
    if client.all_incident:
        events, last_id, last_timestamp_ids = all_incidents_trimmer(
            incident_ids, client, max_fetch, last_timestamp_ids, first_fetch, last_id
        )  # type: ignore
    else:
        events, last_id, last_timestamp_ids = open_incidents_trimmer(incident_ids, client, max_fetch, last_id)

    return events, last_id, last_timestamp_ids


def test_module_command(client: Client, first_fetch: datetime) -> str:
    fetch_events_command(client, first_fetch, max_fetch=1)
    return "ok"


def get_incidents_with_the_same_timestamps(incidents):
    """
    this function store all the incidents with the same timestamp as the last incident,
    so we will be able to filter the incidents that we already seen in the next run.
    """
    if not incidents:
        return None
    last_incident = incidents[-1]
    incidents_with_same_time = []
    for incident in incidents[::-1]:
        if incident.get("_time") == last_incident.get("_time"):
            incidents_with_same_time.append(incident.get("incident_id"))
    return incidents_with_same_time


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    try:
        first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
        assert isinstance(first_fetch, datetime)
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
        demisto.debug(f"Test-IronScales: Running start - max_fetch={str(max_fetch)}, first_fetch = {str(first_fetch)}")

        client = Client(
            company_id=params.get("company_id"),
            base_url=urljoin(params["url"], "/appapi"),
            verify_certificate=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            api_key=params.get("apikey", {}).get("password"),
            scopes=argToList(params.get("scopes")),
            all_incident=params.get("collect_all_incidents"),
        )
        demisto.debug(f'Test-IronScales: Client created. all_incident = {params.get("collect_all_incidents")}')
        if command == "test-module":
            return_results(test_module_command(client, first_fetch))

        elif command == "ironscales-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)

        elif command == "fetch-events":
            if demisto.getLastRun().get("last_incident_time"):
                demisto.debug("Test-IronScales: last_run buffer is not empty. using other first_fetch time.")
                first_fetch = arg_to_datetime(demisto.getLastRun().get("last_incident_time")) or first_fetch
                demisto.debug(f'Test-IronScales: new time = {demisto.getLastRun().get("last_incident_time")}')
            events, last_id, last_timestamp_ids = fetch_events_command(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                last_id=demisto.getLastRun().get("last_id"),
                last_timestamp_ids=demisto.getLastRun().get("last_timestamp_ids"),
            )
            demisto.debug("Test-IronScales: returned from fetch_event")
            demisto.debug(
                f"Test-IronScales: returned data = events:\
                    {str([event.get('incident_id') for event in events])},\
                        last event: {str(last_id)}, num of events: {len(events)},\
                        set last run to: 'last_id': {last_id},\
                            'last_incident_time': {events[-1].get('first_reported_date')if events else None},\
                                'last_timestamp_ids': {last_timestamp_ids}"
            )

            send_events_to_xsiam(events, VENDOR, PRODUCT)

            demisto.setLastRun(
                {
                    "last_id": last_id,
                    "last_incident_time": events[-1].get("first_reported_date") if events else None,
                    "last_timestamp_ids": last_timestamp_ids,
                }
            )

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
