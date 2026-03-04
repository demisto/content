import copy
import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401
from collections import defaultdict


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

    def get_incident_ids(self, start_time: datetime) -> List[int]:
        """
        Navigate to the correct endpoint
        """
        if self.all_incident:
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

    def get_all_incident_ids(self, start_time: datetime) -> List[int]:
        """
        Summary:
            Pull all the incident IDs from the API, using pagination mechanizm with respect to max_fetch
        Args:
            start_time: from what time to start pulling
        Returns:
            List of incident IDs
        """
        curr_time = datetime.now(timezone.utc)  # Get the current datetime with UTC timezone
        # Convert to ISO format as it is the API format
        curr_time = curr_time.isoformat()
        start = start_time.isoformat()

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
        while page <= total_pages:
            params["page"] = page  # type: ignore
            response = self._http_request(method="GET", url_suffix=f"/incident/{self.company_id}/list/", params=params, retries=4)
            total_pages = response.get("total_pages")
            new_incidents = response.get("incidents", [])
            page += 1
            incidents.extend(new_incidents)
        # Sort the incidents by time
        incidents_sorted_by_time = sorted(
            incidents, key=lambda incident: datetime.strptime(incident.get("created"), "%Y-%m-%dT%H:%M:%S.%fZ")
        )
        incidents_ids_sorted_by_time = [incident.get("incidentID") for incident in incidents_sorted_by_time]
        return incidents_ids_sorted_by_time

    def get_mailbox_mitigation_details(self, incident_ids: list, page_number: int) -> dict:
        """
        Gets a single page of mailbox mitigations (including the affected mailboxes) for specific incidents.

        Args:
            incident_ids (list): List of incident IDs.
            page_number (int): Page number starting from 1.

        Returns:
            dict: The raw API response containing the "mitigations" array and pagination details.
        """
        # https://appapi.ironscales.com/appapi/docs/#tag/Mitigation/operation/Get%20details%20of%20mitigations%20per%20mailbox
        return self._http_request(
            method="POST",
            url_suffix=f"/mitigation/{self.company_id}/details/",
            json_data={"incidents": incident_ids, "page": page_number},
        )


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
) -> List[int]:
    incident_ids: List[int] = client.get_incident_ids(first_fetch)
    if not incident_ids:
        return []
    if client.all_incident:
        # if we pulled all incidents we already pulled by timestamp
        return incident_ids
    if isinstance(last_id, int):
        # We filter out only events with ID greater than the last_id
        return list(filter(lambda i: i > last_id, incident_ids))
    return get_incident_ids_by_time(
        client,
        incident_ids,
        start_time=first_fetch,
    )


def enrich_events_with_mailbox_details(client: Client, events: list[dict[str, Any]]) -> None:
    """Adds mailbox mitigation details per event.

    Args:
        client (Client): The instance of IronScales API client.
        events (list[dict]): List of new formatted events (based on raw incidents).
    """
    if not events:
        demisto.debug("No events found. Skipping mailbox enrichment.")
        return

    incident_ids = list({event.get("incident_id") for event in events})
    demisto.debug(f"Starting mailbox enrichment on {len(incident_ids)} incident IDs: {incident_ids}.")

    per_incident_mitigations = defaultdict(list)  # To group mailbox mitigations per incidentID
    current_page = 1
    total_pages = 1  # Ensure loop runs at least once

    while current_page <= total_pages:
        demisto.debug(f"Getting mailbox mitigation details using {current_page=}.")
        response = client.get_mailbox_mitigation_details(incident_ids, page_number=current_page)
        mitigations = response.get("mitigations", [])
        demisto.debug(f"Got {len(mitigations)} mailbox mitigation details using {current_page=}.")

        # Group mitigations from the current page
        for mitigation in mitigations:
            incident_id = mitigation.pop("incidentID")
            per_incident_mitigations[incident_id].append(snakify(mitigation))

        total_pages = response.get("total_pages", 0)
        current_page += 1

    demisto.debug(f"Mapping grouped mailbox mitigations to {len(events)} events.")
    for event in events:
        incident_id = event.get("incident_id")
        event["mitigations"] = per_incident_mitigations.get(incident_id, [])
    demisto.debug(f"Finished running mailbox enrichment on {len(incident_ids)} incident IDs: {incident_ids}.")


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
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    since_time = arg_to_datetime(args.get("since_time") or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
    mailbox_enrichment: bool = argToBoolean(args.get("mailbox_enrichment", False))
    assert isinstance(since_time, datetime)
    events, _, _ = fetch_events_command(client, since_time, limit, mailbox_enrichment=mailbox_enrichment)
    message = "All Incidents" if client.all_incident else "Open Incidents"
    result = CommandResults(
        readable_output=tableToMarkdown(message, events),
        raw_response=events,
    )
    return result, events


def get_new_last_id(last_timestamp, incident, new_last_ids):
    """
        check if the id came after or in the same time as the previous incident, and update the ids array and the timestamp
    Args:
        last_timestamp: the old last timestamp
        incident: the incident to check
        new_last_ids: array of the ids with the same timestamp as last_timestamp
    Returns:
        the new last timestamp and the array of ids
    """
    incident_time = arg_to_datetime(incident.get("first_reported_date"))
    inc_id = incident.get("incident_id")
    # Make sure that time format is comparable
    incident_time = incident_time.isoformat()  # type: ignore
    incident_time = arg_to_datetime(incident_time)
    last_timestamp = last_timestamp.isoformat()
    last_timestamp = arg_to_datetime(last_timestamp)
    # compare the datetime
    if last_timestamp is None or incident_time > last_timestamp:  # type: ignore
        new_last_ids = {inc_id}
        last_timestamp = incident_time
    else:
        new_last_ids.add(inc_id)
    return last_timestamp, new_last_ids


def all_incidents_trimmer(
    incident_ids: List[int],
    client: Client,
    max_fetch: int,
    last_timestamp_ids: List[int],
    last_timestamp: datetime,
):
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
    new_last_ids: set[int] = set(last_timestamp_ids)  # The new ids to save for the next run
    last_timestamp_ids = set(last_timestamp_ids)  # For better runtime
    for i in incident_ids:
        # Remove ids that already pulled
        if last_timestamp_ids and i in last_timestamp_ids:
            continue
        try:
            incident = client.get_incident(i)  # get incident details
            events.extend(incident_to_events(incident))  # incident_to_events returns a list of events
        except Exception as e:
            demisto.debug(f"Error in getting incident id {i} details, error: {e}")
            # Note: The IronScales endpoint does not support retrieving details for events of type ATO and MTS.
            continue

        # we use the original incident
        last_timestamp, new_last_ids = get_new_last_id(last_timestamp, incident, new_last_ids)
        # We are sending incident, not the one with "_time" field
        if len(events) >= max_fetch:
            break
    new_last_ids: list[int] = list(new_last_ids)
    return events, new_last_ids


def open_incidents_trimmer(incident_ids, client, max_fetch, last_id):
    """
    Only open incidents case, will loop over the incidents and add the only those we didn't see yet.

    Args:
        incident_ids (_type_): the new ids that we pulled
        client (_type_): client
        max_fetch (_type_): max fetch
        last_id : the last id from the last run

    Returns:
        the processed ids and the new last id
    """
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
    last_timestamp_ids: List[int] = [],
    mailbox_enrichment: bool = False,
) -> tuple[List[dict[str, Any]], int, list[Any] | None]:
    """Fetches IRONSCALES incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.

    Args:
        client (Client): The client object.
        first_fetch (datetime): First fetch time.
        max_fetch (int): Maximum number of events to fetch.
        last_id (Optional[int]): The ID of the most recent incident ingested in previous runs. Defaults to None.
        mailbox_enrichment (bool): Whether to fetch the affected mailboxes per incident. Defaults to False.

    Returns:
        Tuple[List[Dict[str, Any]], int]:
            - A list of new events.
            - ID of the most recent incident ingested in the current run.
    """
    incident_ids: List[int] = get_incident_ids_to_fetch(client=client, first_fetch=first_fetch, last_id=last_id)
    last_id = last_id or -1
    if client.all_incident:
        events, last_timestamp_ids = all_incidents_trimmer(
            incident_ids,
            client,
            max_fetch,
            last_timestamp_ids,
            first_fetch,
        )
    else:
        events, last_id, last_timestamp_ids = open_incidents_trimmer(incident_ids, client, max_fetch, last_id)

    if mailbox_enrichment:
        demisto.debug(f"Fetch Mailbox is enabled. Running mailbox enrichment on {len(events)} events.")
        enrich_events_with_mailbox_details(client=client, events=events)
    else:
        demisto.debug("Fetch Mailbox is disabled. Skipping mailbox enrichment.")

    return events, last_id, last_timestamp_ids


def test_module_command(client: Client, first_fetch: datetime) -> str:
    fetch_events_command(client, first_fetch, max_fetch=1)
    return "ok"


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    try:
        first_fetch = arg_to_datetime(params.get("first_fetch") or DEFAULT_FIRST_FETCH, settings=DATEPARSER_SETTINGS)
        assert isinstance(first_fetch, datetime)
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

        client = Client(
            company_id=params.get("company_id"),
            base_url=urljoin(params["url"], "/appapi"),
            verify_certificate=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            api_key=params.get("apikey", {}).get("password"),
            scopes=argToList(params.get("scopes")),
            all_incident=params.get("collect_all_events"),
        )
        demisto.debug(f'Client created. all_incident = {params.get("collect_all_events")}')
        if command == "test-module":
            return_results(test_module_command(client, first_fetch))

        elif command == "ironscales-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            if last_run.get("last_incident_time"):
                first_fetch = arg_to_datetime(last_run.get("last_incident_time")) or first_fetch
            events, last_id, last_timestamp_ids = fetch_events_command(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                last_id=last_run.get("last_id"),
                last_timestamp_ids=last_run.get("last_timestamp_ids", []),
                mailbox_enrichment=params.get("mailbox_enrichment", False),
            )

            send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            demisto.setLastRun(
                {
                    "last_id": last_id,
                    "last_incident_time": events[-1].get("_time") if events else first_fetch,
                    "last_timestamp_ids": last_timestamp_ids,
                }
            )

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {e!s}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
