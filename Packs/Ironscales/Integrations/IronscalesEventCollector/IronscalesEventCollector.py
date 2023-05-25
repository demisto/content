
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import copy
import dateparser
import urllib3
from typing import Dict, Tuple

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "ironscales"
PRODUCT = "ironscales"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_MAX_FETCH = 1000
DEFAULT_LIMIT = 10


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
    ) -> None:
        self.company_id = company_id
        super().__init__(base_url, verify_certificate, proxy)
        self._headers = {"Authorization": f'JWT {self.get_jwt_token(api_key, scopes)}'}

    def get_jwt_token(self, api_key: str, scopes: list) -> Dict[str, Any]:
        try:
            jwt_key = self._http_request(
                method="POST",
                url_suffix="/get-token/",
                json_data={"key": api_key, "scopes": scopes},
            )
            return jwt_key["jwt"]
        except DemistoException as e:
            if "FORBIDDEN" in str(e):
                raise DemistoException(
                    "Authorization Error: make sure API Key is correctly set"
                )
            raise e

    def get_incident(self, incident_id: int) -> Dict[str, Any]:
        """Gets a specific Incident

        :type incident_id: ``str``
        :param incident_id: id of the incident to return

        :return: dict containing the incident as returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method="GET",
            url_suffix=f"/incident/{self.company_id}/details/{incident_id}",
            json_data={
                "company_id": self.company_id,
                "incident_id": incident_id,
            },
        )

    def get_open_incident_ids(self) -> List[int]:
        return self._http_request(
            method="GET",
            url_suffix=f"/incident/{self.company_id}/open/",
        ).get("incident_ids") or []


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
    incident_time = dateparser.parse(incident.get("first_reported_date", ""))
    assert incident_time, "Missing field `first_reported_date` in incident data"

    if incident_time > start_time:
        if current_idx == start_idx:
            return incident_ids[start_idx:]
        return get_incident_ids_by_time(
            client,
            incident_ids,
            start_time,
            start_idx,
            current_idx - 1,
        )
    if incident_time < start_time:
        if current_idx == start_idx:
            return incident_ids[end_idx:]
        return get_incident_ids_by_time(
            client,
            incident_ids,
            start_time,
            current_idx + 1,
            end_idx,
        )
    return incident_ids[current_idx:]


def get_open_incident_ids(
    client: Client,
    first_fetch: datetime,
) -> List[int]:
    all_open_incident_ids: List[int] = client.get_open_incident_ids()
    if not all_open_incident_ids:
        return []
    return get_incident_ids_by_time(
        client,
        all_open_incident_ids,
        start_time=first_fetch,
    )


def incident_to_events(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Creates an event for each report in the current incident.
        Returns the list of events.
    """
    def report_to_event(report_data: Dict[str, Any]) -> Dict[str, Any]:
        """Transforms a single report data of the incident to an event.
        """
        event = copy.deepcopy(incident)
        event["_time"] = event["first_reported_date"]
        del event["reports"]
        return event | report_data

    return argToList(incident.get("reports", []), transform=report_to_event)


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client,
    args: Dict[str, Any]
) -> Tuple[CommandResults, List[Dict[str, Any]]]:
    events: List[Dict[str, Any]] = []

    for incident_id in client.get_open_incident_ids():
        if len(events) >= args.get('limit', DEFAULT_LIMIT):
            break
        inc = client.get_incident(incident_id)
        events.extend(incident_to_events(inc))

    result = CommandResults(
        readable_output=tableToMarkdown("Open Incidents", events),
        raw_response=events,
    )
    return result, events


def fetch_events_command(
    client: Client,
    first_fetch: datetime,
    max_fetch: int,
    last_id: Optional[int] = None,
    fetch_ids: Optional[List[int]] = None,

) -> Tuple[List[Dict[str, Any]], int]:
    events: List[Dict[str, Any]] = []
    incident_ids: List[int] = fetch_ids if fetch_ids else get_open_incident_ids(
        client=client,
        first_fetch=first_fetch,
    )

    if last_id:
        incident_ids = [i for i in incident_ids if i > last_id]

    for incident_id in incident_ids:
        if len(events) == max_fetch:
            break
        inc = client.get_incident(incident_id)
        events.extend(incident_to_events(inc))
        last_id = incident_id

    return events, last_id or 0


def main():
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    try:
        first_fetch = dateparser.parse(params.get("first_fetch") or DEFAULT_FIRST_FETCH)
        assert isinstance(first_fetch, datetime), f"Invalid first_fetch value: {params.get('first_fetch')}"
        max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
        fetch_ids = argToList(params.get("fetch_ids"), transform=int)

        client = Client(
            company_id=params.get("company_id"),
            base_url=urljoin(params["url"], "/appapi"),
            verify_certificate=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            api_key=params.get("apikey", {}).get("password"),
            scopes=argToList(params.get("scopes")),
        )
        if command == "test-module":
            # parameters or client connectivity issues will be raised by now
            return_results("ok")

        elif command == "ironscales-get-events":
            results, events = get_events_command(client, args)
            return_results(results)
            if argToBoolean(args.get("should_fetch_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)

        elif command == "fetch-events":
            events, last_id = fetch_events_command(
                client=client,
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                last_id=demisto.getLastRun().get("last_id") or 0,
                fetch_ids=fetch_ids,
            )
            demisto.setLastRun({"last_id": last_id})
            send_events_to_xsiam(events, VENDOR, PRODUCT)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
