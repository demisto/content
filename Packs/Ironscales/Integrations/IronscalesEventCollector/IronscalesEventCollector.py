
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import dateparser
import urllib3
from typing import Dict, Tuple

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "ironscales"
PRODUCT = "ironscales"


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
        headers = self.get_jwt_token(api_key, scopes)
        super().__init__(base_url, verify_certificate, proxy, headers=headers)

    def get_jwt_token(self, api_key: str, scopes: list) -> Dict[str, Any]:
        try:
            jwt_key = self._http_request(
                method="POST",
                url_suffix="/get-token/",
                json_data={"key": api_key, "scopes": scopes},
            )
        except DemistoException as e:
            if "FORBIDDEN" in str(e):
                raise DemistoException(
                    "Authorization Error: make sure API Key is correctly set"
                )
            raise e

        return {"Authorization": f'JWT {jwt_key["jwt"]}'}

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

    def get_open_incidents(self) -> Dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/incident/{self.company_id}/open/",
        )


""" HELPER FUNCTIONS """


def get_incident_ids_by_time(
    client: Client,
    incident_ids: List[int],
    start_time: datetime,
    start_idx: int,
    end_idx: int,
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


def get_incident_ids(
    client: Client,
    last_id: Optional[int],
    first_fetch: datetime,
) -> List[int]:
    incident_ids = client.get_open_incidents().get("incident_ids") or []
    if not incident_ids:
        return []
    if last_id:
        return list(filter(lambda i: i > last_id, incident_ids))
    return get_incident_ids_by_time(
        client,
        incident_ids,
        start_time=first_fetch,
        start_idx=0,
        end_idx=len(incident_ids) - 1,
    )


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client,
    args: Dict[str, Any]
) -> Tuple[CommandResults, List[Dict[str, Any]]]:
    events: List[Dict[str, Any]] = []

    incident_ids = client.get_open_incidents().get("incident_ids") or []
    for idx, incident_id in enumerate(incident_ids):
        if idx == args.get('limit'):
            break
        events.append(client.get_incident(incident_id))

    result = CommandResults(
        readable_output=tableToMarkdown("Open Incidents", events),
        raw_response=events,
    )
    return result, events


def fetch_events_command(
    client: Client,
    last_run: Dict[str, Any],
    first_fetch: datetime,
    max_fetch: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    incident_ids = get_incident_ids(
        client=client,
        last_id=last_run.get("last_id"),
        first_fetch=first_fetch,
    )

    for idx, incident_id in enumerate(incident_ids):
        if idx == max_fetch:
            break
        events.append(client.get_incident(incident_id))
        last_run["last_id"] = incident_id

    if "last_id" not in last_run:
        last_run["last_id"] = -1

    return events, last_run


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")

    try:
        first_fetch = dateparser.parse(params.get("first_fetch", ""))
        assert first_fetch, "Invalid first_fetch parameter"
        max_fetch = arg_to_number(params.get("max_fetch"))
        assert max_fetch, "Invalid max_fetch parameter"

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
            events, last_run = fetch_events_command(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                max_fetch=max_fetch,
            )
            demisto.setLastRun(last_run)
            send_events_to_xsiam(events, VENDOR, PRODUCT)

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
