import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "gitguardian"
PRODUCT = "enterprise"
DEFAULT_PAGE_SIZE = 1000
EVENT_TYPE_TO_TIME_MAPPING = {
    "audit_log": "gg_created_at",
    "incident": "last_occurrence_date",
}
EVENT_TYPE_TO_ENDPOINT = {
    "audit_log": "/audit_logs",
    "incident": "/secrets",
}

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def search_events(
        self, last_run: dict[str, Any], max_events_per_fetch: int, get_events: bool = False
    ) -> tuple[List[Dict], List[Dict], List[int], List[int], str]:  # noqa: E501
        """
        Searches for GitGuardian alerts using the '/secrets' and '/audit_logs' API endpoints.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
            max_events_per_fetch (int): number of events per fetch

        Returns:zxx
            List: A list of events that were fetched
            str: The time to start the next incident fetch.
        """
        incidents, last_fetched_incident_ids = self.retrieve_events(
            last_run.get("from_fetch_time", ""), last_run.get("to_fetch_time", ""), max_events_per_fetch, last_run.get(
                "last_fetched_incident_ids", []), 'incident', get_events
        )
        audit_logs, last_fetched_audit_log_ids = self.retrieve_events(
            last_run.get("from_fetch_time", ""), last_run.get("to_fetch_time", ""), max_events_per_fetch, last_run.get(
                "last_fetched_audit_log_ids", []), 'audit_log', get_events
        )

        next_run_from_fetch_time = last_run.get("to_fetch_time", "")

        return incidents, audit_logs, last_fetched_incident_ids, last_fetched_audit_log_ids, next_run_from_fetch_time

    def retrieve_events(
        self, from_fetch_time: str, to_fetch_time: str, max_events_per_fetch: int, prev_run_fetched_event_ids: List[int], event_type: str, get_events: bool = False
    ) -> tuple[List[Dict], List[int]]:
        """Searching the API for new incidents.

        Args:
            from_fetch_time (str): The time we starting to fetch events.
            max_events_per_fetch (int): Max number of events to fetch.

        Returns:
            List: A list of events that were fetched
            str: The time to start the next incident fetch.
        """
        next_url = ""
        events = []
        fetched_event_ids = []
        all_fetched_events = []
        num_of_fetched_events = 0
        params = {"from": from_fetch_time, "per_page": DEFAULT_PAGE_SIZE, "to": to_fetch_time}

        while True:
            if next_url:
                demisto.debug(f"GG: Fetching events using the next_url: {next_url}")
                response = self._http_request(
                    method="GET",
                    full_url=next_url,
                )
            else:
                demisto.debug(f"GG: Fetching events using the params: {params}")
                response = self._http_request(
                    method="GET",
                    url_suffix=EVENT_TYPE_TO_ENDPOINT.get(event_type, ''),
                    params=params,
                )
            all_fetched_events.extend(response.get("results"))
            new_events = self.remove_duplicated_events(response.get("results"), prev_run_fetched_event_ids)
            events.extend(new_events)
            num_of_fetched_events += len(new_events)
            next_url = response.get("next")

            if num_of_fetched_events >= max_events_per_fetch or not next_url:
                # Fetched the max number of events or no more events, sending them to xsiam
                events, last_fetched_incidents_ids = self.handle_events(events,
                                                                        max_events_per_fetch,
                                                                        event_type,
                                                                        to_fetch_time,
                                                                        get_events)
                fetched_event_ids.extend(last_fetched_incidents_ids)
                num_of_fetched_events = len(events)

            if get_events and len(all_fetched_events) >= max_events_per_fetch:
                break
            if not next_url:
                break

        next_run_events_from_fetch = to_fetch_time
        if response.get("count") == 0:
            demisto.debug(f"GG: No events were fetched, next_run_event_from_time is {next_run_events_from_fetch}")
        else:
            demisto.debug(
                f"GG: Events were fetched, next_run_event_from_time is {next_run_events_from_fetch}"
            )

        return all_fetched_events, fetched_event_ids

    def handle_events(self, events_to_send: list, max_events_per_fetch: int, event_type: str, to_fetch_time: str, get_events: bool = False) -> tuple[List[Dict], List[int]]:
        events_to_send_to_xsiam, events_to_keep = events_to_send[:max_events_per_fetch], events_to_send[max_events_per_fetch:]
        last_fetched_incidents_ids = self.extract_event_ids_with_same_to_fetch_time(
            events_to_send_to_xsiam, to_fetch_time, event_type)

        if events_to_send_to_xsiam and not get_events:
            self.add_time_to_events(events_to_send_to_xsiam, event_type)
            send_events_to_xsiam(events_to_send_to_xsiam, vendor=VENDOR, product=PRODUCT)

        return events_to_keep, last_fetched_incidents_ids

    @staticmethod
    def add_time_to_events(events: List[Dict] | None, event_type: str):
        """
        Adds the _time key to the events.
        Args:
            events: List[Dict] - list of events to add the _time key to.
            event_type: str - The type of the event.
        """
        if events:
            for event in events:
                create_time = arg_to_datetime(
                    arg=event.get(EVENT_TYPE_TO_TIME_MAPPING[event_type])
                )
                event["_time"] = (
                    create_time.strftime(DATE_FORMAT) if create_time else None
                )
                event["source_log_type"] = event_type

    @staticmethod
    def remove_duplicated_events(events: List[Dict], prev_fetched_events_id: List[int]):
        """Remove events that were already fetched in the last fetch,
        """
        new_events = []
        for event in events:
            if event.get('id') not in prev_fetched_events_id:
                new_events.append(event)

        return new_events

    @staticmethod
    def sort_incidents_based_on_date_field(incidents: List[Dict], date_field_to_sort_by):
        """Sort incidents based on their last_occurrence_date. Returns the incidents in an ascending manner (earliest to latest)
        """

        def get_date_time(dict_item):
            return datetime.strptime(dict_item[date_field_to_sort_by], "%Y-%m-%dT%H:%M:%SZ")

        sorted_incidents = sorted(incidents, key=get_date_time)

        return sorted_incidents

    @staticmethod
    def extract_event_ids_with_same_to_fetch_time(events: List[Dict], to_fetch_time: str, event_type: str):
        """Extract incident ids of incidents with the same to_fetch_time.
        Returns the incidents in an ascending manner (earliest to latest).
        """
        def format_date_string(date_string, event_type):
            if event_type == "audit_log":
                return datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%dT%H:%M:%SZ")
            return date_string

        ids_with_same_occurrence_date = [event["id"] for event in events if format_date_string(event[EVENT_TYPE_TO_TIME_MAPPING[event_type]], event_type) == to_fetch_time]  # noqa: E501

        return ids_with_same_occurrence_date


def test_module(
    client: Client, from_fetch_time: str, max_events_per_fetch: int = 1
) -> str:
    """
    Tests API connectivity and authentication
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): GitGuardian client to use.
        first_fetch_time(str): The first fetch time as configured in the integration params.
        max_events_per_fetch (int): number of events per fetch.
    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """

    try:
        last_run = {
            "from_fetch_time": from_fetch_time,
            "to_fetch_time": from_fetch_time,
            "last_fetched_incident_ids": [],
            "last_fetched_audit_log_ids": [],
        }
        client.search_events(last_run, max_events_per_fetch)

    except Exception as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def get_events(
    client: Client, args: dict
) -> tuple[List[Dict], List[Dict], CommandResults]:
    limit = int(args.get("limit", 50))
    from_date = args.get(
        "from_date", ""
    )  # if no from_date, will return all of the available incidents and audit logs
    last_run = {
        "from_fetch_time": from_date,
        "last_fetched_incident_ids": [],
    }
    incidents, audit_logs, _, _, _ = client.search_events(last_run, limit, get_events=True)
    incidents = incidents[:limit]
    audit_logs = audit_logs[:limit]

    hr = tableToMarkdown(
        name="Test Event - incidents",
        t=incidents,
        headers=["display_name", "id", "created_at", "type", "_time"],
        removeNull=True,
    )
    hr += tableToMarkdown(
        name="Test Event - audit_logs",
        t=audit_logs,
        headers=["id", "type", "gg_created_at", "actor_ip", "actor_email", "_time"],
        removeNull=True,
    )

    return incidents, audit_logs, CommandResults(readable_output=hr)


def fetch_events(
    client: Client, last_run: dict[str, Any], max_events_per_fetch: int
) -> tuple[Dict, List[Dict], List[Dict]]:
    """
    Args:
        client (Client): GitGuardian client to use.
        last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
        max_events_per_fetch (int): number of events per fetch
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of events that will be created in XSIAM.
    """

    (
        incidents,
        audit_logs,
        last_fetched_incident_ids,
        last_fetched_audit_log_ids,
        next_run_from_fetch_time,
    ) = client.search_events(last_run, max_events_per_fetch)

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {
        "from_fetch_time": next_run_from_fetch_time,
        "last_fetched_incident_ids": last_fetched_incident_ids,
        "last_fetched_audit_log_ids": last_fetched_audit_log_ids
    }

    return next_run, incidents, audit_logs


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    api_key = params.get("api_key", {}).get("password")
    base_url = urljoin(params.get("url"), "/api/v1")
    proxy = params.get("proxy", False)
    verify = not params.get("insecure", False)
    max_events_per_fetch = int(params.get("max_events_per_fetch", 5000))

    last_run = demisto.getLastRun()
    current_fetch_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    if not last_run:
        # first fetch of the collector, will fetch events
        demisto.debug("GG: first fetch of the collector")
        last_run = {
            "from_fetch_time": current_fetch_time,
            "to_fetch_time": current_fetch_time,
            "last_fetched_incident_ids": [],
            "last_fetched_audit_log_ids": [],
        }

    else:
        last_run["to_fetch_time"] = current_fetch_time

    demisto.debug(f"Command being called is {command}")
    demisto.debug(f"GG: Last run before starting the command: {last_run}")
    try:
        headers = {"Authorization": f"Token {api_key}"}
        client = Client(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

        if command == "test-module":
            result = test_module(client, current_fetch_time)
            return_results(result)

        elif command == "gitguardian-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            incidents, audit_logs, results = get_events(client, args)
            if should_push_events:
                client.add_time_to_events(audit_logs, 'audit_log')
                send_events_to_xsiam(audit_logs, vendor=VENDOR, product=PRODUCT)
                client.add_time_to_events(incidents, 'incident')
                send_events_to_xsiam(incidents, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            next_run, incidents, audit_logs = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events_per_fetch,
            )
            demisto.debug(f"GG: Setting next run: {next_run}.")
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
