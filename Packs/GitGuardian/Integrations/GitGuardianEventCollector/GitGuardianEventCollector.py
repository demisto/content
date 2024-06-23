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

    def search_events(self, last_run: dict[str, Any], max_events_per_fetch: int, event_type: str) -> tuple[List[Dict], List[int], str, bool, str]:  # noqa: E501
        """
        Searches for GitGuardian alerts using the '/secrets' and '/audit_logs' API endpoints.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
            max_events_per_fetch (int): number of events per fetch
            get_events (bool, optional): running the function through the get-events command. Defaults to False.

        Returns:
            List: A list of events that were fetched
            str: The time to start the next incident fetch.
        """
        from_fetch_time = last_run.get("from_fetch_time", "")
        to_fetch_time = last_run.get("to_fetch_time", "")
        last_fetched_event_ids = last_run.get("last_fetched_ids", [])
        next_url_link = last_run.get("next_url_link", "")

        events, last_fetched_event_ids, next_fetch_url, is_pagination_in_progress = self.retrieve_events(
            from_fetch_time, to_fetch_time, max_events_per_fetch, last_fetched_event_ids, event_type, next_url_link
        )

        if is_pagination_in_progress:
            # handle the case where we do not need to update the time window for the next fetch, as we need to
            # continue fetching more pages
            next_run_from_fetch_time = last_run.get("from_fetch_time", "")
        else:
            # there are no more events to fetch in the current time window
            next_run_from_fetch_time = last_run.get("to_fetch_time", "")

        return events, last_fetched_event_ids, next_fetch_url, is_pagination_in_progress, next_run_from_fetch_time

    def retrieve_events(
            self, from_fetch_time: str, to_fetch_time: str, max_events_per_fetch: int, prev_run_fetched_event_ids: List[int],
            event_type: str, next_url: str) -> tuple[List[Dict], List[int], str, bool]:
        """retrieve events from the API

        Args:
            from_fetch_time (str): the time to start the fetch from
            to_fetch_time (str): the time to end the fetch
            max_events_per_fetch (int): maximum number of events to fetch in each fetch
            prev_run_fetched_event_ids (List[int]): the ids of the events that were fetch in the last fetch that
                                                    could be duplicated (the same time as to_fetch_time)
            event_type (str): the type of the event.
            get_events (bool, optional): running the function through the get-events command. Defaults to False.

        """
        events: List[dict] = []
        params = {"from": from_fetch_time, "per_page": DEFAULT_PAGE_SIZE, "to": to_fetch_time}

        while len(events) < max_events_per_fetch:
            if next_url:
                demisto.debug(f"GG: Fetching events using the next_url: {next_url}")
                response = self._http_request(
                    method="GET",
                    full_url=next_url,
                    retries=3,
                )
            else:
                demisto.debug(f"GG: Fetching events using the params: {params}")
                response = self._http_request(
                    method="GET",
                    url_suffix=EVENT_TYPE_TO_ENDPOINT.get(event_type, ''),
                    params=params,
                    retries=3,
                )
            new_events = self.remove_duplicated_events(response.get("results"), prev_run_fetched_event_ids)
            events.extend(new_events)

            next_url = response.get("next")
            if not next_url:
                break

        last_fetched_events_ids, next_fetch_url, is_pagination_in_progress = self.handle_events(events, event_type, to_fetch_time, next_url, prev_run_fetched_event_ids)  # noqa: E501

        if response.get("count") == 0:
            demisto.debug("GG: No events were fetched.")
        else:
            demisto.debug(f"GG: Fetched {len(events)} events.")

        return events, last_fetched_events_ids, next_fetch_url, is_pagination_in_progress

    def handle_events(self, events: list, event_type: str, to_fetch_time: str, next_url: str,
                      prev_run_fetched_event_ids: List[int]) -> tuple[List[int], str, bool]:
        """handle the newly fetched events.

        Args:
            events_to_send (list): events fetched.
            event_type (str): the type of the event.
            to_fetch_time (str): the end time of the fetch
            next_url (str): the url for the next fetch
            prev_run_fetched_event_ids (List[int]): the event ids that were fetched in the previous fetch

        """
        last_fetched_events_ids = []
        if next_url:
            last_fetched_events_ids = prev_run_fetched_event_ids
            next_fetch_url = next_url
            is_pagination_in_progress = True

        else:
            # there are no more events to fetch in the current time window
            last_fetched_events_ids = self.extract_event_ids_with_same_to_fetch_time(events, to_fetch_time, event_type)
            is_pagination_in_progress = False
            next_fetch_url = ''
        return last_fetched_events_ids, next_fetch_url, is_pagination_in_progress

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
    def extract_event_ids_with_same_to_fetch_time(events: List[Dict], to_fetch_time: str, event_type: str):
        """Extract event ids of incidents with the same to_fetch_time as the _time field time.
        Returns the events in an ascending manner (earliest to latest).
        """
        def format_date_string(date_string, event_type):
            if event_type == "audit_log":
                return datetime.strptime(date_string, DATE_FORMAT).strftime("%Y-%m-%dT%H:%M:%SZ")
            return date_string

        ids_with_same_occurrence_date = [event["id"] for event in events if format_date_string(event[EVENT_TYPE_TO_TIME_MAPPING[event_type]], event_type) == to_fetch_time]  # noqa: E501

        return ids_with_same_occurrence_date


def handle_last_run(last_run: dict, is_pagination_in_progress_incident: bool, is_pagination_in_progress_auditlog: bool,
                    next_run_incident_from_fetch_time: str, next_run_audit_log_from_fetch_time: str, last_fetched_incident_ids: list,  # noqa: E501
                    last_fetched_audit_log_ids: list, next_fetch_incident_url: str, next_fetch_auditlog_url: str):
    """Creates the next_run dictionary for the next fetch.
    """
    next_run: Dict[str, Any] = {}
    if is_pagination_in_progress_incident or is_pagination_in_progress_auditlog:
        next_run["nextTrigger"] = "0"
    next_run["incident"] = {
        "from_fetch_time": next_run_incident_from_fetch_time,
        "to_fetch_time": last_run["incident"]['to_fetch_time'],
        "last_fetched_event_ids": last_fetched_incident_ids,
        "next_url_link": next_fetch_incident_url,
        "is_pagination_in_progress": is_pagination_in_progress_incident,
    }
    next_run["audit_log"] = {
        "from_fetch_time": next_run_audit_log_from_fetch_time,
        "to_fetch_time": last_run["audit_log"]['to_fetch_time'],
        "last_fetched_event_ids": last_fetched_audit_log_ids,
        "next_url_link": next_fetch_auditlog_url,
        "is_pagination_in_progress": is_pagination_in_progress_auditlog,
    }

    return next_run


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
            "last_fetched_ids": [],
            "next_url_link": "",
        }
        client.search_events(last_run, max_events_per_fetch, 'incident')

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
        "last_fetched_event_ids": [],
    }
    incidents, _, _, _, _ = client.search_events(last_run, limit, 'incident')
    audit_logs, _, _, _, _ = client.search_events(last_run, limit, 'audit_log')
    incidents = incidents[:limit]
    audit_logs = audit_logs[:limit]

    hr = tableToMarkdown(
        name="incidents",
        t=incidents,
        headers=["display_name", "id", "created_at", "type", "_time"],
        removeNull=True,
    )
    hr += tableToMarkdown(
        name="Audit logs",
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

    incidents, last_fetched_incident_ids, next_fetch_incident_url, is_pagination_in_progress_incident, next_run_incident_from_fetch_time = client.search_events(  # noqa: E501
        last_run.get("incident", {}), max_events_per_fetch, 'incident')
    audit_logs, last_fetched_audit_log_ids, next_fetch_auditlog_url, is_pagination_in_progress_auditlog, next_run_audit_log_from_fetch_time = client.search_events(  # noqa: E501
        last_run.get("audit_log", {}), max_events_per_fetch, 'audit_log')

    next_run = handle_last_run(last_run, is_pagination_in_progress_incident, is_pagination_in_progress_auditlog,
                               next_run_incident_from_fetch_time, next_run_audit_log_from_fetch_time, last_fetched_incident_ids,
                               last_fetched_audit_log_ids, next_fetch_incident_url, next_fetch_auditlog_url)

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

    last_run: dict[str, Any] = demisto.getLastRun()
    current_fetch_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    if not last_run:
        # first fetch of the collector, will fetch events
        demisto.debug("GG: first fetch of the collector.")
        last_run = {
            "incident": {"from_fetch_time": current_fetch_time,
                         "to_fetch_time": current_fetch_time,
                         "last_fetched_event_ids": [],
                         "next_url_link": "",
                         "is_pagination_in_progress": False},
            "audit_log": {
                "from_fetch_time": current_fetch_time,
                "to_fetch_time": current_fetch_time,
                "last_fetched_event_ids": [],
                "next_url_link": "",
                "is_pagination_in_progress": False
            }
        }

    if not last_run["incident"].get("is_pagination_in_progress"):
        last_run["incident"]["to_fetch_time"] = current_fetch_time
    if not last_run["audit_log"].get("is_pagination_in_progress"):
        last_run["audit_log"]["to_fetch_time"] = current_fetch_time
    demisto.debug(f"GG: fetching incidents from {last_run['incident']['from_fetch_time']} to {last_run['incident']['to_fetch_time']}. "  # noqa: E501
                  f"fetching audit logs from {last_run['audit_log']['from_fetch_time']} to {last_run['audit_log']['to_fetch_time']}.")  # noqa: E501

    demisto.debug(f"Command being called is {command}")
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
                client.add_time_to_events(incidents, 'incident')
                send_events_to_xsiam(incidents + audit_logs, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            next_run, incidents, audit_logs = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events_per_fetch,
            )
            client.add_time_to_events(audit_logs, 'audit_log')
            client.add_time_to_events(incidents, 'incident')
            send_events_to_xsiam(incidents + audit_logs, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"GG: Setting next run: {next_run}.")
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
