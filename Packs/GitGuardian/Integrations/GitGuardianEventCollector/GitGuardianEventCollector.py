import demistomock as demisto
from CommonServerPython import *
import urllib3
from typing import Any
import math

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
VENDOR = "gitguardian"
PRODUCT = "enterprise"
DEFAULT_PAGE_SIZE = 1000
EVENT_TYPE_TO_TIME_MAPPING = {
    "audit_log": "gg_created_at",
    "incident": "first_occurrence_date",
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
        self, last_run: dict[str, Any], max_events_per_fetch: int
    ) -> tuple[List[Dict], List[Dict], List[int], str, str]:  # noqa: E501
        """
        Searches for GitGuardian alerts using the '/secrets' and '/audit_logs' API endpoints.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            last_run (dict): A dict with a key containing the latest event created time we got from last fetch.
            max_events_per_fetch (int): number of events per fetch

        Returns:
            List: A list of events that were fetched
            str: The time to start the next incident fetch.
        """
        incidents, next_run_incidents, last_fetched_incident_ids = self.search_incidents(
            last_run.get("incident_from_fetch_time", ""), max_events_per_fetch, last_run.get("last_fetched_incident_ids", [])
        )
        audit_logs, next_run_audit_logs = self.search_audit_logs(
            last_run.get("audit_log_from_fetch_time", ""), max_events_per_fetch
        )

        self.add_time_to_events(incidents, "incident")
        self.add_time_to_events(audit_logs, "audit_log")

        return incidents, audit_logs, last_fetched_incident_ids, next_run_incidents, next_run_audit_logs

    def search_incidents(
        self, from_fetch_time: str, max_events_per_fetch: int, last_fetched_incident_ids: List[int]
    ) -> tuple[List[Dict], str, List[int]]:
        """Searching the API for new incidents.

        Args:
            from_fetch_time (str): The time we starting to fetch incidents.
            max_events_per_fetch (int): Max number of events to fetch.

        Returns:
            List: A list of events that were fetched
            str: The time to start the next incident fetch.
        """
        next_url = ""
        incidents = []
        total_num_of_fetched_incidents = 0
        params = {"from": from_fetch_time, "per_page": DEFAULT_PAGE_SIZE}

        while True:
            if next_url:
                demisto.debug(f"GG: Fetching incidents using the next_url: {next_url}")
                response = self._http_request(
                    method="GET",
                    full_url=next_url,
                )
            else:
                demisto.debug(f"GG: Fetching incidents using the params: {params}")
                response = self._http_request(
                    method="GET",
                    url_suffix="/secrets",
                    params=params,
                )
            new_incidents = self.remove_duplicated_incidents(response.get("results"), last_fetched_incident_ids)
            incidents.extend(new_incidents)
            total_num_of_fetched_incidents += len(new_incidents)

            next_url = response.get("next")
            if not next_url:
                break

        sorted_incidents = self.sort_incidents_based_on_last_occurrence_date(incidents)
        incidents = sorted_incidents[:max_events_per_fetch]

        if len(incidents) == 0:
            next_run_incidents_from_fetch: str = from_fetch_time
            fetched_incident_ids = last_fetched_incident_ids
            demisto.debug("GG: No incidents were fetched")
        else:
            next_run_incidents_from_fetch = incidents[-1].get("last_occurrence_date", "")
            fetched_incident_ids = self.extract_incident_ids_with_same_last_occurrence_date(incidents,
                                                                                            next_run_incidents_from_fetch)
            demisto.debug(
                f"GG: {len(incidents)} incidents were fetched, last incident time is {next_run_incidents_from_fetch}"
            )

        return incidents, next_run_incidents_from_fetch, fetched_incident_ids

    def search_audit_logs(
        self, from_fetch_time: str, max_events_per_fetch: int
    ) -> tuple[List[Dict], str]:
        """Searching the API for new audit logs. The logs are ordered by newest to oldest.

        Args:
            from_fetch_time (str): The time we starting to fetch incidents.
            max_events_per_fetch (int): Max number of events to fetch.

        Returns:
            List: A list of events that were fetched
            str: The time to start the next incident fetch.
        """
        next_url = ""
        audit_logs = []
        total_num_of_fetched_logs = 0
        params = {"from": from_fetch_time, "per_page": DEFAULT_PAGE_SIZE}

        last_page = self.get_last_page(params, "/audit_logs")
        params["page"] = last_page

        while total_num_of_fetched_logs < max_events_per_fetch:
            if next_url:
                demisto.debug(f"GG: Fetching audit logs using the next_url: {next_url}")
                response = self._http_request(
                    method="GET",
                    full_url=next_url,
                )
            else:
                demisto.debug(f"GG: Fetching audit logs using the params: {params}")
                response = self._http_request(
                    method="GET",
                    url_suffix="/audit_logs",
                    params=params,
                )

            raw_audit_logs = response.get("results")
            raw_audit_logs.reverse()  # reversing the events due to LIFO order
            audit_logs.extend(raw_audit_logs)

            next_url = response.get("previous")
            total_num_of_fetched_logs += len(response.get("results"))

            if not next_url:
                break

        audit_logs = audit_logs[:max_events_per_fetch]
        if len(audit_logs) == 0:
            demisto.debug("GG: No audit_logs were fetched")
            next_run_audit_logs_from_fetch = from_fetch_time
        else:
            next_run_audit_logs_from_fetch = self.alter_next_fetch_time(
                audit_logs[-1].get("gg_created_at")
            )
            demisto.debug(
                f"GG: {len(audit_logs)} audit_logs were fetched,last audit_logs time is {next_run_audit_logs_from_fetch}"
            )

        return audit_logs, next_run_audit_logs_from_fetch

    def get_last_page(self, params: dict[str, Any], url_suffix: str) -> int:
        """As the API returns the entries from the latest to the oldest, we need to start the fetch from the last page.
        Calculates the number of the last page.
        """
        response = self._http_request(
            method="GET",
            url_suffix=url_suffix,
            params=params,
        )
        total_num_of_results = response.get("count")
        number_of_last_page = math.ceil(total_num_of_results / DEFAULT_PAGE_SIZE) or 1
        return number_of_last_page

    @staticmethod
    def alter_next_fetch_time(
        time_str_to_alter, num_of_microseconds_to_add: int = 1
    ) -> str:
        """Adds the requested amount of microseconds to a time str"""
        event_time = datetime.strptime(time_str_to_alter, DATE_FORMAT)
        altered_event_time = event_time + timedelta(
            microseconds=num_of_microseconds_to_add
        )

        return altered_event_time.strftime(DATE_FORMAT)

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
    def remove_duplicated_incidents(incidents: List[Dict], last_fetched_incident_ids: List[int]):
        """Remove incidents that were already fetched in the last fetch, due to first_occurrence_date not supporting miliseconds
        """
        new_incidents = []
        for incident in incidents:
            if incident.get('id') not in last_fetched_incident_ids:
                new_incidents.append(incident)

        return new_incidents

    @staticmethod
    def sort_incidents_based_on_last_occurrence_date(incidents: List[Dict]):
        """Sort incidents based on their last_occurrence_date. Returns the incidents in an ascending manner (earliest to latest)
        """

        def get_date_time(dict_item):
            return datetime.strptime(dict_item["last_occurrence_date"], "%Y-%m-%dT%H:%M:%SZ")

        sorted_incidents = sorted(incidents, key=get_date_time)

        return sorted_incidents

    @staticmethod
    def extract_incident_ids_with_same_last_occurrence_date(incidents: List[Dict], last_occurrence_date: str):
        """Extract incident ids of incidents with the same last_occurrence_date.
        Returns the incidents in an ascending manner (earliest to latest).
        """

        ids_with_same_occurrence_date = [incident["id"] for incident in incidents if incident["last_occurrence_date"] == last_occurrence_date]  # noqa: E501

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
            "incident_from_fetch_time": from_fetch_time,
            "audit_log_from_fetch_time": from_fetch_time,
            "last_fetched_incident_ids": [],
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
        "incident_from_fetch_time": from_date,
        "audit_log_from_fetch_time": from_date,
        "last_fetched_incident_ids": [],
    }
    incidents, audit_logs, _, _, _ = client.search_events(last_run, limit)
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
        next_run_incidents,
        next_run_audit_logs,
    ) = client.search_events(last_run, max_events_per_fetch)

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {
        "incident_from_fetch_time": next_run_incidents,
        "audit_log_from_fetch_time": next_run_audit_logs,
        "last_fetched_incident_ids": last_fetched_incident_ids,
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
    from_fetch_time = datetime.now().isoformat()
    if not last_run:
        # first fetch of the collector
        last_run = {
            "incident_from_fetch_time": from_fetch_time,
            "audit_log_from_fetch_time": from_fetch_time,
        }

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Token {api_key}"}
        client = Client(base_url=base_url, verify=verify, headers=headers, proxy=proxy)

        if command == "test-module":
            result = test_module(client, from_fetch_time)
            return_results(result)

        elif command == "gitguardian-get-events":
            should_push_events = argToBoolean(args.pop("should_push_events"))
            incidents, audit_logs, results = get_events(client, args)
            if should_push_events:
                send_events_to_xsiam(audit_logs, vendor=VENDOR, product=PRODUCT)
                send_events_to_xsiam(incidents, vendor=VENDOR, product=PRODUCT)
            return_results(results)

        elif command == "fetch-events":
            next_run, incidents, audit_logs = fetch_events(
                client=client,
                last_run=last_run,
                max_events_per_fetch=max_events_per_fetch,
            )
            send_events_to_xsiam(audit_logs, vendor=VENDOR, product=PRODUCT)
            send_events_to_xsiam(incidents, vendor=VENDOR, product=PRODUCT)
            demisto.debug(f"GG: Setting next run: {next_run}.")
            demisto.setLastRun(next_run)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
