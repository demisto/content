"""Neosec Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""
import json
from typing import Dict, Any, Tuple, cast

import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
NEOSEC_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
MAX_INCIDENTS_TO_FETCH = 50

ALERT_TYPE_MAP = {
    "Runtime": "UserBehaviorAlert",
    "Posture": "APIAlert",
}


""" CLIENT CLASS """


class NeosecNodeClient(BaseClient):
    def health_check(self) -> str:
        response = self._http_request(method="GET", url_suffix="/healthcheck")
        return response.get("Status", "")

    def detokenize_message(self, message: str) -> str:
        response = self._http_request(
            method="POST", url_suffix="/detokenize", json_data={"message": message}
        )
        return response.get("Message", "")


class NeosecClient(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(
        self, base_url: str, proxy: bool, verify: bool, headers: Dict, tenant_key: str
    ):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify, headers=headers)
        self.tenant_key = tenant_key

    def search_alerts(
        self,
        alert_status: Optional[str],
        severities: Optional[List[str]],
        alert_types: Optional[List[str]],
        max_results: Optional[int],
        start_time: Optional[int],
    ) -> List[Dict[str, Any]]:
        """
        Searches for Neosec alerts using the '/alerts/query' API endpoint.
        All the parameters are passed directly to the API as HTTP POST parameters in the request

        Args:
            alert_status (str): status of the alert to search for. Options are: 'Open' or 'Closed'
            severities (List[str]): severity of the alert to search for. Options are: "Low", "Medium", "High", "Info".
            alert_types (List[str]): type of alerts to search for. Options are: 'UserBehaviorAlert' or 'APIAlert'
            max_results (int): maximum number of results to return.
            start_time (int): start timestamp (epoch in seconds) for the alert search.

        Returns:
            list: list of Neosec alerts as dicts.
        """

        request_data: Dict[str, Any] = {
            "alert_filters": [],
            "offset": 0,
            "sort_by": "asc(triggered_at)",
        }

        if alert_status:
            request_data["alert_filters"].append(
                build_filter("status", "Eq", alert_status)
            )

        if alert_types:
            request_data["alert_filters"].append(
                build_filter(
                    "alert_type",
                    "Eq",
                    [ALERT_TYPE_MAP[alert_type] for alert_type in alert_types],
                )
            )

        if severities:
            request_data["alert_filters"].append(
                build_filter("severity", "Eq", severities)
            )

        if start_time:
            request_data["alert_filters"].append(
                build_filter(
                    "triggered_at", "Gt", timestamp_to_neosec_datetime(start_time)
                )
            )

        if max_results:
            request_data["limit"] = max_results

        response = self._http_request(
            method="POST",
            url_suffix=f"organizations/{self.tenant_key}/alerts/query",
            json_data=request_data,
        )
        items = response.get("items", [])
        return items

    def patch_alert(self, alert_id: str, alert_status: str) -> None:
        request_data = {"status": alert_status}
        self._http_request(
            method="PATCH",
            url_suffix=f"organizations/{self.tenant_key}/alerts/{alert_id}",
            json_data=request_data,
        )


""" HELPER FUNCTIONS """


def convert_to_demisto_severity(severity: str) -> float:
    """
    Maps Neosec severity to Cortex XSOAR severity.
    Converts the Neosec alert severity level ('Low', 'Medium', 'High', 'Critical') to Cortex XSOAR incident
    severity (1 to 4).

    Args:
        severity (str): severity as returned from the Neosec API.

    Returns:
        int: Cortex XSOAR Severity (0 to 4)
    """
    return {
        "Low": IncidentSeverity.LOW,
        "Medium": IncidentSeverity.MEDIUM,
        "High": IncidentSeverity.HIGH,
        "Info": IncidentSeverity.INFO,
    }[severity]


def build_filter(
    name: str, operator: str, values: Union[List[Any], Any]
) -> List[Dict[str, Any]]:
    if not isinstance(values, list):
        values = [values]
    return [{"name": name, "operator": operator, "value": value} for value in values]


def neosec_datetime_to_timestamp(date_str: str) -> int:
    return int(
        datetime.strptime(date_str, NEOSEC_DATE_FORMAT)
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )


def timestamp_to_neosec_datetime(timestamp: int) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime(NEOSEC_DATE_FORMAT)


def detokenize_alerts(
    neosec_node_client: NeosecNodeClient, alerts: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    return [
        json.loads(neosec_node_client.detokenize_message(json.dumps(alert)))
        for alert in alerts
    ]


""" COMMAND FUNCTIONS """


def test_module(
    client: NeosecClient,
    node_client: Optional[NeosecNodeClient],
    params: Dict[str, Any],
    first_fetch_timestamp: int,
) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.

        alert_status = params.get("alert_status", None)
        alert_type = params.get("alert_type", None)
        severities = params.get("severities", None)

        # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
        max_results = arg_to_number(
            arg=params.get("max_fetch"), arg_name="max_fetch", required=False
        )
        if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
            max_results = MAX_INCIDENTS_TO_FETCH

        if params.get("isfetch"):  # Tests fetch incident:
            fetch_incidents(
                client=client,
                node_client=node_client,
                max_results=max_results,
                first_fetch_time=first_fetch_timestamp,
                last_run={},
                alert_status=alert_status,
                severities=severities,
                alert_type=alert_type,
            )
        else:
            client.search_alerts(
                max_results=max_results,
                alert_status=alert_status,
                severities=severities,
                alert_types=alert_type,
                start_time=first_fetch_timestamp,
            )

        if node_client:
            status = node_client.health_check()
            if status != "ok":
                return f"Neosec Node is not available, status: {status}"

    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def fetch_incidents(
    client: NeosecClient,
    node_client: Optional[NeosecNodeClient],
    max_results: int,
    last_run: Dict[str, int],
    first_fetch_time: int,
    alert_status: Optional[str],
    severities: Optional[List[str]],
    alert_type: Optional[List[str]],
) -> Tuple[Dict[str, int], List[dict]]:

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get("last_fetch", None)
    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    alerts = client.search_alerts(
        alert_types=alert_type,
        alert_status=alert_status,
        max_results=max_results,
        start_time=last_fetch,
        severities=severities,
    )
    alerts = detokenize_alerts(node_client, alerts) if node_client else alerts

    demisto.info("Starting iterating over incidents")
    for alert in alerts:
        demisto.info("alert to incident workflow")
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the Neosec API response
        incident_created_time = dateparser.parse(alert["triggered_at"]).timestamp()
        demisto.info(
            f"alert: {incident_created_time}, triggered_at: {alert.get('triggered_at')}"
        )

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                demisto.info(f"dropping alert {alert.get('id')}")
                continue

        incident = {
            "name": alert["name"],
            "occurred": timestamp_to_datestring(
                neosec_datetime_to_timestamp(alert["timestamp"]) * 1000,
                date_format=DATE_FORMAT,
                is_utc=True,
            ),
            "rawJSON": json.dumps(alert),
            "severity": convert_to_demisto_severity(alert.get("severity", "Low")),
            "dbotMirrorId": str(alert["id"]),
            "details": alert["description"],
        }

        demisto.info(f"Created new incident: {incident}")
        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"last_fetch": latest_created_time}
    return next_run, incidents


def set_alert_status(client: NeosecClient, alert_id: str, alert_status: str) -> None:
    client.patch_alert(alert_id, alert_status)


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get("credentials", {}).get("password")

    # get the service API url
    base_url = urljoin(params["url"], "/v4")

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get("insecure", False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=params.get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )
    first_fetch_timestamp = (
        int(first_fetch_time.timestamp()) if first_fetch_time else None
    )
    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    assert isinstance(first_fetch_timestamp, int)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    tenant_key = params.get("tenant_key")

    demisto.debug(f"Command being called is {command}")
    try:
        is_tokenized = params.get("is_tokenized", False)
        neosec_node_url = params.get("neosec_node_url")
        if (is_tokenized and not neosec_node_url) or (
            not is_tokenized and neosec_node_url
        ):
            return_error(
                f"Invalid input: De-Tokenized Alerts(is_tokenized={is_tokenized}) and Neosec Node URL({neosec_node_url}) is not matched"
            )

        neosec_node_client = (
            NeosecNodeClient(base_url=neosec_node_url, verify=False, proxy=proxy)
            if is_tokenized and neosec_node_url
            else None
        )

        # (i.e. "Authorization": {api key})
        headers: Dict = {"X-API-Key": api_key}

        client = NeosecClient(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            tenant_key=tenant_key,
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(
                client, neosec_node_client, params, first_fetch_timestamp
            )
            return_results(result)

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = params.get("alert_status", None)
            alert_type = params.get("alert_type", None)
            severities = params.get("severities", None)

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(
                arg=params.get("max_fetch"), arg_name="max_fetch", required=False
            )
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                node_client=neosec_node_client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=alert_status,
                severities=severities,
                alert_type=alert_type,
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif command == "neosec-alert-status-set":
            alert_id = args.get("alert_id")
            alert_status = args.get("alert_status")
            set_alert_status(client, alert_id, alert_status)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
