from typing import Tuple, cast

import urllib3
from requests import Response

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

    def patch_alert(self, alert_id: str, alert_status: str) -> Response:
        request_data = {"status": alert_status}
        return self._http_request(
            method="PATCH",
            url_suffix=f"organizations/{self.tenant_key}/alerts/{alert_id}",
            json_data=request_data,
            resp_type='response'
        )


""" HELPER FUNCTIONS """


def convert_to_demisto_severity(severity: str) -> float:
    """
    Maps Neosec severity to Cortex XSOAR severity.
    Converts the Neosec alert severity level ('Info', 'Low', 'Medium', 'High', 'Critical') to Cortex XSOAR incident
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
        "Critical": IncidentSeverity.CRITICAL,
    }[severity]


def build_filter(
        name: str, operator: str, values: Union[List[Any], Any]
) -> List[Dict[str, Any]]:
    if not isinstance(values, list):
        values = [values]
    return [{"name": name, "operator": operator, "value": value} for value in values]


def timestamp_to_neosec_datetime(timestamp: int) -> str:
    return datetime.utcfromtimestamp(timestamp).strftime(NEOSEC_DATE_FORMAT)


def detokenize_alerts(
        neosec_node_client: NeosecNodeClient, alerts: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    return json.loads(neosec_node_client.detokenize_message(json.dumps(alerts)))


""" COMMAND FUNCTIONS """


def test_module(
        client: NeosecClient,
        node_client: Optional[NeosecNodeClient],
        alert_status: Optional[str],
        severities: Optional[List[str]],
        alert_types: Optional[List[str]],
        max_results: int,
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
        client.search_alerts(
            max_results=max_results,
            alert_status=alert_status,
            severities=severities,
            alert_types=alert_types,
            start_time=None,
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
        alert_status: Optional[str] = None,
        severities: Optional[List[str]] = None,
        alert_type: Optional[List[str]] = None,
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

    for alert in alerts:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the Neosec API response
        alert_trigger_at = dateparser.parse(alert["triggered_at"])
        if not alert_trigger_at:
            raise ValueError("Alert triggered at is not valid")
        incident_created_time = alert_trigger_at.timestamp()

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch:
            if incident_created_time <= last_fetch:
                continue

        alert_timestamp = dateparser.parse(alert.get("timestamp"))  # type: ignore
        if not alert_timestamp:
            raise ValueError("Alert's timestamp is not valid")

        incident = {
            "name": alert["name"],
            "occurred": timestamp_to_datestring(
                int(alert_timestamp.timestamp() * 1000),
                date_format=DATE_FORMAT,
                is_utc=True,
            ),
            "rawJSON": json.dumps(alert),
            "severity": convert_to_demisto_severity(alert.get("severity", "Low")),
            "dbotMirrorId": str(alert["id"]),
            "details": alert["description"],
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = int(incident_created_time)

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"last_fetch": latest_created_time}
    return next_run, incidents


def set_alert_status(client: NeosecClient, alert_id: str, alert_status: str) -> str:
    response = client.patch_alert(alert_id, alert_status)
    if response.status_code == 200:
        return f"Alert {alert_id} updated successfully"
    else:
        raise DemistoException(f"Error updating alert {alert_id} - {response.text}")


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

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=params.get("first_fetch", "3 days"),
        arg_name="First fetch time",
        required=True,
    )

    # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    if first_fetch_time:
        first_fetch_timestamp = int(first_fetch_time.timestamp())
    else:
        raise DemistoException('The first fetch parameter is inavlid, make sure it\'s according to standards.')

    demisto.debug(f"Command being called is {command}")
    try:
        neosec_node_url = params.get("neosec_node_url")
        neosec_node_client = (
            NeosecNodeClient(base_url=neosec_node_url, verify=False, proxy=False)
            if neosec_node_url else None
        )
        client = NeosecClient(
            base_url=base_url,
            verify=not params.get("insecure", False),
            headers={"X-API-Key": api_key},
            proxy=params.get("proxy", False),
            tenant_key=params.get("tenant_key"),
        )

        # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
        max_results = arg_to_number(
            arg=params.get("max_fetch"), arg_name="max_fetch", required=False
        )
        if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
            max_results = MAX_INCIDENTS_TO_FETCH

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(
                client,
                neosec_node_client,
                params.get("alert_status", None),
                params.get("severities", None),
                params.get("alert_type", None),
                max_results
            )
            return_results(result)

        elif command == "fetch-incidents":
            next_run, incidents = fetch_incidents(
                client=client,
                node_client=neosec_node_client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=params.get("alert_status", None),
                severities=params.get("severities", None),
                alert_type=params.get("alert_type", None),
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif command == "neosec-alert-status-set":
            return_results(set_alert_status(client, args.get("alert_id"), args.get("alert_status")))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
