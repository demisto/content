import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
VENDOR = "orca"
PRODUCT = "security"

""" CLIENT CLASS """


class Client(BaseClient):
    def __init__(self, server_url: str, headers: dict, proxy: bool = False, verify: bool = False):
        super().__init__(base_url=server_url, verify=verify, proxy=proxy, headers=headers)

    def get_alerts_request(self, max_fetch: int, last_fetch: str, next_page_token: Optional[str]) -> dict:
        """Retrieve information about alerts using the new Serving Layer API.
        Args:
            max_fetch: int - Limit number of returned records.
            last_fetch: str - The date and time of the last fetch.
                             **MUST be a valid ISO 8601 string (e.g., "2023-10-27T10:00:00Z" or "2023-10-27T10:00:00+00:00").**
                             The API is very strict about this format.
            next_page_token: Optional[str] - The token for the next page, used as start_at_index.
        Returns:
            A dictionary with the alerts details.
        """

        start_index = 0
        if next_page_token:
            try:
                start_index = int(next_page_token)
            except ValueError:
                demisto.info(
                    f"Invalid next_page_token (expected integer for start_at_index): {next_page_token}. Defaulting to 0."
                )
                start_index = 0

        payload = {
            "query": {
                "models": ["Alert"],
                "type": "object_set",
                "with": {
                    "type": "operation",
                    "operator": "and",
                    "values": [
                        {
                            "key": "CreatedAt",
                            "values": [last_fetch],
                            "type": "datetime",
                            "operator": "date_gte",
                            "value_type": "days",
                        }
                    ],
                },
            },
            "limit": max_fetch,
            "start_at_index": start_index,
            "order_by[]": ["CreatedAt"],
            "select": [
                "AlertId",
                "AlertType",
                "OrcaScore",
                "RiskLevel",
                "RuleSource",
                "ScoreVector",
                "Category",
                "Inventory.Name",
                "CloudAccount.Name",
                "CloudAccount.CloudProvider",
                "Source",
                "Status",
                "CreatedAt",
                "LastSeen",
                "Labels",
            ],
        }

        demisto.debug(f"In get_alerts (Serving Layer API) request payload: {json.dumps(payload)}")

        return self._http_request(method="POST", url_suffix="/serving-layer/query", json_data=payload)


""" HELPER FUNCTIONS """


def add_time_key_to_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adds the _time key to the alerts with improved logging and clarity.
    This function mutates the 'alerts' list in place and also returns it.

    Args:
        alerts: A list of alert dictionaries to process.

    Returns:
        The mutated list of alerts, now including the '_time' key.
    """
    now_utc = datetime.now(timezone.utc)
    fallback_time_str = now_utc.strftime(DATE_FORMAT)

    if not alerts:
        return alerts

    for alert in alerts:
        alert_data = alert.get("data", {})
        create_time_str = alert_data.get("CreatedAt", {}).get("value")
        alert_id = alert_data.get("AlertId", {}).get("value") or alert.get("id", "UNKNOWN_ID")
        create_time = None
        if create_time_str:
            try:
                create_time = arg_to_datetime(arg=create_time_str)
            except Exception as e:
                demisto.error(
                    f"arg_to_datetime failed unexpectedly while parsing for AlertId: {alert_id} "
                    f"with value '{create_time_str}', setting fallback time {now_utc}. Error: {e}"
                )
                create_time = now_utc

        if create_time:
            alert["_time"] = create_time.strftime(DATE_FORMAT)
        else:
            demisto.info(
                f"Could not parse or find 'CreatedAt' value for AlertId: {alert_id}. "
                f"Raw 'CreatedAt' value was: '{create_time_str}'. Setting '_time' to {fallback_time_str}."
            )
            alert["_time"] = fallback_time_str

        demisto.debug(f"Processed AlertId: {alert_id}, final _time: {alert.get('_time')}")

    return alerts


""" COMMAND FUNCTIONS """


def orca_test_module(client: Client, last_fetch: str, max_fetch: int) -> str:
    """Test the connection to Orca Security.
    Args:
        client: client - An Orca client.
        last_fetch: str - The time and date of the last fetch alert
        max_fetch: int - The maximum number of events per fetch
    Returns:
        'ok' if the connection was successful, else throws exception.
    """
    try:
        client.get_alerts_request(max_fetch, last_fetch, None)
        return "ok"
    except DemistoException as e:
        if "Error in API call [404] - Not Found" in e.message:
            raise Exception('Error in API call [404] - Not Found\n{"error": "URL is invalid"}')
        else:
            raise Exception(e.message)


def get_alerts(client: Client, max_fetch: int, last_fetch: str, next_page_token: str = None) -> tuple:
    """Retrieve information about alerts.
    Args:
        client: client - An Orca client.
        max_fetch: int - The maximum number of events per fetch
        last_fetch: str - The time and date of the last fetch alert
        next_page_token: str - The token to the next page.
    Returns:
        - list of alerts
        - next_page_token if exist
    """
    response = client.get_alerts_request(max_fetch, last_fetch, next_page_token)
    next_page_token = response.get("next_page_token", None)
    alerts = response.get("data", [])
    demisto.debug(f"Get Alerts Response {next_page_token=} , {len(alerts)=}\n {alerts=}")
    return alerts, next_page_token


""" MAIN FUNCTION """


def main() -> None:
    command = demisto.command()
    api_token = demisto.params().get("credentials", {}).get("password")
    server_url = f"{demisto.params().get('server_url')}/api"
    first_fetch = demisto.params().get("first_fetch") or "3 days"
    max_fetch = arg_to_number(demisto.params().get("max_fetch")) or 1000
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    # How much time before the first fetch to retrieve events
    first_fetch_time = arg_to_datetime(arg=first_fetch, arg_name="First fetch time", required=True)
    first_fetch_time = first_fetch_time.strftime(DATE_FORMAT) if first_fetch_time else ""
    demisto.debug(f"{first_fetch_time=}")
    demisto.info(f"Orca Security. Command being called is {command}")
    try:
        headers: dict = {"Authorization": f"Token {api_token}"}

        client = Client(server_url=server_url, verify=verify_certificate, headers=headers, proxy=proxy)

        last_run = demisto.getLastRun()
        if not last_run:
            demisto.debug(f"first run {last_run=}")
            last_fetch = first_fetch_time
        else:
            last_fetch = last_run.get("lastRun")
            demisto.debug(f"Isn't the first run {last_fetch}")
        next_page_token = last_run.get("next_page_token")

        if command == "test-module":
            return_results(orca_test_module(client, last_fetch, 3))
        elif command in ("fetch-events", "orca-security-get-events"):
            alerts, next_page_token = get_alerts(client, max_fetch, last_fetch, next_page_token)

            if command == "fetch-events":
                should_push_events = True

            else:  # command == 'orca-security-get-events'
                should_push_events = argToBoolean(demisto.args().get("should_push_events", False))
                return_results(
                    CommandResults(
                        readable_output=tableToMarkdown(t=alerts, name=f"{VENDOR} - {PRODUCT} events", removeNull=True),
                        raw_response=alerts,
                    )
                )

            if should_push_events and alerts:
                alerts = add_time_key_to_alerts(alerts)
                demisto.debug(f"before send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}")
                send_events_to_xsiam(alerts, VENDOR, PRODUCT)
                demisto.debug(f"after send_events_to_xsiam {VENDOR=} {PRODUCT=} {alerts=}")

            current_last_run = {"next_page_token": next_page_token}
            if next_page_token:
                current_last_run["lastRun"] = last_fetch
            else:
                last_updated_str = alerts[-1].get("data", {}).get("CreatedAt", {}).get("value") if alerts else None
                last_updated = arg_to_datetime(arg=last_updated_str)
                current_last_run["lastRun"] = last_updated.strftime(DATE_FORMAT) if last_updated else last_fetch

            demisto.setLastRun(current_last_run)
            demisto.debug(f"{current_last_run=}")

        else:
            raise NotImplementedError("This command is not implemented yet.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
