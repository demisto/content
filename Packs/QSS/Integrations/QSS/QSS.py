import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import json
import urllib3
import traceback
from typing import Any, cast

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """


DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_INCIDENTS_TO_FETCH = 50
QSS_SEVERITIES = ["Low", "Medium", "High", "Critical"]

""" CLIENT CLASS """


class Client(BaseClient):
    def search_alerts(
        self,
        alert_status: str | None,
        severity: str | None,
        max_results: int | None,
        start_time: int | None,
        api_key: str | None,
        false_positive: str | None,
    ) -> list[dict[str, Any]]:
        request_params: dict[str, Any] = {}

        if api_key:
            request_params["apikey"] = api_key

        if start_time:
            request_params["start_time"] = start_time

        if severity:
            request_params["severity"] = severity

        if alert_status:
            request_params["status"] = alert_status

        if max_results:
            request_params["max_fetch"] = max_results

        if false_positive:
            request_params["false_positive"] = false_positive

        demisto.debug(f"Command being called is {demisto.command()}")

        return self._http_request(method="GET", url_suffix="/rest/noauth/third_party/read_object/xsoar/v1", params=request_params)


""" HELPER FUNCTIONS """


def convert_to_demisto_severity(severity: str) -> int:
    return {
        "Low": 1,  # low severity
        "Medium": 2,  # medium severity
        "High": 3,  # high severity
        "Critical": 4,  # critical severity
    }[severity]


def test_module(client: Client, first_fetch_time: int, api_key: str) -> str:
    try:
        client.search_alerts(
            max_results=1, alert_status=None, severity=None, start_time=first_fetch_time, api_key=api_key, false_positive=None
        )
    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return "ok"


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: dict[str, int],
    first_fetch_time: int | None,
    alert_status: str | None,
    min_severity: str,
    api_key: str | None,
    false_positive: str | None,
) -> tuple[dict[str, int], list[dict]]:
    last_fetch = last_run.get("last_fetch", None)

    if last_fetch is None:
        last_fetch = first_fetch_time
    else:
        last_fetch = int(last_fetch)

    latest_created_time = cast(int, last_fetch)
    incidents: list[dict[str, Any]] = []
    alerts = client.search_alerts(
        alert_status=alert_status,
        max_results=max_results,
        start_time=last_fetch,
        severity=min_severity,
        false_positive=false_positive,
        api_key=api_key,
    )

    demisto.debug("Alerts Fetched")

    for alert in alerts:
        incident_created_time = int(alert.get("last_update_sec", "0"))

        if last_fetch:
            if incident_created_time <= last_fetch:
                continue

        incident_name = "SOC Case " + str(alert.get("reference"))

        demisto.debug("JSON debug alert")
        demisto.debug(json.dumps(alert))
        incident = {
            "name": incident_name,
            "occurred": alert.get("created"),
            "event_id": alert.get("id"),
            "rawJSON": json.dumps(alert),
            "severity": convert_to_demisto_severity(alert.get("severity", "Low")),
        }

        incidents.append(incident)

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {"last_fetch": latest_created_time}
    return next_run, incidents


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    base_url = urljoin(demisto.params()["url"], "")

    verify_certificate = not demisto.params().get("insecure", False)

    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get("first_fetch", "3 days"), arg_name="First fetch time", required=True
    )

    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)

    proxy = demisto.params().get("proxy", False)

    try:
        api_key = demisto.params().get("apikey")

        headers: dict[str, Any] = {
            # No need for headers in the current version of integration
        }
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client, first_fetch_timestamp, api_key)
            return_results(result)

        elif demisto.command() == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get("status")
            min_severity = demisto.params().get("severity")
            false_positive = demisto.params().get("false_positive")

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(arg=demisto.params().get("max_fetch"), arg_name="max_fetch", required=False)
            if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
                max_results = MAX_INCIDENTS_TO_FETCH

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=alert_status,
                min_severity=min_severity,
                api_key=api_key,
                false_positive=false_positive,
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to crate
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
