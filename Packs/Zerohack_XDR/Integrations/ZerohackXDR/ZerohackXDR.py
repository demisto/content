import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from typing import cast
import urllib3
import json
from datetime import datetime
import math


# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

# These severities go from info to high. (Reverse of Cortex severities notation.)
ZEROHACK_SEVERITIES = ["4", "3", "2", "1"]
ZEROHACK_XDR_API_BASE_URL = "https://xdr.zerohack.in/api"
MAX_INCIDENTS_TO_FETCH = 200
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


""" CLIENT CLASS """


class Client(BaseClient):
    """
    This class is responsible for dealing with the XDR api.
    It performs all the fetching related commands andensure proper pre processing ebfore forward events.
    """

    def __init__(
        self,
        api_key: Optional[str],
        base_url: Optional[str],
        proxy: Optional[bool],
        verify: Optional[bool],
    ):
        """
        This function initializes the connection with the API server by collecting curcial information from the users.
        """

        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key
        if self.api_key:
            self._headers = {"Key": self.api_key}

    def get_alerts(
        self,
        severity_level: Optional[str] = None,
        max_results: Optional[int] = None,
        offset: Optional[int] = None,
        start_time: int = None,
    ):
        """
        This function is responsible for fetching all the alerts from the zerohack XDR between given timestamps.
        it takes various inputs and formats the request parameters for macthing the XDR api format.

        :param severity_level: This variable sets the severity level to fetch alerts from the XDR.
        :type severity_level: ``Optional[str]``

        :return: A dictionary containing XDR response.
        :rtype: ``Dict[str, Any]``
        """
        # Setting request parameters.
        request_params: Dict[str, Any] = {}
        if offset:
            request_params["offset"] = offset
        if max_results:
            request_params["limit"] = max_results
        if start_time:
            request_params["start_date"] = cast(str, start_time)
        request_params["severity"] = severity_level
        request_params["order_by"] = "asc"
        # Querying the alerts and appending them to a list.
        return self._http_request(
            method="GET", url_suffix="/xdr-api", params=request_params
        )

    def get_alert(
        self,
        severity_level: Optional[str] = None,
        max_results: Optional[int] = None,
        offset: Optional[int] = None,
        start_time: Optional[str] = None,
    ):
        """
        This function can be used to retrieve a singular incident for a severity level.

        :return: A single function containing a XDR event of specified severity.
        :rtype: ``Dict[str, Any]``
        """
        max_results = 1
        # Setting request parameters.
        request_params: Dict[str, Any] = {}
        if offset:
            request_params["offset"] = offset
        if max_results:
            request_params["limit"] = max_results
        if start_time:
            request_params["start_date"] = start_time

        request_params["severity"] = severity_level
        request_params["order_by"] = "asc"
        response = self._http_request(
            method="GET", url_suffix="/xdr-api", params=request_params
        )
        return response

    def test_connection(self):
        """
        This is a special connection function designed to test if the connection is made and working correctly.
        This function is activated when you call the module Test function.

        :return: A list containing a single XDR event.
        :rtype: ``List[Dict[str, Any]]``
        """

        request_params: Dict[str, Any] = {}
        offset = 0
        max_results = "1"

        request_params["offset"] = offset
        if max_results:
            request_params["limit"] = max_results

        return self._http_request(
            method="GET", url_suffix="/xdr-api", params=request_params
        )


""" HELPER FUNCTIONS """


def convert_to_demisto_severity(severity: str):
    """
    This function is designed to convert the Zerohack XDR severity to Cortex severity levels.

    :param severity: The severity level to be converted into
    :type severity: ``str``

    :return converted_severity: The converted severiy level to cortex format.
    :rtype: ``int``
    """

    zerohack_severity = str(severity)

    converted_severity = {
        "4.0": IncidentSeverity.INFO,
        "3.0": IncidentSeverity.MEDIUM,
        "2.0": IncidentSeverity.HIGH,
        "1.0": IncidentSeverity.CRITICAL,
    }[zerohack_severity]
    return converted_severity


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    This function tests if the connection with the API is working correctly.

    :param client: The client object to use for connection.
    :type client: ``Client``
    """

    try:
        client.test_connection()

    except DemistoException as e:
        if "Forbidden" in str(e):
            return "Authorization Error: make sure API Key is correctly set"
        else:
            raise e

    return "ok"


def fetch_incidents(
    client: Client,
    max_results: int,
    last_run: Dict[str, int],
    first_fetch: str,
    min_severity: str,
):
    """
    This function continously fetches incidents from the Zerohack XDR api.

    :param client: The client object to use for connection.
    :type client: ``Client``

    :param max_results: Maximum amount of results to fetch from the API per severity level.
    :type max_results: ``int``

    :param last_run: This parameter contains the details about last time this integration was run.
    :type last_run: ``Dict[str, int]``

    :param first_fetch_time: This parameter contains the time from when to fetch incidents details in case last run is not setup.
    :type first_fetch_time: ``str``

    :param min_severity: This is minimum level of the severity you want to query the zerohack XDR for.
    :type min_severity: ``int``

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR.

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # A dictionary to store last fetch values for each severity.
    next_run = {}
    # Sorting the severity levels and creating a list.
    severity_levels = ZEROHACK_SEVERITIES[ZEROHACK_SEVERITIES.index(min_severity):]
    severity_levels.sort()
    # Initializating the incidents dictionary and setting the severity levels.
    incidents: List[Dict[str, Any]] = []

    for severity in severity_levels:
        # Get the last fetch time for each severity and if it fails then use the first fetch time.
        last_fetch = last_run.get(f"last_fetch_severity_{severity}", None)
        if last_fetch is None:
            # We know that the first_fetch can never be None.
            first_fetch_timestamp = arg_to_datetime(first_fetch)
            # Assert if argument parsing has not resulted in None.
            if first_fetch_timestamp is not None:
                last_fetch = cast(int, first_fetch_timestamp.timestamp())
        else:
            last_fetch = cast(int, last_fetch)

        # Set the last incident time for this severity and start the calculations.
        last_incident_time = cast(int, last_fetch)
        last_fetch_timestamp = cast(int, datetime.fromtimestamp(cast(float, last_fetch)))
        # Calculate the required results from this severity level.
        required_results = math.floor(max_results / len(severity_levels))

        # Fetch the response from the API.
        response = client.get_alerts(
            max_results=required_results,
            severity_level=severity,
            start_time=last_fetch_timestamp,
        )
        response_status = response.get("message_type")
        if response_status != "d_not_f":
            response_data = response.get("data")
            for alert in response_data:
                attack_time = datetime.strptime(
                    alert.get("attack_timestamp", "0"), DATE_FORMAT
                )
                incident_created_time = int(
                    (attack_time - datetime(1970, 1, 1)).total_seconds()
                )
                if last_fetch is not None:
                    if incident_created_time > last_fetch:
                        incident_name = "Zerohack XDR " + alert["ids_threat_class"]
                        incident = {
                            "name": incident_name,
                            "occurred": timestamp_to_datestring(incident_created_time),
                            "type": alert["ids_threat_class"],
                            "movement_type": alert["type_of_threat"],
                            "platform": alert["platform"],
                            "attacker_rep": alert["ip_rep"],
                            "rawJSON": json.dumps(alert),
                            "severity": convert_to_demisto_severity(
                                alert.get("ids_threat_severity", "Low")
                            ),
                        }
                        demisto.debug(incident)
                        incidents.append(incident)
                        last_incident_time = incident_created_time

        # Based on the findings update the last fetch dictionary.
        if last_fetch == last_incident_time:
            demisto.debug(f"Couldnt find new incidents with {last_fetch}. Updating.")
            last_incident_time = last_incident_time + 1
            next_run[f"last_fetch_severity_{severity}"] = last_incident_time
        else:
            next_run[f"last_fetch_severity_{severity}"] = last_incident_time

    return next_run, incidents


def get_latest_incident(client: Client, severity_level: str):
    """
    This function is responsible for fetching a single sample incident for study/inspection purposes by the analyser
    or the SOAR handler.
    It can be run in playground and it gives output in readable format so you can evaluate the incident format.

    :param client: The client object to use for connection.
    :type client: ``Client``

    :param severity_level: This is the level of the severity you want to query the zerohack XDR for.
    :type severity_level: ``int``

    :return incident: List of incidents that will be created in XSOAR.
    :rtype: ``List[dict]``
    """

    # Hard coding thge max results as we only need to send the latest output.
    max_results = 1
    alert = client.get_alert(
        severity_level=severity_level, max_results=max_results, offset=0
    )
    incident_data = alert["data"][0]
    incident_name = "Zerohack XDR " + incident_data["ids_threat_class"]
    incident = {
        "name": incident_name,
        "occurred": incident_data["attack_timestamp"],
        "type": incident_data["ids_threat_class"],
        "movement_type": incident_data["type_of_threat"],
        "platform": incident_data["platform"],
        "attacker_rep": incident_data["ip_rep"],
        "rawJSON": json.dumps(str(incident_data)),
        "severity": convert_to_demisto_severity(
            incident_data.get("ids_threat_severity", "Low")
        ),
    }

    return incident


""" MAIN FUNCTION """


def main():
    """
    This function is the main control function.
    It is responsible for handling the core control logic of the XDR integration.
    This component handles the command input and fetching control.
    Apart from command control it alkso handles the inputs from the integration settings.
    """

    # Collecting details for initializing the connection.
    api_key = demisto.params().get("apikey")
    base_url = ZEROHACK_XDR_API_BASE_URL
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"The command initiated is: {demisto.command()}")
    try:
        client = Client(
            api_key=api_key, base_url=base_url, verify=verify_certificate, proxy=proxy
        )

        # Integration test command.
        if demisto.command() == "test-module":
            result = test_module(client)
            return_results(result)

        # Incident continous fetch command.
        elif demisto.command() == "fetch-incidents":
            # Getting parameters and checking if they conflict with defaults.
            min_severity = demisto.params().get("min_severity", None)
            max_results = arg_to_number(
                arg=demisto.params().get("max_fetch"),
                arg_name="max_fetch",
                required=False,
            )
            # Make sure first fetch can never be None.
            first_fetch = demisto.params().get("first_fetch", "1 day")

            if (not max_results) or (max_results > MAX_INCIDENTS_TO_FETCH):
                max_results = MAX_INCIDENTS_TO_FETCH

            # Calling the fetch incidents command.
            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                min_severity=min_severity,
            )

            # Setting the last fetch timestamp.
            demisto.setLastRun(next_run)

            # Inserting the incidents.
            if incidents != []:
                demisto.incidents(incidents)
            else:
                demisto.incidents([])

        # Retrieve a sample incident of determined severity level.
        elif demisto.command() == "zerohack-get-latest-incident":
            arguments = demisto.args()
            severity_level = arguments["severity_level"]
            incident = get_latest_incident(client=client, severity_level=severity_level)
            demisto.incidents(incident)

    # Log exceptions and return errors
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}"
        )


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
