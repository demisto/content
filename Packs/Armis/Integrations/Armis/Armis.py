"""IMPORTS"""

from typing import List

import pytz
import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """


class AccessToken:
    def __init__(self, token: str, expiration: datetime):
        self._expiration = expiration
        self._token = token

    def __str__(self):
        return self._token

    @property
    def expired(self) -> bool:
        return self._expiration < datetime.now()


class Client(BaseClient):
    def __init__(self, secret: str, base_url: str, verify: bool, proxy):
        super().__init__(base_url, verify=verify, proxy=proxy)
        self._secret = secret
        self._token: AccessToken = AccessToken("", datetime.now())

    def _get_token(self, force_new: bool = False):
        """
        Returns an existing access token if a valid one is available and creates one if not
        Args:
            force_new (bool): create a new access token even if an existing one is available
        Returns:
            AccessToken: A valid Access Token to authorize requests
        """
        if self._token is None or force_new or self._token.expired:
            response = self._http_request("POST", "/access_token/", data={"secret_key": self._secret})
            token = response.get("data", {}).get("access_token")
            expiration = response.get("data", {}).get("expiration_utc")
            expiration_date = dateparser.parse(expiration)
            assert expiration_date is not None, f"failed parsing {expiration}"

            self._token = AccessToken(token, expiration_date)
        return self._token

    def search_by_aql_string(self, aql_string: str, order_by: str = None, max_results: int = None, page_from: int = None):
        """
        Search with an AQL string and return the results.
        This function exists to allow a more advanced search than is provided for
        by the basic search alerts and search devices functions
        Args:
            aql_string (str): The AQL String by which to search
            order_by (str): what attribute to order the results by (time, etc')
            max_results (int): The maximum number of results to return
            page_from (int): Start from this number result - skip this many results
        Returns:
            dict: A JSON containing a list of results represented by JSON objects
        """
        token = self._get_token()
        params = {"aql": aql_string}
        if order_by is not None:
            params["orderBy"] = order_by
        if max_results is not None:
            params["length"] = str(max_results)
        if page_from is not None:
            params["from"] = str(page_from)

        response = self._http_request(
            "GET", "/search/", params=params, headers={"accept": "application/json", "Authorization": str(token)}
        )
        if max_results is None:
            # if max results was not specified get all results.
            results: list = response.get("data", {}).get("results")
            while response.get("data", {}).get("next") is not None:
                # while the response says there are more results use the 'page from' parameter to get the next results
                params["from"] = str(len(results))
                response = self._http_request(
                    "GET", "/search/", params=params, headers={"accept": "application/json", "Authorization": str(token)}
                )
                results.extend(response.get("data", {}).get("results", []))

            response["data"]["results"] = results

        return response["data"]

    def search_alerts(
        self,
        severity: List[str] = None,
        status: List[str] = None,
        alert_type: List[str] = None,
        alert_id: str = None,
        time_frame: str = None,
        order_by: str = None,
        max_results: int = None,
        page_from: int = None,
    ):
        """
        Search Alerts based on commonly used parameters
        Args:
            severity (List[str]): The severities of Alerts to include
            status (List[str]): The statuses of Alerts to include
            alert_type (List[str]): The types of Alerts to include
            alert_id (str): The Id of a specific Alert to filter by
            time_frame (str): A time from for the creation of the Alerts
            order_by (str): Order results by this attribute
            max_results (int): The maximum number of results to return
            page_from (int): Start from this number result - skip this many results
        Returns:
            dict: A JSON containing a list of matching Alerts represented by JSON objects
        """
        time_frame = "3 Days" if time_frame is None else time_frame
        aql_string = ["in:alerts", f'timeFrame:"{time_frame}"']
        if severity:
            severity_string = ",".join([severity_option for severity_option in severity])
            aql_string.append(f"riskLevel:{severity_string}")
        if status:
            status_string = ",".join([status_option for status_option in status])
            aql_string.append(f"status:{status_string}")
        if alert_type:
            alert_string = ",".join([f'"{alert_option}"' for alert_option in alert_type])
            aql_string.append(f"type:{alert_string}")
        if alert_id:
            aql_string.append(f"alertId:({alert_id})")

        aql_string = " ".join(aql_string)  # type: ignore
        return self.search_by_aql_string(aql_string, order_by=order_by, max_results=max_results, page_from=page_from)  # type: ignore

    def free_string_search_alerts(self, aql_string: str, order_by: str = None, max_results: int = None, page_from: int = None):
        """
        Search Alerts using a custom AQL String
        Args:
            aql_string (str): The AQL String by which to search
            order_by (str): Order results by this attribute
            max_results (int): The maximum number of results to return
            page_from (int): Start from this number result - skip this many results
        Returns:
            dict: A JSON containing a list of matching Alerts represented by JSON objects
        """
        return self.search_by_aql_string(
            f"in:alerts {aql_string}", order_by=order_by, max_results=max_results, page_from=page_from
        )

    def update_alert_status(self, alert_id: str, status: str):
        """
        Update the status of an Alert
        Args:
            status (str): The new status of the Alert to set
            alert_id (str): The Id of the Alert
        """
        token = self._get_token()
        return self._http_request(
            "PATCH",
            f"/alerts/{alert_id}/",
            headers={
                "accept": "application/json",
                "Authorization": str(token),
                "content-type": "application/x-www-form-urlencoded",
            },
            data={"status": status},
        )

    def tag_device(self, device_id: str, tags: List[str]):
        """
        Add tags to a Device
        Args:
            tags (str): The tags to add to the Device
            device_id (str): The Id of the Device
        """
        token = self._get_token()
        return self._http_request(
            "POST",
            f"/devices/{device_id}/tags/",
            json_data={"tags": tags},
            headers={"accept": "application/json", "Authorization": str(token)},
        )

    def untag_device(self, device_id: str, tags: List[str]):
        """
        Remove tags from a Device
        Args:
            tags (List[str]): The tags to remove from the Device
            device_id (str): The Id of the Device
        """
        token = self._get_token()
        return self._http_request(
            "DELETE",
            f"/devices/{device_id}/tags/",
            json_data={"tags": tags},
            headers={"accept": "application/json", "Authorization": str(token)},
        )

    def search_devices(
        self,
        name: str = None,
        device_id: str = None,
        mac_address: str = None,
        risk_level: List[str] = None,
        ip_address: str = None,
        device_type: List[str] = None,
        time_frame: str = None,
        order_by: str = None,
        max_results: int = None,
    ):
        """
        Search Devices using commonly used search parameters
        Args:
            name (str): The name of the Device
            device_id (str): The Id of a Device
            mac_address (str): The MAC Address of the Device
            risk_level (List[str]): The risk level to filter by
            ip_address (str): the IP Address of the Device
            device_type (List[str]): The type of Device to filter by
            time_frame (str): A time frame to filter by
            order_by (str): Order results by this attribute
            max_results (int): The maximum number of results to return
        Returns:
            dict: A JSON containing a list of matching Devices represented by JSON objects
        """

        time_frame = "3 Days" if time_frame is None else time_frame
        aql_string = ["in:devices", f'timeFrame:"{time_frame}"']
        if name is not None:
            aql_string.append(f"name:({name})")
        if device_type is not None:
            type_string = ",".join([f'"{type_option}"' for type_option in device_type])
            aql_string.append(f"type:{type_string}")
        if mac_address is not None:
            aql_string.append(f"macAddress:({mac_address})")
        if ip_address is not None:
            aql_string.append(f"ipAddress:({ip_address})")
        if device_id is not None:
            aql_string.append(f"deviceId:({device_id})")
        if risk_level is not None:
            risk_level_string = ",".join([risk_level_option for risk_level_option in risk_level])
            aql_string.append(f"riskLevel:{risk_level_string}")

        aql_string = " ".join(aql_string)  # type: ignore
        return self.search_by_aql_string(aql_string, order_by=order_by, max_results=max_results)  # type: ignore

    def free_string_search_devices(self, aql_string: str, order_by: str = None, max_results: int = None):
        """
        Search Devices using commonly used search parameters
        Args:
            aql_string (str): The AQL Sgtring by which to search
            order_by (str): Order results by this attribute
            max_results (int): The maximum number of results to return
        Returns:
            dict: A JSON containing a list of matching Devices represented by JSON objects
        """
        return self.search_by_aql_string(f"in:devices {aql_string}", order_by=order_by, max_results=max_results)


def test_module(client: Client):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    This test works by using a Client instance to create a temporary access token using the provided secret key,
    thereby testing both the connection to the server and the validity of the secret key
    Args:
        client: Armis client
    Returns:
        'ok' if test passed, anything else will fail the test.
    """

    try:
        client._get_token(force_new=True)
        return "ok"
    except Exception as e:
        return f"Test failed with the following error: {repr(e)}"


def _ensure_timezone(date: datetime):
    """
    Some datetime objects are timezone naive and these cannot be compared to timezone aware datetime objects.
    This function sets a default timezone of UTC for any object without a timezone
    Args:
        date (datetime): The date object to add a timezone to
    Returns:
        datetime: A timezone aware datetime object
    """
    if date.tzinfo is None:
        return date.replace(tzinfo=pytz.UTC)
    return date


def _create_time_frame_string(last_fetch: datetime):
    """
    The function receives the last_fetch time and returns a string formatted to Armis' requirements
    Armis' smallest unit is seconds so the function rounds the result to seconds
    Args:
        last_fetch (datetime): The date object of the last fetch
    Returns:
        time_frame_string: An Armis' compatible time frame string based on the last_fetch time
    """
    current_time = _ensure_timezone(datetime.now())
    time_frame_seconds = round((current_time - last_fetch).total_seconds())
    time_frame_string = f"{time_frame_seconds} seconds"
    return time_frame_string


def fetch_incidents(
    client: Client,
    last_run: dict,
    first_fetch_time: str,
    minimum_severity: str,
    alert_type: List[str],
    alert_status: List[str],
    free_search_string: str,
    max_results: int,
):
    """
    This function will execute each interval (default is 1 minute).
    Args:
        client (Client): Armis client
        last_run (dict): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time
        minimum_severity (str): the minimum severity of alerts to fetch
        alert_type (List[str]): the type of alerts to fetch
        alert_status (List[str]): the status of alerts to fetch
        free_search_string (str): A custom search string for fetching alerts
        max_results: (int): The maximum number of alerts to fetch at once
    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get("last_fetch")
    latest_alert_fetch = last_run.get("latest_alert_fetch")
    if latest_alert_fetch:
        latest_alert_fetch_date = dateparser.parse(latest_alert_fetch)
        assert latest_alert_fetch_date is not None
        latest_alert_fetch = _ensure_timezone(latest_alert_fetch_date)
    incomplete_fetches = last_run.get("incomplete_fetches", 0)

    # Handle first time fetch
    if last_fetch:
        last_fetch_date = dateparser.parse(last_fetch)
        assert last_fetch_date is not None, f"failed parsing {last_fetch}"

        last_fetch = _ensure_timezone(last_fetch_date)
    else:
        last_fetch_time_date = dateparser.parse(first_fetch_time)
        assert last_fetch_time_date is not None
        last_fetch = _ensure_timezone(last_fetch_time_date)

    # use the last fetch time to build a time frame in which to search for alerts.
    time_frame = _create_time_frame_string(last_fetch)

    latest_created_time = _ensure_timezone(last_fetch)

    # get a list of severities from the minimum specified and upward
    # for example if min_severity is Medium requested_severities will be ['Medium', 'High']
    severities_in_order = ["Low", "Medium", "High"]
    requested_severities = severities_in_order[severities_in_order.index(minimum_severity) :]
    incidents = []

    # when the previous fetch returned more than max_results alerts, the same query is made again and max_results alerts
    # are skipped using the page_from parameter. in a case where multiple fetches were incomplete max_results times the
    # number of incomplete fetches must be skipped in order to prevent duplicating incidents
    page_from = max_results * incomplete_fetches or None
    if free_search_string:
        data = client.free_string_search_alerts(
            f"{free_search_string} timeFrame:{time_frame}", order_by="time", max_results=max_results, page_from=page_from
        )
    else:
        data = client.search_alerts(
            status=alert_status,
            severity=requested_severities,
            alert_type=alert_type,
            time_frame=time_frame,
            order_by="time",
            max_results=max_results,
            page_from=page_from,
        )

    for alert in data.get("results", []):
        time_date = dateparser.parse(alert.get("time"))
        assert time_date is not None
        incident_created_time = _ensure_timezone(time_date)

        # Alert was already fetched. Skipping
        if latest_alert_fetch and latest_alert_fetch >= incident_created_time:
            continue

        incident = {
            "name": alert.get("description"),
            "occurred": incident_created_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "rawJSON": json.dumps(alert),
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch

        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    latest_alert_fetch_iso_format = latest_created_time.isoformat()
    if data.get("next"):
        # if more than max_results alerts were returned, this fetch is incomplete and the extra results must be fetched
        # next time
        next_run = {
            "last_fetch": last_fetch.isoformat(),
            "incomplete_fetches": incomplete_fetches + 1,
            "latest_alert_fetch": latest_alert_fetch_iso_format,
        }
    else:
        next_run = {
            "last_fetch": latest_alert_fetch_iso_format,
            "incomplete_fetches": 0,
            "latest_alert_fetch": latest_alert_fetch_iso_format,
        }
    return next_run, incidents


def untag_device_command(client: Client, args: dict):
    """
    armis-untag-device command: Remove tags from a Device
    Args:
        client (Client): An Armis client object
        args (dict): A dict object containing the arguments for this command
    """

    device_id = str(args.get("device_id"))
    tags = argToList(args.get("tags"))
    client.untag_device(device_id, tags)
    return f"Successfully Untagged device: {device_id} with tags: {tags}"


def tag_device_command(client: Client, args: dict):
    """
    armis-tag-device command: Add the given tags to a device
    Args:
        client (Client): An Armis client object
        args (dict): A dict object containing the arguments for this command
    """
    device_id = str(args.get("device_id"))
    tags = argToList(args.get("tags"))
    client.tag_device(device_id, tags)
    return f"Successfully Tagged device: {device_id} with tags: {tags}"


def update_alert_status_command(client: Client, args: dict):
    """
    armis-update-alert-status command: Update the status of an Alert to the given status
    Args:
        client (Client): An Armis client object
        args (dict): A dict object containing the arguments for this command
    """
    alert_id = str(args.get("alert_id"))
    status = str(args.get("status"))
    client.update_alert_status(alert_id, status)
    return f"Successfully Updated Alert: {alert_id} to status: {status}"


def search_alerts_command(client: Client, args: dict):
    """
    armis-search-alerts command: Returns results for searching Alerts by common parameters
    Args:
        client (Client): An Armis client object
        args (dict): A dict object containing the arguments for this command
    Returns:
        CommandResults: A CommandResults object containing the matching alerts
    """
    severity = args.get("severity")
    if severity is not None:
        severity = argToList(severity)

    status = args.get("status")
    if status is not None:
        status = argToList(status)

    alert_type = args.get("alert_type")
    if alert_type is not None:
        alert_type = argToList(alert_type)

    alert_id = args.get("alert_id")
    max_results = int(args.get("max_results", 50))
    time_frame = args.get("time_frame")

    response = client.search_alerts(severity, status, alert_type, alert_id, time_frame, max_results=max_results)
    results = response.get("results")
    if results:
        return CommandResults(
            outputs_prefix="Armis.Alert",
            outputs_key_field="alertId",
            outputs=results,
            raw_response=response,
            readable_output=tableToMarkdown(
                "Alerts",
                results,
                headers=[
                    "severity",
                    "type",
                    "time",
                    "status",
                    "title",
                    "description",
                    "activityIds",
                    "activityUUIDs",
                    "alertId",
                    "connectionIds",
                    "deviceIds",
                ],
                removeNull=True,
                headerTransform=pascalToSpace,
            ),
        )
    return "No results found"


def search_devices_command(client: Client, args: dict):
    """
    armis-search-devices command: Returns results for searching Devices by common parameters
    Args:
        client (Client): An Armis client object
        args (dict): A dict object containing the arguments for this command
    """
    risk_level = args.get("risk_level")
    if risk_level is not None:
        risk_level = argToList(risk_level)

    device_type = args.get("device_type")
    if device_type is not None:
        device_type = argToList(device_type)

    name = args.get("name")
    device_id = args.get("device_id")
    mac_address = args.get("mac_address")
    ip_address = args.get("ip_address")
    time_frame = args.get("time_frame")
    max_results = int(args.get("max_results", 50))

    response = client.search_devices(
        name, device_id, mac_address, risk_level, ip_address, device_type, time_frame, max_results=max_results
    )
    results = response.get("results")
    if results:
        headers = [
            "riskLevel",
            "id",
            "name",
            "type",
            "ipAddress",
            "ipv6",
            "macAddress",
            "operatingSystem",
            "operatingSystemVersion",
            "manufacturer",
            "model",
            "tags",
            "user",
        ]
        return CommandResults(
            outputs_prefix="Armis.Device",
            outputs_key_field="deviceId",
            outputs=results,
            raw_response=response,
            readable_output=tableToMarkdown("Devices", results, headers=headers, removeNull=True, headerTransform=pascalToSpace),
        )
    return "No devices found"


def search_devices_by_aql_command(client: Client, args: dict):
    """
    armis-search-devices-by-aql command: Returns results for searching Devices using a free AQL string
    Args:
        client (Client): An Armis client object
        args (dict): A dict object containing the arguments for this command
    """
    aql_string = str(args.get("aql_string"))
    max_results = int(args.get("max_results", 50))

    response = client.free_string_search_devices(aql_string, max_results=max_results)
    results = response.get("results")
    if results:
        headers = [
            "riskLevel",
            "name",
            "type",
            "ipAddress",
            "tags",
            "user",
            "id",
        ]
        return CommandResults(
            outputs_prefix="Armis.Device",
            outputs_key_field="deviceId",
            outputs=results,
            raw_response=response,
            readable_output=tableToMarkdown("Devices", results, headers=headers, removeNull=True, headerTransform=pascalToSpace),
        )
    return "No devices found"


def search_alerts_by_aql_command(client: Client, args: dict):
    """
    armis-search-alerts-by-aql command: Returns results for searching Alerts using a free AQL string
     Args:
         client (Client): An Armis client object
         args (dict): A dict object containing the arguments for this command
    """
    aql_string = str(args.get("aql_string"))
    max_results = int(args.get("max_results", 50))

    response = client.free_string_search_alerts(aql_string, max_results=max_results)
    results = response.get("results")
    if results:
        return CommandResults(
            outputs_prefix="Armis.Alert",
            outputs_key_field="alertId",
            outputs=results,
            raw_response=response,
            readable_output=tableToMarkdown(
                "Alerts",
                results,
                headers=[
                    "alertId",
                    "description",
                    "type",
                    "title",
                    "severity",
                    "status",
                    "time",
                    "activityIds",
                    "activityUUIDs",
                    "connectionIds",
                    "deviceIds",
                ],
                removeNull=True,
                headerTransform=pascalToSpace,
            ),
        )
    return "No alerts found"


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    secret = params.get("secret")

    # get the service API url
    base_url = params.get("url")
    if "api/v1" not in base_url:
        base_url = urljoin(base_url, "/api/v1/")
    verify = not params.get("insecure", False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = params.get("fetch_time", "3 days").strip()

    proxy = params.get("proxy", False)

    demisto.info(f"Command being called is {command}")
    try:
        client = Client(secret, base_url=base_url, verify=verify, proxy=proxy)

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == "fetch-incidents":
            minimum_severity = params.get("min_severity")
            alert_status = params.get("alert_status")
            alert_type = params.get("alert_type")
            free_search_string = params.get("free_fetch_string")

            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time,
                alert_type=alert_type,
                alert_status=alert_status,
                minimum_severity=minimum_severity,
                free_search_string=free_search_string,
                max_results=int(params.get("max_fetch")),
            )

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == "armis-search-alerts":
            return_results(search_alerts_command(client, args))

        elif command == "armis-update-alert-status":
            return_results(update_alert_status_command(client, args))

        elif command == "armis-tag-device":
            return_results(tag_device_command(client, args))

        elif command == "armis-untag-device":
            return_results(untag_device_command(client, args))

        elif command == "armis-search-devices":
            return_results(search_devices_command(client, args))

        elif command == "armis-search-devices-by-aql":
            return_results(search_devices_by_aql_command(client, args))

        elif command == "armis-search-alerts-by-aql-string":
            return_results(search_alerts_by_aql_command(client, args))

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
