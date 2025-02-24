import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

import json
import urllib3
import dateparser  # type: ignore
from typing import Any, cast
from datetime import datetime
import re
import pytz  # type: ignore

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
INTERVAL_SECONDS_EVENTS = 1
TIMEOUT_EVENTS = 30
INCIDENT_TYPE_NAME = "Sekoia XDR"
SEKOIA_INCIDENT_FIELDS = {
    "short_id": "The ID of the alert to edit",
    "status": "The name of the status.",
}

STATUS_TRANSITIONS = {
    "Ongoing": "Validate",
    "Acknowledged": "Acknowledge",
    "Rejected": "Reject",
    "Closed": "Close",
}

MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": None,
    "Incoming and Outgoing": "In",
}


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API"""

    def get_validate_resource(self) -> str:
        """
        Request Sekoia.io to validate the API Key
        """
        try:
            self._http_request(
                method="GET",
                url_suffix="/v1/auth/validate",
                raise_on_status=True,
            )
            return "ok"
        except DemistoException as e:
            raise DemistoException(f"Integration error: the request failed due to: {e}")

    def list_alerts(
        self,
        alerts_limit: int | None,
        alerts_status: str | None,
        alerts_created_at: str | None,
        alerts_updated_at: str | None,
        alerts_urgency: str | None,
        alerts_type: str | None,
        sort_by: str | None,
    ) -> dict[str, Any]:
        request_params: dict[str, Any] = {}

        """ Normal parameters"""
        if alerts_limit:
            request_params["limit"] = alerts_limit

        """ Matching parameters"""
        if alerts_status:
            request_params["match[status_name]"] = alerts_status
        if alerts_created_at:
            request_params["date[created_at]"] = alerts_created_at
        if alerts_updated_at:
            request_params["date[updated_at]"] = alerts_updated_at
        if alerts_urgency:
            request_params["range[urgency]"] = alerts_urgency
        if alerts_type:
            request_params["match[type_value]"] = alerts_type

        """ Sorting parameters"""
        if sort_by:
            request_params["sort"] = sort_by

        return self._http_request(
            method="GET", url_suffix="/v1/sic/alerts", params=request_params
        )

    def get_alert(self, alert_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET", url_suffix=f"/v1/sic/alerts/{alert_uuid}"
        )

    def update_status_alert(
        self, alert_uuid: str, action_uuid: str, comment: str | None
    ) -> dict[str, Any]:
        request_params: dict[str, Any] = {"action_uuid": action_uuid}

        """ Normal parameters"""
        if comment:
            request_params["comment"] = comment

        return self._http_request(
            method="PATCH",
            url_suffix=f"/v1/sic/alerts/{alert_uuid}/workflow",
            json_data=request_params,
        )

    def post_comment_alert(
        self, alert_uuid: str, content: str, author: str | None
    ) -> dict[str, Any]:
        request_params: dict[str, Any] = {"content": content}

        """ Normal parameters"""
        if author:
            request_params["author"] = author

        return self._http_request(
            method="POST",
            url_suffix=f"/v1/sic/alerts/{alert_uuid}/comments",
            json_data=request_params,
        )

    def get_comments_alert(self, alert_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/v1/sic/alerts/{alert_uuid}/comments",
        )

    def get_workflow_alert(self, alert_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/v1/sic/alerts/{alert_uuid}/workflow",
        )

    def query_events(
        self,
        events_earliest_time: str,
        events_latest_time: str,
        events_term: str,
        max_last_events: str | None,
    ) -> dict[str, Any]:
        request_params: dict[str, Any] = {
            "earliest_time": events_earliest_time,
            "latest_time": events_latest_time,
            "term": events_term,
        }

        """ Normal parameters"""
        if max_last_events:
            request_params["max_last_events"] = max_last_events

        return self._http_request(
            method="POST",
            url_suffix="/v1/sic/conf/events/search/jobs",
            json_data=request_params,
        )

    def query_events_status(self, event_search_job_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/v1/sic/conf/events/search/jobs/{event_search_job_uuid}",
        )

    def retrieve_events(self, event_search_job_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/v1/sic/conf/events/search/jobs/{event_search_job_uuid}/events",
        )

    def get_cases_alert(self, alert_uuid: str, case_id: str | None) -> dict[str, Any]:
        request_params: dict[str, Any] = {"match[alert_uuid]": alert_uuid}

        """ Matching parameters"""
        if case_id:
            request_params["match[short_id]"] = case_id

        return self._http_request(
            method="GET", url_suffix="v1/sic/cases", params=request_params
        )

    def get_asset(self, asset_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET",
            url_suffix=f"/v1/asset-management/assets/{asset_uuid}",
        )

    def list_asset(self, limit: str | None, assets_type: str | None) -> dict[str, Any]:
        request_params: dict[str, Any] = {}

        """ Normal parameters"""
        if limit:
            request_params["limit"] = limit

        """ Matching parameters"""
        if assets_type:
            request_params["match[type_name]"] = assets_type

        return self._http_request(
            method="GET",
            url_suffix="/v1/asset-management/assets",
            params=request_params,
        )

    def add_attributes_asset(
        self, asset_uuid: str, name: str, value: str
    ) -> dict[str, Any]:
        request_params: dict[str, Any] = {"name": name, "value": value}

        return self._http_request(
            method="POST",
            url_suffix=f"/v1/asset-management/assets/{asset_uuid}/attr",
            params=request_params,
        )

    def add_keys_asset(self, asset_uuid: str, name: str, value: str) -> dict[str, Any]:
        request_params: dict[str, Any] = {"name": name, "value": value}

        return self._http_request(
            method="POST",
            url_suffix=f"/v1/asset-management/assets/{asset_uuid}/keys",
            params=request_params,
        )

    def remove_attribute_asset(
        self, asset_uuid: str, attribute_uuid: str
    ) -> list[dict[str, Any]]:
        return self._http_request(
            method="DELETE",
            url_suffix=f"/v1/asset-management/assets/{asset_uuid}/attr/{attribute_uuid}",
            resp_type="text",
        )

    def remove_key_asset(self, asset_uuid: str, key_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="DELETE",
            url_suffix=f"/v1/asset-management/assets/{asset_uuid}/keys/{key_uuid}",
            resp_type="text",
        )

    def get_user(self, user_uuid: str) -> dict[str, Any]:
        return self._http_request(method="GET", url_suffix=f"/v1/users/{user_uuid}")

    def get_kill_chain(self, kill_chain_uuid: str) -> dict[str, Any]:
        return self._http_request(
            method="GET", url_suffix=f"/v1/sic/kill-chains/{kill_chain_uuid}"
        )

    def http_request(
        self, method: str, url_suffix: str, params: dict
    ) -> dict[str, Any]:
        if not params:
            params = {}

        return self._http_request(method=method, url_suffix=url_suffix, params=params)


""" HELPER FUNCTIONS """


def arg_to_timestamp(arg: Any, arg_name: str, required: bool = False) -> int:
    """
    Converts an XSOAR argument to a timestamp (seconds from epoch).
    This function is used to quickly validate an argument provided to XSOAR
    via ``demisto.args()`` into an ``int`` containing a timestamp (seconds
    since epoch). It will throw a ValueError if the input is invalid.
    If the input is None, it will throw a ValueError if required is ``True``,
    or ``None`` if required is ``False``.

    Args:
        arg: argument to convert
        arg_name: argument name.
        required: throws exception if ``True`` and argument provided is None

    Returns:
        returns an ``int`` containing a timestamp (seconds from epoch) if conversion works
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    """
    if arg is None and required is True:
        raise ValueError(f'Missing "{arg_name}"')

    if (isinstance(arg, str) and arg.isdigit()) or isinstance(arg, int | float):
        # timestamp is a str containing digits - we just convert it to int
        # or convert to int if the input is a float
        return int(arg)
    if isinstance(arg, str):
        # we use dateparser to handle strings either in ISO8601 format, or
        # relative time stamps.
        # For example: format 2019-10-23T00:00:00 or "3 days", etc
        date = dateparser.parse(arg, settings={"TIMEZONE": "UTC"})
        if date is None:
            # if d is None it means dateparser failed to parse it
            raise ValueError(f"Invalid date: {arg_name}")

        return int(date.timestamp())
    raise ValueError(f'Invalid date: "{arg_name}"')


def timezone_format(epoch: int) -> str:
    """
    Converts an epoch timestamp into a formatted date in
    a specific timezone defined in the integration parameter.

    Args:
        epoch: argument to convert in epoch format

    Returns:
        returns an ``str`` containing a formatted datestring in the timezone selected
    """
    utc_datetime = datetime.utcfromtimestamp(epoch)
    timezone = demisto.params().get("timezone", "UTC")
    timezoneFormat = pytz.timezone(timezone)
    format_datetime = utc_datetime.astimezone(timezoneFormat)
    return format_datetime.strftime("%Y-%m-%dT%H:%M:%S")


def time_converter(time):
    """
    Converts a given time string to a datetime object.

    Args:
        time (str): The time string to be converted.

    Returns:
        datetime: The converted datetime object.

    Raises:
        ValueError: If the time string is in an invalid format.
    """

    # Regular expression patterns
    iso_8601_pattern = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
    )
    unix_timestamp_pattern = re.compile(r"^\d+$")

    if iso_8601_pattern.match(time):
        update_time = datetime.fromisoformat(time)
    elif unix_timestamp_pattern.match(time):
        update_time = datetime.fromtimestamp(int(time), pytz.utc)
    else:
        raise ValueError("Invalid time format")

    return update_time.strftime(DATE_FORMAT)


def convert_to_demisto_severity(severity: str) -> int:
    """
    Maps Sekoia XDR urgency to Cortex XSOAR severity.
    Converts the Sekoia XDR alert urgency level ('Low','Moderate','High','Major','Urgent') to Cortex XSOAR incident
    severity (1 to 4).

    Args:
        urgency (str): urgency display text as returned from the Sekoia XDR API.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """

    return {
        "Low": IncidentSeverity.LOW,
        "Moderate": IncidentSeverity.MEDIUM,
        "High": IncidentSeverity.HIGH,
        "Major": IncidentSeverity.HIGH,
        "Urgent": IncidentSeverity.CRITICAL,
    }[severity]


def exclude_info_events(event_info: dict, exclude_info: str) -> list:
    """
    Exclude information from the events.
    This function will exclude information from the events that is duplicated or not needed.

    Args:
        event_info (dict): JSON to be transformed removing some of the information.
        exclude_info (str): the event fields to be removed from the results.

    Returns:
        dict: JSON transformed with the information removed.
    """
    splitted_exclude_info = exclude_info.split(",")

    """ Exclude headers from the readable output """
    headers = list(event_info["items"][0].keys())
    for header in splitted_exclude_info:
        if header in headers:
            headers.remove(header)
    return headers


def undot(json_data: dict) -> str:
    """
    Remove/Replace dots from the key names of a JSON.
    This function transform the name of the JSON keys that contain "dots" to make it easier to reference them in XSOAR.

    Args:
        json_data (dict): JSON to be transformed.

    Returns:
        dict: JSON with the key names that contain "dots" transformed.
    """
    replace_symbol = demisto.params().get("replace_dots_event", "_")

    if isinstance(json_data, str):
        data = json.loads(json_data)
    elif isinstance(json_data, dict):
        data = json_data
    else:
        raise TypeError(
            "JSON data sent to undot function must be a string or a dictionary"
        )

    # Iterate over each item in the items array
    for item in data["items"]:
        # Replace dots with underscores in each key
        for key in list(item.keys()):
            new_key = key.replace(".", replace_symbol)
            if new_key != key:
                item[new_key] = item.pop(key)
    # Convert back to JSON and return it
    return json.dumps(data)


def filter_list_by_keys(dicts_list: list, keys_to_keep: list) -> list:
    """
    Filters a list of dictionaries by keeping only the specified keys.

    Args:
        dicts_list (list): A list of dictionaries.
        keys_to_keep (list): A list of keys to keep in the dictionaries.

    Returns:
        list: A new list of dictionaries with only the specified keys.
    """
    filtered_list = []
    for d in dicts_list:
        filtered_dict = {key: value for key, value in d.items() if key in keys_to_keep}
        filtered_list.append(filtered_dict)
    return filtered_list


def filter_dict_by_keys(input_dict: dict, keys_to_keep: list) -> dict:
    """
    Filters a dictionary by keeping only the key-value pairs whose keys are present in the given list.

    Args:
        input_dict (dict): The dictionary to filter.
        keys_to_keep (list): The list of keys to keep in the filtered dictionary.

    Returns:
        dict: The filtered dictionary containing only the key-value pairs whose keys are present in the keys_to_keep list.
    """
    return {key: value for key, value in input_dict.items() if key in keys_to_keep}


""" COMMAND FUNCTIONS """


def fetch_incidents(
    client: Client,
    max_results: int | None,
    last_run: dict[str, int],
    first_fetch_time: int | None,
    alert_status: str | None,
    alert_urgency: str | None,
    alert_type: str | None,
    fetch_mode: str | None,
    mirror_direction: str | None,
    fetch_with_assets: bool | None,
    fetch_with_kill_chain: bool | None,
) -> tuple[dict[str, int], list[dict]]:
    """
    This function retrieves new alerts every interval (default is 1 minute).
    It has to implement the logic of making sure that incidents are fetched only onces and no incidents are missed.
    By default it's invoked by XSOAR every minute. It will use last_run to save the timestamp of the last incident it
    processed. If last_run is not provided, it should use the integration parameter first_fetch_time to determine when
    to start fetching the first time.

    Args:
        client (Client): Sekoia XDR client to use.
        max_results (int): Maximum numbers of incidents per fetch.
        last_run (dict): A dict with a key containing the latest incident created time we got from last fetch.
        first_fetch_time(int): If last_run is None (first time we are fetching), it contains the timestamp in
            milliseconds on when to start fetching incidents.
        alert_status (str): status of the alert to search for.
        alert_urgency (str): alert urgency range to search for. Format: "MIN_urgency,MAX_urgency". i.e: 80,100.
        alert_type (str): type of alerts to search for.
        fetch_mode (str): If the alert will be fetched with or without the events.
        mirror_direction (str): The direction of the mirroring can be set to None or to Incoming.
        fetch_with_assets (bool): If the alert will include the assets information on the fetching.
        fetch_with_kill_chain (bool): If the alert will include the kill chain information on the fetching.
    Returns:
        dict: Next run dictionary containing the timestamp that will be used in ``last_run`` on the next fetch.
        list: List of incidents that will be created in XSOAR.
    """
    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get("last_fetch")

    # The case where no last_fetch or first_fetch_time are present.
    if last_fetch is None and first_fetch_time is None:
        raise DemistoException(
            "Failure to fetch incidents. Can't find neither \
            last_fetch and first_fetch_time"
        )
    # Handle first fetch time
    elif last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # Convert time from epoch to ISO8601 in the correct format and add the ,now also
    alerts_created_at = f"{time_converter(str(last_fetch))},now"

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []
    alerts = client.list_alerts(
        alerts_limit=max_results,
        alerts_status=alert_status,
        alerts_created_at=alerts_created_at,
        alerts_updated_at=None,
        alerts_urgency=alert_urgency,
        alerts_type=alert_type,
        sort_by="created_at",
    )

    for alert in alerts["items"]:
        # If no created_time set is as epoch (0). We use time in ms so we must
        # convert it from the Sekoia XDR API response
        incident_created_time = int(alert.get("created_at", "0"))
        incident_created_time_ms = incident_created_time * 1000

        # to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if last_fetch and incident_created_time <= last_fetch:
            continue

        # If no name is present it will throw an exception
        incident_name = alert["title"]
        urgency = alert["urgency"]

        if fetch_mode == "Fetch With All Events":
            # Add the events to the alert
            earliest_time = alert["first_seen_at"]
            lastest_time = "now"
            term = f"alert_short_ids:{alert['short_id']}"
            interval_in_seconds = INTERVAL_SECONDS_EVENTS
            timeout_in_seconds = TIMEOUT_EVENTS

            # Add the events to the alert
            args = {
                "earliest_time": earliest_time,
                "lastest_time": lastest_time,
                "query": term,
                "interval_in_seconds": interval_in_seconds,
                "timeout_in_seconds": timeout_in_seconds,
            }
            events = search_events_command(args=args, client=client)
            alert["events"] = events.outputs  # pylint: disable=E1101

        if fetch_with_assets:
            # Add assets information to the alert
            asset_list = []
            for asset in alert["assets"]:
                try:
                    asset_info = client.get_asset(asset_uuid=asset)
                    asset_list.append(asset_info)
                except Exception as e:
                    # Handle the exception if there is any problem with the API call
                    demisto.debug(f"Error fetching asset {asset}: {e}")
                    # Continue with the next asset
                    continue
            alert["assets"] = asset_list

        if fetch_with_kill_chain and alert["kill_chain_short_id"]:
            # Add kill chain information to the alert
            try:
                kill_chain = client.get_kill_chain(
                    kill_chain_uuid=alert["kill_chain_short_id"]
                )
                alert["kill_chain"] = kill_chain
            except Exception as e:
                # Handle the exception if there is any problem with the API call
                demisto.debug(
                    f"Error fetching kill chain information {kill_chain}: {e}"
                )

        # If the integration parameter is set to mirror add the instance name to be mapped to dbotMirrorInstance
        incident = {
            "name": incident_name,
            "occurred": timestamp_to_datestring(incident_created_time_ms),
            "severity": convert_to_demisto_severity(urgency.get("display", "Low")),
        }
        # If the integration parameter is set to mirror add the appropriate fields to the incident
        alert["mirror_instance"] = demisto.integrationInstance()
        alert["mirrorOut"] = str(mirror_direction) in [
            "Outgoing",
            "Incoming and Outgoing",
        ]
        incident["rawJSON"] = json.dumps(alert)
        incident["dbotMirrorDirection"] = MIRROR_DIRECTION.get(str(mirror_direction))
        incident["dbotMirrorId"] = alert["short_id"]
        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {"last_fetch": latest_created_time}
    return next_run, incidents


# =========== Mirroring Mechanism ===========


def get_remote_data_command(
    client: Client,
    args: dict,
    close_incident: bool,
    close_note: str,
    mirror_events: bool,
    mirror_kill_chain: bool,
    reopen_incident: bool,
):
    """get-remote-data command: Returns an updated alert and error entry (if needed)

    Args:
        client (Client): Sekoia XDR client to use.
        args (dict): The command arguments
        close_incident (bool): Indicates whether to close the corresponding XSOAR incident if the alert
            has been closed on Sekoia's end.
        close_note (str): Indicates the notes to be including when the incident gets closed by mirroring.
        mirror_events (bool): If the events will be included in the mirroring of the alerts or not.
        mirror_kill_chain: If the kill chain information from the alerts will be mirrored.
        reopen_incident: Indicates whether to reopen the corresponding XSOAR incident if the alert
            has been reopened on Sekoia's end.
    Returns:
        GetRemoteDataResponse: The Response containing the update alert to mirror and the entries
    """

    demisto.debug("#### Entering MIRRORING IN - get_remote_data_command ####")

    parsed_args = GetRemoteDataArgs(args)
    alert = client.get_alert(alert_uuid=parsed_args.remote_incident_id)
    alert_short_id, alert_status = alert["short_id"], alert["status"]["name"]
    last_update = arg_to_timestamp(
        arg=parsed_args.last_update, arg_name="lastUpdate", required=True
    )
    alert_last_update = arg_to_timestamp(
        arg=alert.get("updated_at"), arg_name="updated_at", required=False
    )

    demisto.debug(
        f"Alert {alert_short_id} with status {alert_status} : last_update is {last_update} , alert_last_update is {alert_last_update}"  # noqa: E501
    )

    entries = []

    # Add the events to the alert
    if mirror_events and alert["status"]["name"] not in ["Closed", "Rejected"]:
        earliest_time = alert["first_seen_at"]
        lastest_time = "now"
        term = f"alert_short_ids:{alert['short_id']}"
        interval_in_seconds = INTERVAL_SECONDS_EVENTS
        timeout_in_seconds = TIMEOUT_EVENTS

        args = {
            "earliest_time": earliest_time,
            "lastest_time": lastest_time,
            "query": term,
            "interval_in_seconds": interval_in_seconds,
            "timeout_in_seconds": timeout_in_seconds,
        }
        events = search_events_command(args=args, client=client)
        alert["events"] = events.outputs  # pylint: disable=E1101

    # Add the kill chain information to the alert
    if mirror_kill_chain and alert["kill_chain_short_id"]:
        try:
            kill_chain = client.get_kill_chain(
                kill_chain_uuid=alert["kill_chain_short_id"]
            )
            alert["kill_chain"] = kill_chain
        except Exception as e:
            # Handle the exception if there is any problem with the API call
            demisto.debug(f"Error fetching kill_chain : {e}")

    # This adds all the information from the XSOAR incident.
    demisto.debug(
        f"Alert {alert_short_id} with status {alert_status} have this info updated: {alert}"
    )

    investigation = demisto.investigation()
    demisto.debug(f"The investigation information is {investigation}")

    incident_id = investigation["id"]
    incident_status = investigation["status"]

    demisto.debug(
        f"The XSOAR incident is {incident_id} with status {incident_status} is being mirrored with the alert {alert_short_id} that have the status {alert_status}."  # noqa: E501
    )

    # Close the XSOAR incident using mirroring
    if (
        (close_incident)
        and (alert_status in ["Closed", "Rejected"])
        and (investigation["status"] != 1)
    ):
        demisto.debug(
            f"Alert {alert_short_id} with status {alert_status} was closed or rejected in Sekoia, closing incident {incident_id} in XSOAR"  # noqa: E501
        )
        entries = [
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": f"{alert_status} - Mirror",
                    "closeNotes": close_note,
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        ]

    # Reopen the XSOAR incident using mirroring
    if (
        (reopen_incident)
        and (alert_status not in ["Closed", "Rejected"])
        and (investigation["status"] == 1)
    ):
        demisto.debug(
            f"Alert {alert_short_id} with status {alert_status} was reopened in Sekoia, reopening incident {incident_id} in XSOAR"
        )
        entries = [
            {
                "Type": EntryType.NOTE,
                "Contents": {"dbotIncidentReopen": True},
                "ContentsFormat": EntryFormat.JSON,
            }
        ]

    demisto.debug("#### Leaving MIRRORING IN - get_remote_data_command ####")

    demisto.debug(f"This's the final alert status for mirroring in : {alert}")

    return GetRemoteDataResponse(mirrored_object=alert, entries=entries)


def get_modified_remote_data_command(client: Client, args):
    """Gets the list of all alert ids that have change since a given time

    Args:
        client (Client): Sekoia XDR client to use.
        args (dict): The command argument

    Returns:
        GetModifiedRemoteDataResponse: The response containing the list of ids of notables changed
    """
    modified_alert_ids = []
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = remote_args.last_update
    last_update_utc = dateparser.parse(
        last_update, settings={"TIMEZONE": "UTC"}
    )  # converts to a UTC timestamp
    formatted_last_update = last_update_utc.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")  # type: ignore
    converted_time = time_converter(formatted_last_update)
    last_update_time = f"{converted_time},now"

    raw_alerts = client.list_alerts(
        alerts_updated_at=last_update_time,
        alerts_limit=100,
        alerts_status=None,
        alerts_created_at=None,
        alerts_urgency=None,
        alerts_type=None,
        sort_by="updated_at",
    )

    modified_alert_ids = [item["short_id"] for item in raw_alerts["items"]]

    return GetModifiedRemoteDataResponse(modified_incident_ids=modified_alert_ids)


def update_remote_system_command(client: Client, args):
    pass


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
     this command pulls the remote schema for the different incident types, and their associated incident fields,
     from the remote system.
    :return: A list of keys you want to map
    """
    sekoia_incident_type_scheme = SchemeTypeMapping(type_name=INCIDENT_TYPE_NAME)
    for argument, description in SEKOIA_INCIDENT_FIELDS.items():
        sekoia_incident_type_scheme.add_field(name=argument, description=description)

    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(sekoia_incident_type_scheme)

    return mapping_response


# =========== Mirroring Mechanism ===========


def list_alerts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    alerts = client.list_alerts(
        alerts_limit=args.get("limit"),
        alerts_status=args.get("status"),
        alerts_created_at=args.get("created_at"),
        alerts_updated_at=args.get("updated_at"),
        alerts_urgency=args.get("urgency"),
        alerts_type=args.get("alerts_type"),
        sort_by=args.get("sort_by"),
    )

    header = ["title", "uuid", "short_id", "community_uuid"]
    command_output = filter_list_by_keys(alerts["items"], header)
    readable_output = tableToMarkdown("Alerts :", command_output, headers=header)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.ListAlerts",
        outputs_key_field="short_id",
        outputs=alerts["items"],
    )


def get_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    alert_uuid = args["id"]

    alert = client.get_alert(alert_uuid=alert_uuid)
    header = [
        "alert_type",
        "short_id",
        "created_by_type",
        "kill_chain_short_id",
        "details",
        "rule",
    ]
    command_output = filter_dict_by_keys(alert, header)
    readable_output = tableToMarkdown(
        f"Alert {alert_uuid}:", command_output, headers=header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Alert",
        outputs_key_field="uuid",
        outputs=alert,
    )


def query_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    earliest_time = args["earliest_time"]
    lastest_time = args["lastest_time"]
    term = args["query"]
    max_last_events = args.get("max_last_events")

    jobQuery = client.query_events(
        events_earliest_time=earliest_time,
        events_latest_time=lastest_time,
        events_term=term,
        max_last_events=max_last_events,
    )
    readable_output = tableToMarkdown(
        f"Event search created using the term {term}:", jobQuery
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Events",
        outputs_key_field="uuid",
        outputs=jobQuery,
    )


def query_events_status_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    search_job_uuid = args["uuid"]

    status = client.query_events_status(event_search_job_uuid=search_job_uuid)
    readable_output = tableToMarkdown(f"Status of the job {search_job_uuid}:", status)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Events",
        outputs_key_field="search_job_uuid",
        outputs=status,
    )


def retrieve_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    search_job_uuid = args["uuid"]

    events = client.retrieve_events(event_search_job_uuid=search_job_uuid)
    readable_output = tableToMarkdown(
        f"Events retrieved for the search {search_job_uuid}:", events
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Events",
        outputs_key_field="search_job_uuid",
        outputs=events,
    )


@polling_function(name="sekoia-xdr-search-events", requires_polling_arg=False)
def search_events_command(args: dict[str, Any], client: Client) -> PollResult:
    """Parameters"""
    earliest_time = args["earliest_time"]
    lastest_time = args["lastest_time"]
    term = args["query"]
    max_last_events = args.get("max_last_events")
    exclude_info_arg = args.get("exclude_info")
    exclude_info_param = demisto.params().get("exclude_info_events")
    replace_symbol = demisto.params().get("replace_dots_event")

    if not (search_job_uuid := args.get("job_uuid")):
        search = client.query_events(
            events_earliest_time=earliest_time,
            events_latest_time=lastest_time,
            events_term=term,
            max_last_events=max_last_events,
        )
        search_job_uuid = search["uuid"]

    query_status = client.query_events_status(event_search_job_uuid=search_job_uuid)
    finished_status = query_status["status"] == 2

    if not finished_status:
        return PollResult(
            response=None,
            continue_to_poll=True,
            args_for_next_run=(args | {"job_uuid": search_job_uuid}),
            partial_result=CommandResults(
                readable_output=f"Query is still running. Current state: {query_status['status']}."
            ),
        )

    events = client.retrieve_events(event_search_job_uuid=search_job_uuid)
    total = max_last_events or events["total"]

    if len(events["items"]) > 0:
        if exclude_info_arg:
            headers = exclude_info_events(
                event_info=events, exclude_info=exclude_info_arg
            )
            headers = [header.replace(".", replace_symbol) for header in headers]
            undot(json_data=events)
            readable_output = tableToMarkdown(
                f"{total} events out of {str(events['total'])} retrieved for the {term}",
                events["items"],
                headers=headers,
            )
        elif exclude_info_param:
            headers = exclude_info_events(
                event_info=events, exclude_info=",".join(exclude_info_param)
            )
            headers = [header.replace(".", replace_symbol) for header in headers]
            undot(json_data=events)
            readable_output = tableToMarkdown(
                f"{total} events out of {events['total']} retrieved for the {term}",
                events["items"],
                headers=headers,
            )
        else:
            undot(json_data=events)
            headers = list(events["items"][0].keys())
            readable_output = tableToMarkdown(
                f"{total} events out of {events['total']} retrieved for the {term}",
                events["items"],
                headers=headers,
            )
    else:
        readable_output = tableToMarkdown(
            f"{total} events out of {events['total']} retrieved for the {term}",
            events["items"],
        )

    return PollResult(
        response=CommandResults(
            readable_output=readable_output,
            outputs_prefix="SekoiaXDR.Events.Results",
            outputs_key_field="search_job_uuid",
            outputs=events["items"],
        ),
        continue_to_poll=False,
    )


def update_status_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    alert_uuid, updated_status, comment = (
        args["id"],
        args["status"],
        args.get("comment"),
    )
    sekoia_transition = STATUS_TRANSITIONS.get(updated_status)
    readable_output = "Unknown alert"

    workflow = client.get_workflow_alert(alert_uuid=alert_uuid)

    for action in workflow["actions"]:
        if action["name"] == sekoia_transition:
            update = client.update_status_alert(
                alert_uuid=alert_uuid, action_uuid=action["id"], comment=comment
            )
            if update or update == {}:
                readable_output = (
                    f"### Alert {alert_uuid} updated to status: {updated_status}"
                )
            else:
                raise DemistoException(
                    "Failure to update the status of the alert. \
                    Run the command !sekoia-xdr-get-workflow-alert to see the possible\
                    transitions and review the code."
                )

    return CommandResults(readable_output=readable_output, outputs=update)


def post_comment_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    alert_uuid, comment, author = (
        args["id"],
        args["comment"],
        args.get("author"),
    )

    response = client.post_comment_alert(
        alert_uuid=alert_uuid, content=comment, author=author
    )
    response["date"] = timezone_format(response["date"])

    readable_output = tableToMarkdown(
        f"Alert {alert_uuid} updated with the comment: \n {comment}:", response
    )

    return CommandResults(readable_output=readable_output, outputs=response)


def get_comments_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    alert_uuid = args["id"]

    response = client.get_comments_alert(alert_uuid=alert_uuid)

    for item in response["items"]:
        # Add author of the comment
        if item["author"].startswith("user"):
            item["user"] = f"User with id {item['created_by']}"
        elif item["author"].startswith("apikey"):
            item["user"] = "Commented via API"
        elif item["author"].startswith("application"):
            item["user"] = "Sekoia.io"
        else:
            item["user"] = item["author"]
        # Add formatted date of the comment
        item["date"] = timezone_format(item["date"])

    readable_output = tableToMarkdown(
        f"Alert {alert_uuid} have the following comments:", response["items"]
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Comments",
        outputs_key_field="alert_uuid",
        outputs=response["items"],
    )


def get_workflow_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    alert_uuid = args["id"]

    response = client.get_workflow_alert(alert_uuid=alert_uuid)
    readable_output = tableToMarkdown(
        f"Alert {alert_uuid} have the following available status transitions:",
        response["actions"],
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.StatusTransitions",
        outputs_key_field="alert_uuid",
        outputs=response["actions"],
    )


def get_cases_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    alert_uuid, case_id = args["alert_id"], args.get("case_id")

    response = client.get_cases_alert(alert_uuid=alert_uuid, case_id=case_id)
    header = [
        "title",
        "description",
        "priority",
        "short_id",
        "status",
        "community_uuid",
    ]
    command_output = filter_list_by_keys(response["items"], header)
    readable_output = tableToMarkdown(
        f"Alert {alert_uuid} have the following cases:", command_output, headers=header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Cases",
        outputs_key_field="alert_uuid",
        outputs=response["items"],
    )


def get_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    asset_uuid = args["asset_uuid"]

    asset = client.get_asset(asset_uuid=asset_uuid)
    header = ["name", "uuid", "description"]
    command_output = filter_dict_by_keys(asset, header)
    readable_output = tableToMarkdown(
        f"Asset {asset_uuid} have the following information:",
        command_output,
        headers=header,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Asset",
        outputs_key_field="uuid",
        outputs=asset,
    )


def list_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    limit, assets_type = args.get("limit"), args.get("assets_type")

    assets = client.list_asset(limit=limit, assets_type=assets_type)
    header = ["name", "uuid", "description"]
    command_output = filter_list_by_keys(assets["items"], header)
    readable_output = tableToMarkdown(
        f"List of {assets['total']} assets found:", command_output, headers=header
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.Assets",
        outputs_key_field="asset_uuid",
        outputs=assets["items"],
    )


def get_user_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    user_uuid = args["user_uuid"]

    user = client.get_user(user_uuid=user_uuid)
    readable_output = tableToMarkdown(
        f"User {user_uuid} have the following information:", user
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.User",
        outputs_key_field="user_uuid",
        outputs=user,
    )


def add_attributes_asset_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Parameters"""
    asset_uuid, name, value = (
        args["asset_uuid"],
        args["name"],
        args["value"],
    )

    asset_attributes = client.add_attributes_asset(
        asset_uuid=asset_uuid, name=name, value=value
    )
    readable_output = tableToMarkdown(
        f"Asset {asset_uuid} was updated with new attributes:", asset_attributes
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field="asset_uuid",
        outputs=asset_attributes,
    )


def add_keys_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    asset_uuid, name, value = (
        args["asset_uuid"],
        args["name"],
        args["value"],
    )

    asset_keys = client.add_keys_asset(asset_uuid=asset_uuid, name=name, value=value)
    readable_output = tableToMarkdown(
        f"Asset {asset_uuid} was updated with new keys:", asset_keys
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_key_field="asset_uuid",
        outputs=asset_keys,
    )


def remove_attribute_asset_command(
    client: Client, args: dict[str, Any]
) -> CommandResults:
    """Parameters"""
    asset_uuid, attribute_uuid = args["asset_uuid"], args["attribute_uuid"]

    client.remove_attribute_asset(asset_uuid=asset_uuid, attribute_uuid=attribute_uuid)
    readable_output = (
        f"Asset {asset_uuid} had the following attribute removed:\n{attribute_uuid}"
    )

    return CommandResults(readable_output=readable_output)


def remove_key_asset_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    asset_uuid, key_uuid = args["asset_uuid"], args["key_uuid"]

    client.remove_key_asset(asset_uuid=asset_uuid, key_uuid=key_uuid)
    readable_output = f"Asset {asset_uuid} had the following key removed:\n{key_uuid}"

    return CommandResults(readable_output=readable_output)


def get_kill_chain_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    kill_chain_uuid = args["kill_chain_uuid"]

    kill_chain = client.get_kill_chain(kill_chain_uuid=kill_chain_uuid)
    readable_output = tableToMarkdown(
        f"Kill chain {kill_chain_uuid} have the following information:", kill_chain
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.KillChain",
        outputs_key_field="uuid",
        outputs=kill_chain,
    )


def http_request_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """Parameters"""
    method, url_sufix, params = (
        args["method"],
        args["url_sufix"],
        args.get("parameters", {}),
    )

    request = client.http_request(method=method, params=params, url_suffix=url_sufix)
    readable_output = tableToMarkdown(
        f"The HTTP {method} request with params {params} returned the following information:",
        request["items"] if request["items"] else request,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="SekoiaXDR.http_request",
        outputs_key_field="uuid",
        outputs=request,
    )


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication'
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Sekoia XDR client to use.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    # Check a JWT token’s validity
    # https://docs.sekoia.io/develop/rest_api/identity_and_authentication/#tag/User-Authentication/operation/get_validate_resource

    try:
        client.get_validate_resource()
    except DemistoException as e:
        doc = """Please visit the API Key documentation for more information:
         https://docs.sekoia.io/getting_started/generate_api_keys/"""

        if "T300" in str(e):
            return f"Authorization Error: The token is invalid. {doc}"
        elif "T301" in str(e):
            return f"Authorization Error: The token has expired. {doc}"
        elif "T302" in str(e):
            return f"Authorization Error: The token has been revoked. {doc}"
        else:
            raise e
    return "ok"


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params, args, command = demisto.params(), demisto.args(), demisto.command()

    # get the service API url and api key
    api_key = params.get("credentials", {}).get("password")
    base_url = params.get("url")

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` and ``proxy`` to
    # the Client constructor
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=params["first_fetch"],
        arg_name="First fetch time",
        required=True,
    )
    first_fetch_timestamp = (
        int(first_fetch_time.timestamp()) if first_fetch_time else None
    )

    demisto.debug(f"Command being called is {command}")
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        client = Client(
            base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
        )

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            alerts_status = ",".join(params.get("alerts_status", ""))
            alerts_type = ",".join(params.get("alerts_type", ""))
            alerts_urgency = params.get("alerts_urgency", None)
            fetch_mode = params.get("fetch_mode")
            fetch_with_assets = params.get("fetch_with_assets")
            fetch_with_kill_chain = params.get("fetch_with_kill_chain")
            mirror_direction = params.get("mirror_direction", "None")

            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            max_results = arg_to_number(params["max_fetch"])
            last_run: dict[str, Any] = (
                demisto.getLastRun()
            )  # getLastRun() gets the last run dict

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=last_run,
                first_fetch_time=first_fetch_timestamp,
                alert_status=alerts_status,
                alert_urgency=alerts_urgency,
                alert_type=alerts_type,
                fetch_mode=fetch_mode,
                mirror_direction=mirror_direction,
                fetch_with_assets=fetch_with_assets,
                fetch_with_kill_chain=fetch_with_kill_chain,
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list of incidents to create
            demisto.incidents(incidents)

        elif command == "sekoia-xdr-list-alerts":
            return_results(list_alerts_command(client, args))
        elif command == "sekoia-xdr-get-alert":
            return_results(get_alert_command(client, args))
        elif command == "sekoia-xdr-events-execute-query":
            return_results(query_events_command(client, args))
        elif command == "sekoia-xdr-events-status-query":
            return_results(query_events_status_command(client, args))
        elif command == "sekoia-xdr-events-results-query":
            return_results(retrieve_events_command(client, args))
        elif command == "sekoia-xdr-search-events":
            return_results(search_events_command(args, client))
        elif command == "sekoia-xdr-update-status-alert":
            return_results(update_status_alert_command(client, args))
        elif command == "sekoia-xdr-post-comment-alert":
            return_results(post_comment_alert_command(client, args))
        elif command == "sekoia-xdr-get-comments":
            return_results(get_comments_alert_command(client, args))
        elif command == "sekoia-xdr-get-workflow-alert":
            return_results(get_workflow_alert_command(client, args))
        elif command == "sekoia-xdr-get-cases-alert":
            return_results(get_cases_alert_command(client, args))
        elif command == "sekoia-xdr-get-asset":
            return_results(get_asset_command(client, args))
        elif command == "sekoia-xdr-list-assets":
            return_results(list_asset_command(client, args))
        elif command == "sekoia-xdr-get-user":
            return_results(get_user_command(client, args))
        elif command == "sekoia-xdr-add-attributes-asset":
            return_results(add_attributes_asset_command(client, args))
        elif command == "sekoia-xdr-add-keys-asset":
            return_results(add_keys_asset_command(client, args))
        elif command == "sekoia-xdr-remove-attribute-asset":
            return_results(remove_attribute_asset_command(client, args))
        elif command == "sekoia-xdr-remove-key-asset":
            return_results(remove_key_asset_command(client, args))
        elif command == "sekoia-xdr-get-kill-chain":
            return_results(get_kill_chain_command(client, args))
        elif command == "sekoia-xdr-http-request":
            return_results(http_request_command(client, args))
        elif command == "get-remote-data":
            return_results(
                get_remote_data_command(
                    client,
                    args,
                    close_incident=demisto.params().get("close_incident"),  # type: ignore
                    close_note=demisto.params().get("close_notes", "Closed by Sekoia."),  # type: ignore
                    mirror_events=demisto.params().get("mirror_events"),  # type: ignore
                    mirror_kill_chain=demisto.params().get("mirror_kill_chain"),  # type: ignore
                    reopen_incident=demisto.params().get("reopen_incident"),  # type: ignore
                )
            )
        elif command == "get-modified-remote-data":
            return_results(get_modified_remote_data_command(client, args))
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
