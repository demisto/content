import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
from datetime import datetime
import dateparser

"""Doppel for Cortex XSOAR (aka Demisto)

This integration contains features to mirror the alerts from Doppel to create incidents in XSOAR
and the commands to perform different updates on the alerts
"""

import urllib3
from typing import Any, Callable  # noqa: UP035

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """
XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DOPPEL_API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
DOPPEL_PAYLOAD_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"
MIRROR_DIRECTION = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
DOPPEL_ALERT = "Doppel Alert"
DOPPEL_INCIDENT = "Doppel Incident"
DEFAULT_RETRY_TOTAL = 3
DEFAULT_RETRY_BACKOFF_FACTOR = 2
DEFAULT_RETRY_STATUS_LIST = [429, 500, 502, 503, 504]
# Doppel's get-alerts API caps a page at 200 results; request the max to drain backlogs in fewer calls.
DOPPEL_MAX_PAGE_SIZE = 200
# Fallback when max_fetch is blank/invalid.
DEFAULT_MAX_FETCH = 10
# Hard ceiling on pages pulled in a single fetch run, so a misbehaving API can never spin forever.
MAX_FETCH_PAGES_PER_RUN = 1000


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def __init__(
        self,
        base_url,
        api_key,
        user_api_key=None,
        organization_code=None,
        verify=None,
        proxy=None,
        retry_total=DEFAULT_RETRY_TOTAL,
        retry_backoff_factor=DEFAULT_RETRY_BACKOFF_FACTOR,
        retry_status_list=DEFAULT_RETRY_STATUS_LIST,
    ):
        super().__init__(base_url, verify=verify, proxy=proxy)

        self._headers = {"accept": "application/json", "x-api-key": api_key}
        if user_api_key:
            self._headers["x-user-api-key"] = user_api_key
        if organization_code:
            self._headers["x-organization-code"] = organization_code

        # Store retry configuration on the client and leverage BaseClient._http_request parameters
        self._retries = retry_total
        self._backoff_factor = retry_backoff_factor
        self._status_list_to_retry = retry_status_list

        demisto.debug(
            f"Initialized HTTP client using BaseClient._http_request retry params: total={retry_total}, "
            f"backoff_factor={retry_backoff_factor}, status_list={retry_status_list}"
        )

    def get_alert(self, id: str, entity: str) -> dict[str, str]:
        """Return the alert's details when provided the Alert ID or Entity as input

        :type id: ``str``
        :param id: Alert id for which we need to fetch details

        :type entity: ``str``
        :param entity: Alert id for which we need to fetch details

        :return: dict as with alert's details
        :rtype: ``dict``
        """
        params: dict = {}
        if id:
            params["id"] = id
        if entity:
            params["entity"] = entity

        response_content = self._http_request(
            method="GET",
            url_suffix="alert",
            params=params,
            retries=self._retries,
            backoff_factor=self._backoff_factor,
            status_list_to_retry=self._status_list_to_retry,
        )
        return response_content

    def update_alert(
        self,
        queue_state: str,
        entity_state: str,
        alert_id: str | None = None,
        entity: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """
        Updates an existing alert using either the alert ID or the entity.

        :param queue_state: The queue state to update to.
        :param entity_state: The entity state to update to.
        :param alert_id: The alert ID (optional).
        :param entity: The entity (optional).
        :param comment: The comment (optional).
        :return: JSON response containing the updated alert.
        """
        if alert_id and entity:
            raise ValueError("Only one of 'alert_id' or 'entity' can be specified, not both.")
        if not alert_id and not entity:
            raise ValueError("Either 'alert_id' or 'entity' must be specified.")

        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        params = {}
        if alert_id is not None:
            params["id"] = alert_id
        elif entity is not None:
            params["entity"] = entity
        payload = {"queue_state": queue_state, "entity_state": entity_state, "comment": comment}

        response_content = self._http_request(
            method="PUT",
            full_url=api_url,
            params=params,
            json_data=payload,
            retries=self._retries,
            backoff_factor=self._backoff_factor,
            status_list_to_retry=self._status_list_to_retry,
        )
        return response_content

    def get_alerts(self, params: dict[str, Any]) -> dict[str, Any]:
        """
        Fetches multiple alerts based on query parameters.

        :param params: A dictionary of query parameters to apply to the request.
        :return: A list of dictionaries containing alert details.
        """
        api_name = "alerts"
        api_url = f"{self._base_url}/{api_name}"
        # Filter out None values
        filtered_params = {k: v for k, v in params.items() if v is not None}

        demisto.debug(f"API Request Params: {filtered_params}")

        response_content = self._http_request(
            method="GET",
            full_url=api_url,
            params=filtered_params,
            retries=self._retries,
            backoff_factor=self._backoff_factor,
            status_list_to_retry=self._status_list_to_retry,
        )
        return response_content

    def create_alert(self, entity: str) -> dict[str, Any]:
        api_name = "alert"
        api_url = f"{self._base_url}/{api_name}"
        response_content = self._http_request(
            method="POST",
            full_url=api_url,
            json_data={"entity": entity},
            retries=self._retries,
            backoff_factor=self._backoff_factor,
            status_list_to_retry=self._status_list_to_retry,
        )
        return response_content

    def create_abuse_alert(self, entity: str) -> dict[str, Any]:
        api_name = "alert/abuse"
        api_url = f"{self._base_url}/{api_name}"
        response_content = self._http_request(
            method="POST",
            full_url=api_url,
            json_data={"entity": entity},
            retries=self._retries,
            backoff_factor=self._backoff_factor,
            status_list_to_retry=self._status_list_to_retry,
        )
        return response_content


""" HELPER FUNCTIONS """


def _get_remote_updated_incident_data_with_entry(client: Client, doppel_alert_id: str, last_update_str: str):
    """
    Retrieves updated incident data from the remote system based on the given alert ID and last update timestamp.

    Args:
        client (Client):
            An instance of the Client class used to interact with the remote Doppel API.
        doppel_alert_id (str):
            The unique identifier of the alert in the remote system.
        last_update_str (str):
            A string representing the last update timestamp in ISO 8601 format (e.g., "2025-01-19T08:44:52Z").

    Returns:
        dict[str, Any]:
            A dictionary containing the updated incident details, including entries related to the alert.
    """

    # Truncate to microseconds since Python's datetime only supports up to 6 digits
    last_update_str = last_update_str[:26] + "Z"
    last_update = datetime.strptime(last_update_str, "%Y-%m-%dT%H:%M:%S.%fZ")
    if not last_update:
        demisto.debug(f"Warning: Could not parse timestamp: {last_update_str}")
        return None, []

    demisto.debug(f"Getting Remote Data for {doppel_alert_id} which was last updated on: {last_update}")
    updated_doppel_alert = client.get_alert(id=doppel_alert_id, entity="")
    demisto.debug(f"Received alert data for {doppel_alert_id}")
    audit_logs = updated_doppel_alert.get("audit_logs")
    demisto.debug(f'The alert contains {len(audit_logs or "")} audit logs')

    if isinstance(audit_logs, list) and all(isinstance(log, dict) for log in audit_logs):
        most_recent_audit_log = max(audit_logs, key=lambda audit_log: audit_log["timestamp"])
        demisto.debug(f"Most recent audit log is {most_recent_audit_log}")
        if isinstance(most_recent_audit_log, dict):
            recent_audit_log_datetime_str = most_recent_audit_log["timestamp"]
            recent_audit_log_datetime = datetime.strptime(recent_audit_log_datetime_str, DOPPEL_PAYLOAD_DATE_FORMAT)
            demisto.debug(f"The event was modified recently on {recent_audit_log_datetime}")
            updated_doppel_alert["id"] = doppel_alert_id
            entries: list = [
                {"Type": EntryType.NOTE, "Contents": most_recent_audit_log, "ContentsFormat": EntryFormat.JSON, "Note": True}
            ]
            demisto.debug(f"Successfully returning the updated alert and entries: {updated_doppel_alert, entries}")
            return updated_doppel_alert, entries
    return None, []


def _get_mirroring_fields():
    """
    Get tickets mirroring.
    """
    mirror_direction: str = demisto.params().get("mirror_direction", "None")
    return {
        "mirror_direction": MIRROR_DIRECTION.get(mirror_direction),
        "mirror_instance": demisto.integrationInstance(),
        "incident_type": "Doppel_Incident",
    }


def _get_last_fetch_datetime(last_run):
    # Fetch the last run (time of the last fetch)
    last_fetch_datetime: datetime = datetime.now()
    if last_run:
        last_fetch_datetime = datetime.strptime(last_run, "%Y-%m-%dT%H:%M:%SZ")
        demisto.debug(f"Alerts were fetched last on: {last_fetch_datetime}")
    else:
        # If no last run is found
        first_fetch_time = demisto.params().get("first_fetch", "3 days").strip()
        last_fetch_datetime = dateparser.parse(first_fetch_time) or datetime.now()
        assert last_fetch_datetime is not None, f"could not parse {first_fetch_time}"
        demisto.debug(f"This is the first time we are fetching the incidents. This time fetching it from: {last_fetch_datetime}")

    return last_fetch_datetime


def _paginated_call_to_get_alerts(client, page, last_fetch_datetime):
    """
    Set the query parameters
    """
    last_fetch_str: str = last_fetch_datetime.strftime(DOPPEL_API_DATE_FORMAT)
    query_params = {
        "created_after": last_fetch_str,  # Fetch alerts after the last_fetch,
        "sort_type": "date_sourced",
        "sort_order": "asc",
        "page": page,
        "page_size": DOPPEL_MAX_PAGE_SIZE,  # Pull large pages to drain backlogs in fewer requests (API max is 200)
    }
    get_alerts_response = client.get_alerts(params=query_params)
    alerts = get_alerts_response.get("alerts", None)
    return alerts


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.password
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    try:
        # Using the same dates so that we do not fetch any data for testing,
        # but still get the response as 200
        current_datetime_str = datetime.now().strftime(DOPPEL_API_DATE_FORMAT)
        query_params = {"created_before": current_datetime_str, "created_after": current_datetime_str}

        # Call the client's `get_alerts` method to test the connection
        client.get_alerts(params=query_params)
        message: str = "ok"

    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


def doppel_get_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Comand to get a specific alert in the Doppel client using the provided arguments.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object including alert details.

    """

    id: str = args.get("id", "")
    entity: str = args.get("entity", "")
    if not id and not entity:
        raise ValueError("Neither id nor the entity is specified. We need exactly single input for this command")
    if id and entity:
        raise ValueError("Both id and entity is specified. We need exactly single input for this command")

    try:
        result = client.get_alert(id=id, entity=entity)
    except Exception as exception:
        raise Exception(f"No alert found with the given parameters :- {str(exception)}")

    title = "Alert Summary"
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix="Doppel.Alert",
        outputs_key_field="id",
        outputs=result,
        readable_output=human_readable,
    )


def doppel_update_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Executes the update alert command.

    :param client: The Client instance.
    :param args: Command arguments.
    :return: CommandResults object.
    """
    alert_id = args.get("alert_id", "")
    entity = args.get("entity", "")
    queue_state = args.get("queue_state", "")
    entity_state = args.get("entity_state", "")
    comment = args.get("comment", "")

    if alert_id and entity:
        raise ValueError("Only one of 'alert_id' or 'entity' can be specified.")

    if not any([queue_state, entity_state, comment]):
        raise ValueError("At least one of 'queue_state', 'entity_state', or 'comment' must be provided.")

    try:
        result = client.update_alert(
            queue_state=queue_state, entity_state=entity_state, alert_id=alert_id, entity=entity, comment=comment
        )
    except Exception as exception:
        raise Exception(f"Failed to update the alert with the given parameters :- {str(exception)}.")

    title = "Alert Summary"
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix="Doppel.UpdatedAlert",
        outputs_key_field="id",
        outputs=result,
        readable_output=human_readable,
    )


def format_datetime(timestamp_str):
    """
    Formats a given timestamp string into ISO 8601 format.

    :param timestamp_str: A string representing the datetime, which may or may not be in ISO 8601 format.
    :return: A formatted datetime string in ISO 8601 format (YYYY-MM-DDTHH:MM:SS).
    """
    if not timestamp_str:
        return None  # Return None if no timestamp is provided

    try:
        # Replace 'Z' with '+00:00' to make it compatible with fromisoformat()
        if timestamp_str.endswith("Z"):
            timestamp_str = timestamp_str.replace("Z", "+00:00")

        # Attempt to parse the string in ISO 8601 format
        datetime.fromisoformat(timestamp_str)
        return timestamp_str  # Already in ISO format
    except ValueError:
        datetime_obj = arg_to_datetime(timestamp_str)

        # Convert to standard ISO 8601 format without microseconds and timezone
        iso_format_truncated = datetime_obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if datetime_obj else None
        return iso_format_truncated


def doppel_get_alerts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Command to fetch multiple alerts based on query parameters.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object with the retrieved alerts.
    """

    created_before = format_datetime(args.get("created_before"))
    created_after = format_datetime(args.get("created_after"))

    # Extract query parameters directly from arguments
    query_params = {
        "search_key": args.get("search_key"),
        "queue_state": args.get("queue_state"),
        "product": args.get("product"),
        "created_before": created_before,
        "created_after": created_after,
        "sort_type": args.get("sort_type"),
        "sort_order": args.get("sort_order"),
        "page": args.get("page"),
        "tags": argToList(args.get("tags"), separator=",", transform=None),
    }

    # Call the client's `get_alerts` method to fetch data
    demisto.debug(f"Query parameters before sending to client: {query_params}")

    try:
        results = client.get_alerts(params=query_params)
    except Exception as exception:
        raise Exception(f"No alerts were found with the given parameters :- {str(exception)}.")
    demisto.debug(f"Results received: {results}")

    alerts = results.get("alerts")
    title = "Alert Summary"
    human_readable = tableToMarkdown(title, alerts, removeNull=True)
    return CommandResults(
        outputs_prefix="Doppel.GetAlerts",
        outputs_key_field="id",
        outputs=results,
        readable_output=human_readable,
    )


def doppel_create_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Comand to create an alert in the Doppel client using the provided arguments.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object including details of the created alert.
    """

    entity = args.get("entity")
    if not entity:
        raise ValueError("Entity must be specified to create an alert.")

    try:
        result = client.create_alert(entity=entity)
    except Exception as exception:
        raise Exception(f"Failed to create the alert with the given parameters:- {str(exception)}.")

    title = "Alert Summary"
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix="Doppel.CreatedAlert",
        outputs_key_field="id",
        outputs=result,
        readable_output=human_readable,
    )


def doppel_create_abuse_alert_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Comand to create an abuse alert in the Doppel client using the provided arguments.

    :param client: Client instance to interact with the API.
    :param args: Command arguments containing the query parameters as key-value pairs.
    :return: CommandResults object including details of the created abuse alert.

    """

    entity = args.get("entity")
    if not entity:
        raise ValueError("Entity must be specified to create an abuse alert.")

    try:
        result = client.create_abuse_alert(entity=entity)
    except Exception as exception:
        raise Exception(f"Failed to create the abuse alert with the given parameters:- {str(exception)}.")

    title = "Alert Summary"
    human_readable = tableToMarkdown(title, result, removeNull=True)
    return CommandResults(
        outputs_prefix="Doppel.AbuseAlert",
        outputs_key_field="id",
        outputs=result,
        readable_output=human_readable,
    )


def _parse_fetch_timeout():
    """Parse the fetch_timeout param. Blank or invalid means no timeout limit."""
    raw = demisto.params().get("fetch_timeout")
    if raw is None or str(raw).strip() == "":
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _parse_max_fetch():
    """Parse the max_fetch param, falling back to a safe default when blank/invalid."""
    raw = demisto.params().get("max_fetch")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_FETCH
    return value if value > 0 else DEFAULT_MAX_FETCH


def _incident_alert_id(incident):
    """Return the Doppel alert id for a queued/created incident (dbotMirrorId, else rawJSON id)."""
    alert_id = str(incident.get("dbotMirrorId") or "")
    if alert_id:
        return alert_id
    raw = incident.get("rawJSON")
    if raw:
        try:
            return str(json.loads(raw).get("id") or "")
        except Exception:
            return ""
    return ""


def _seen_ids_from_queue(incidents_queue):
    """Collect the Doppel alert ids already present in the persisted incidents queue."""
    seen = set()
    for queued in incidents_queue:
        alert_id = _incident_alert_id(queued)
        if alert_id:
            seen.add(alert_id)
    return seen


def _alert_to_incident(alert, mirroring_object):
    """Build an XSOAR incident dict from a single Doppel alert."""
    alert_id = str(alert.get("id") or "")
    created_at_str = alert.get("created_at")
    created_at_datetime = None
    if created_at_str:
        for date_format in (DOPPEL_PAYLOAD_DATE_FORMAT, DOPPEL_API_DATE_FORMAT):
            try:
                created_at_datetime = datetime.strptime(created_at_str, date_format)
                break
            except (ValueError, TypeError):
                continue
    if created_at_datetime is None:
        created_at_datetime = datetime.now()
    alert.update(mirroring_object)
    # Use the external Doppel alert id (e.g. TET-1953421) as the incident name so it
    # is human-meaningful and duplicates are visually obvious.
    incident_name = f"Doppel Alert {alert_id}" if alert_id else "Doppel Alert"
    return {
        "name": incident_name,
        "type": DOPPEL_ALERT,
        "occurred": created_at_datetime.strftime(XSOAR_DATE_FORMAT),
        "dbotMirrorId": alert_id,
        "rawJSON": json.dumps(alert),
    }


def fetch_incidents_command(client: Client, args: dict[str, Any]) -> None:
    """
    Fetch incidents from Doppel alerts and create XSOAR incidents.
    Pagination is bounded per run and duplicates are removed by Doppel alert id
    (both within a single run and across runs), so a large multi-page backlog is
    drained safely over consecutive runs without ever creating the same alert twice.
    """
    demisto.debug("Fetching alerts from Doppel.")
    start_time = time.time()
    timeout = _parse_fetch_timeout()
    fetch_limit = _parse_max_fetch()
    last_run = demisto.getLastRun() or {}
    demisto.debug(f"Last run details:- {last_run}")
    incidents_queue = last_run.get("incidents_queue", [])
    recently_seen_ids = last_run.get("recently_seen_ids", [])
    last_run_time = last_run.get("last_run", None)
    last_fetch_datetime = _get_last_fetch_datetime(last_run_time)
    # Seed the dedupe set with ids already in the queue plus the ids persisted from
    # the previous run's high-water-mark second. This prevents re-creating alerts
    # that share the cursor's boundary second when the next run re-pulls them.
    seen_alert_ids = _seen_ids_from_queue(incidents_queue)
    seen_alert_ids.update(str(i) for i in recently_seen_ids if i)
    # Only pull more pages if the queue can't already cover this run plus a buffer.
    target_queue_size = fetch_limit * 2
    mirroring_object = _get_mirroring_fields()
    if len(incidents_queue) < target_queue_size:
        page = 0
        while True:
            if timeout is not None and (time.time() - start_time) > timeout:
                demisto.info("Fetch incidents reached its time budget. Progress saved; the next run continues.")
                break
            # Hard safeguard against an unbounded loop (e.g. a misbehaving API that
            # never returns an empty page) when no fetch timeout is configured.
            if page >= MAX_FETCH_PAGES_PER_RUN:
                demisto.info(f"Reached the per-run page ceiling ({MAX_FETCH_PAGES_PER_RUN}). Continuing on the next run.")
                break
            alerts = _paginated_call_to_get_alerts(client, page, last_fetch_datetime)
            if not alerts:
                demisto.info("No more alerts returned from Doppel. Exiting pagination loop.")
                break
            page_incidents = []
            for alert in alerts:
                alert_id = str(alert.get("id") or "")
                if not alert_id or alert_id in seen_alert_ids:
                    continue
                seen_alert_ids.add(alert_id)
                page_incidents.append(_alert_to_incident(alert, mirroring_object))
            incidents_queue += page_incidents
            demisto.info(f"Fetched page {page} from Doppel ({len(page_incidents)} new alerts).")
            page += 1
            if len(incidents_queue) >= target_queue_size:
                demisto.info("Reached per-run queue target; remaining pages will drain on the next run.")
                break
    oldest_incidents = incidents_queue[:fetch_limit]
    remaining_queue = incidents_queue[fetch_limit:]
    # Advance the cursor to the newest alert time we currently know about. We do NOT
    # skip the boundary second (which could drop same-second alerts split across a
    # page); instead we persist the ids at that second so the inclusive re-pull on
    # the next run is de-duplicated rather than lost.
    all_occurred = [inc.get("occurred") for inc in incidents_queue if inc.get("occurred")]
    if all_occurred:
        newest_occurred = max(all_occurred)
        next_fetch = newest_occurred
        # Accumulate every alert id we have emitted/queued at this boundary second.
        # incidents_queue here is the full pre-slice list (created + remaining), and
        # while the cursor stays on the same second we also carry forward the ids
        # already created on prior runs so the inclusive re-pull never re-creates them.
        boundary = {_incident_alert_id(inc) for inc in incidents_queue if inc.get("occurred") == newest_occurred}
        boundary.discard("")
        if last_run_time == newest_occurred:
            boundary.update(str(i) for i in recently_seen_ids if i)
        boundary_ids = list(boundary)
    else:
        next_fetch = last_run_time
        boundary_ids = [str(i) for i in recently_seen_ids if i]
    demisto.setLastRun(
        {
            "last_run": next_fetch,
            "incidents_queue": remaining_queue,
            "recently_seen_ids": boundary_ids,
        }
    )
    demisto.debug(f"Next cursor: {next_fetch}; queued for later: {len(remaining_queue)}; boundary ids: {len(boundary_ids)}.")
    # Create incidents in XSOAR
    if oldest_incidents and len(oldest_incidents) > 0:
        try:
            demisto.incidents(oldest_incidents)
            demisto.info(f"Successfully created {len(oldest_incidents)} incidents in XSOAR.")
        except Exception as e:
            raise ValueError(f"Incident creation failed due to: {str(e)}")
    else:
        demisto.incidents([])
        demisto.info("No incidents to create. Exiting fetch_incidents_command.")


def get_modified_remote_data_command(client: Client, args: dict[str, Any]) -> GetModifiedRemoteDataResponse:
    """
    Checks for remote modifications since the last update timestamp
    and returns a list of modified incident IDs.
    """

    remote_args = GetModifiedRemoteDataArgs(args)
    last_update = dateparser.parse(remote_args.last_update, settings={"TIMEZONE": "UTC"}).strftime(  # type: ignore[union-attr]
        DOPPEL_API_DATE_FORMAT
    )

    query_params = {
        "last_activity_timestamp": last_update,
    }

    try:
        results = client.get_alerts(params=query_params)
        alerts = results.get("alerts", [])

        modified_incident_ids = [str(alert.get("id")) for alert in alerts if alert.get("id")]

        demisto.debug(f"Found {len(modified_incident_ids)} modified remote incidents. Incidents: {modified_incident_ids}")
        return GetModifiedRemoteDataResponse(modified_incident_ids)

    except Exception as e:
        demisto.error(f"Error in get-modified-remote-data: {e}")
        return GetModifiedRemoteDataResponse([])


def get_remote_data_command(client: Client, args: dict[str, Any]) -> GetRemoteDataResponse:
    try:
        remote_updated_incident_data: dict[str, Any] = {}
        mirrored_object: dict[str, Any] = {}
        demisto.debug(f'Calling the "get-remote-data" for {args["id"]}')
        parsed_args = GetRemoteDataArgs(args)
        remote_updated_incident_data, parsed_entries = _get_remote_updated_incident_data_with_entry(
            client, parsed_args.remote_incident_id, parsed_args.last_update
        )
        if remote_updated_incident_data:
            demisto.debug(f'Found updates in the alert with id: {args["id"]}')
            return GetRemoteDataResponse(remote_updated_incident_data, parsed_entries)
        else:
            demisto.debug(f"Nothing new in the incident {parsed_args.remote_incident_id}")
            return GetRemoteDataResponse(mirrored_object, entries=[{}])

    except Exception as e:
        demisto.error(f"Error while running get_remote_data_command: {e}")
        if "Rate limit exceeded" in str(e):
            demisto.debug("API rate limit")
        if not remote_updated_incident_data:
            remote_updated_incident_data = {"id": parsed_args.remote_incident_id}
        mirrored_object["in_mirror_error"] = str(e)
        return GetRemoteDataResponse(mirrored_object, entries=[])


def update_remote_system_command(client: Client, args: dict[str, Any]) -> str:
    """update-remote-system command: pushes local changes to the remote system

    :type client: ``Client``
    :param client: XSOAR client to use

    :type args: ``dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.
        ``args['data']`` the data to send to the remote system
        ``args['entries']`` the entries to send to the remote system
        ``args['incidentChanged']`` boolean telling us if the local incident indeed changed or not
        ``args['remoteId']`` the remote incident id

    :return:
        ``str`` containing the remote incident id - really important if the incident is newly created remotely

    :rtype: ``str``
    """
    demisto.debug(f"Arguments for the update-remote-system is: {args}")
    parsed_args = UpdateRemoteSystemArgs(args)
    new_incident_id = parsed_args.remote_incident_id

    demisto.debug(f"parsed_args data :- {parsed_args}")
    demisto.debug(f"parsed_args data :- {parsed_args.data}")
    try:
        # Only update Doppel Alert if the XSOAR Incident is closed
        if parsed_args.inc_status != IncidentStatus.DONE:
            demisto.debug(f"Incident not closed. Skipping update for remote ID [{new_incident_id}].")
            return new_incident_id

        demisto.debug(f"Sending incident with remote ID [{new_incident_id}] to remote system")

        if parsed_args.remote_incident_id and parsed_args.incident_changed:
            # Fetch existing incident details to preserve versioning
            old_incident = client.get_alert(id=new_incident_id, entity="")

            # Apply changes from XSOAR to the existing incident
            old_incident.update(parsed_args.delta)  # Simplifies key-value assignment

            parsed_args.data = old_incident

        # Ensure queue_state is updated to 'archived' if necessary
        if parsed_args.data.get("queue_state") != "archived":
            client.update_alert(
                queue_state="archived",
                entity_state=parsed_args.data.get("entity_state", ""),  # Preserve old entity_state
                comment=parsed_args.data.get("notes", ""),
                alert_id=new_incident_id,
            )
    except Exception as e:
        demisto.error(f"Doppel - Error in outgoing mirror for incident {new_incident_id} \nError message: {str(e)}")

    return new_incident_id


def get_mapping_fields_command(client: Client, args: dict[str, Any]) -> GetMappingFieldsResponse:
    """
    Retrieves the mapping fields for Doppel alerts in XSOAR.

    This function defines a custom mapping for Doppel alerts, adding specific fields that
    can be used for incident mirroring and enrichment in Cortex XSOAR.

    Args:
        client (Client): The API client used to communicate with Doppel.
        args (dict[str, Any]): Command arguments (not used in this function).

    Returns:
        GetMappingFieldsResponse: The mapping response containing field definitions.
    """
    demisto.debug("Executing get_mapping_fields_command")  # Debug statement

    # Define the incident mapping scheme
    xdr_incident_type_scheme = SchemeTypeMapping(type_name=DOPPEL_ALERT)
    xdr_incident_type_scheme.add_field(name="queue_state", description="Queue State of the Doppel Alert")

    # Create the response object
    mapping_response = GetMappingFieldsResponse()
    mapping_response.add_scheme_type(xdr_incident_type_scheme)

    demisto.debug(f"Mapping fields response created: {mapping_response}")  # Debug statement
    return mapping_response


""" MAIN FUNCTION """


def main() -> None:
    """Main function, parses params and runs command functions."""
    api_key = demisto.params().get("credentials", {}).get("password")
    user_api_key = demisto.params().get("user_credentials", {}).get("password")
    organization_code = demisto.params().get("organization_code")
    verify = not demisto.params().get("insecure")
    proxy = demisto.params().get("proxy")

    demisto.debug(f"Verify SSL: {verify} and Proxy: {proxy}")

    # Get the service API URL
    base_url = urljoin(demisto.params()["url"], "/v1")

    # Explicitly define the type for the command function dictionary
    supported_commands: dict[str, Callable[[Client, dict[str, Any]], Any]] = {
        "fetch-incidents": fetch_incidents_command,
        "get-modified-remote-data": get_modified_remote_data_command,
        "get-remote-data": get_remote_data_command,
        "update-remote-system": update_remote_system_command,
        "get-mapping-fields": get_mapping_fields_command,
        "doppel-get-alert": doppel_get_alert_command,
        "doppel-update-alert": doppel_update_alert_command,
        "doppel-get-alerts": doppel_get_alerts_command,
        "doppel-create-alert": doppel_create_alert_command,
        "doppel-create-abuse-alert": doppel_create_abuse_alert_command,
    }

    # Special case for 'test-module' which does not take args
    supported_commands_test_module: dict[str, Callable[[Client], Any]] = {"test-module": test_module}

    current_command: str = demisto.command()
    demisto.info(f"Command being called is {current_command}")

    try:
        client = Client(
            base_url=base_url,
            api_key=api_key,
            user_api_key=user_api_key,
            organization_code=organization_code,
            verify=verify,
            proxy=proxy,
        )

        if current_command in supported_commands_test_module:
            # Calls test_module(client) without args
            result = supported_commands_test_module[current_command](client)
        elif current_command in supported_commands:
            # Calls command_function(client, demisto.args())
            result = supported_commands[current_command](client, demisto.args())
        else:
            demisto.error(f"Command is not implemented: {current_command}")
            raise NotImplementedError(f"The {current_command} command is not supported")

        demisto.info(f"Command run successful: {current_command}")
        return_results(result)

    except Exception as e:
        return_error(f"Failed to execute {current_command} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
