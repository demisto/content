import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Cohesity Helios Integration for Cortex XSOAR (aka Demisto).
"""
from CommonServerUserPython import *  # noqa

from datetime import datetime, timedelta
from dateparser import parse
from typing import Any
import json
import urllib3
import traceback

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR
MAX_FETCH_DEFAULT = 20
NUM_OF_RETRIES = 3
BACKOFF_FACTOR = 1.0

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with Cohesity Helios."""

    def _api_request(self, method: str, url_suffix: str, **kwargs):
        """Wraps _http_request with response logging and error handling."""
        request_info = {
            "method": method,
            "url": url_suffix,
            "params": kwargs.get("params"),
            "json_data": kwargs.get("json_data"),
            "headers": kwargs.get("headers"),
        }
        try:
            resp = self._http_request(
                method=method,
                url_suffix=url_suffix,
                retries=NUM_OF_RETRIES,
                backoff_factor=BACKOFF_FACTOR,
                **kwargs,
            )
            if demisto.is_debug:
                demisto.results(f"API Request: {request_info}\nAPI Response: {resp}")
            return resp
        except DemistoException as e:
            if demisto.is_debug:
                demisto.results(f"API Request: {request_info}\nAPI Error: {e}")
            raise

    def get_ransomware_alerts(
        self,
        start_time_usecs=None,
        end_time_usecs=None,
        max_fetch=MAX_FETCH_DEFAULT,
        alert_ids=[],
        alert_state_list=[],
        alert_severity_list=[],
        region_ids=[],
        cluster_ids=[],
    ):
        """Gets the Cohesity Helios ransomware alerts via v2 /mcm/alerts API."""
        request_params: dict[str, Any] = {
            "maxAlerts": max_fetch,
            "alertCategoryList": "kSecurity",
            "alertStateList": "kOpen",
            "alertName": "DataIngestAnomalyAlert",
        }

        if start_time_usecs is not None:
            request_params["startDateUsecs"] = int(start_time_usecs)
        if end_time_usecs is not None:
            request_params["endDateUsecs"] = int(end_time_usecs)
        if alert_ids:
            request_params["alertIdList"] = alert_ids
        if alert_state_list:
            request_params["alertStateList"] = alert_state_list
        if alert_severity_list:
            request_params["alertSeverityList"] = alert_severity_list
        if region_ids:
            request_params["regionIds"] = region_ids
        if cluster_ids:
            request_params["clusterIdentifiers"] = cluster_ids

        resp = self._api_request(
            method="GET",
            url_suffix="/v2/mcm/alerts",
            params=request_params,
        )

        return resp.get("alertsList", [])

    def suppress_ransomware_alert_by_id(self, alert_id: str):
        """Patch API call to suppress ransomware alert by id."""
        if demisto.is_debug:
            demisto.results(f"Suppressing alert: {alert_id}")
        return self._api_request(
            method="PATCH",
            url_suffix="/mcm/alerts/" + alert_id,
            json_data={"status": "kSuppressed"},
            return_empty_response=True,
            empty_valid_codes=[200],
        )

    def resolve_ransomware_alert_by_id(self, alert_id: str):
        """Patch API call to resolve ransomware alert by id."""
        if demisto.is_debug:
            demisto.results(f"Resolving alert: {alert_id}")
        return self._api_request(
            method="PATCH",
            url_suffix="/mcm/alerts/" + alert_id,
            json_data={"status": "kResolved"},
            return_empty_response=True,
            empty_valid_codes=[200],
        )

    def get_incidence_details(self, alert_id: str) -> dict[str, Any]:
        """Gets incidence details via /mcm/argus/api/v1/public/incidences API.

        Returns the antiRansomwareDetails dict which contains entityId, entityName,
        clusterId, latestCleanSnapshotId, environment, anomalyStrength, etc.
        """
        resp = self._api_request(
            method="GET",
            url_suffix="/mcm/argus/api/v1/public/incidences",
            params={
                "incidenceIds": alert_id,
                "shieldTypes": "ANTI_RANSOMWARE",
            },
        )
        incidences = resp.get("incidences") or []
        if not incidences:
            raise ValueError(f"CohesityHelios error: no incidence found for alert_id={alert_id}.")
        return incidences[0]

    def create_recovery(self, cluster_id, payload):
        """Creates a recovery via v2 /data-protect/recoveries API."""
        if self._headers is not None:
            client_headers = self._headers.copy()
        else:
            client_headers = {}

        client_headers["accessClusterId"] = str(cluster_id)

        if demisto.is_debug:
            demisto.results(f"Creating recovery on cluster_id={cluster_id}, payload={payload}")
        return self._api_request(
            method="POST",
            url_suffix="/v2/data-protect/recoveries",
            json_data=payload,
            headers=client_headers,
        )


""" HELPER FUNCTIONS """


def get_date_time_from_usecs(time_in_usecs):
    """Get date time from epoch usecs"""
    return datetime.fromtimestamp(time_in_usecs / 1000000.0)


def get_usecs_from_date_time(dt):
    """Get epoch milllis from date time"""
    return int(dt.timestamp() * 1000000)


def datestring_to_usecs(ds: str):
    """Get epoch usecs from datestring"""
    dt = parse(ds)
    if dt is None:
        return dt

    return int(dt.timestamp() * 1000000)


def _get_property_dict(property_list):
    """
    Helper method to get a dictionary from list of property dicts
    with keys, values
    """
    property_dict = {}
    for property in property_list:
        property_dict[property["key"]] = property["value"]
    return property_dict


def convert_to_demisto_severity_int(severity: str):
    """Maps Cohesity helios severity to Cortex XSOAR severity

    :type severity: ``str``

    :return: Cortex XSOAR Severity
    :rtype: ``int``
    """
    return {
        "kInfo": IncidentSeverity.INFO,  # Informational alert
        "kWarning": IncidentSeverity.LOW,  # low severity
        "kCritical": IncidentSeverity.HIGH,  # critical severity
    }.get(severity, IncidentSeverity.UNKNOWN)


def create_ransomware_incident(alert) -> dict[str, Any]:
    """Helper method to create ransomware incident from alert.

    Actual alert response fields:
        Top-level: id, alertCategory, alertCode, alertDocument, alertState, alertType,
                   clusterId, clusterName, severity, latestTimestampUsecs, firstTimestampUsecs
        propertyList keys: entity_id, job_id
        alertDocument keys: alertName, alertDescription, alertCause, alertHelpText
    """
    property_dict = _get_property_dict(alert.get("propertyList", []))
    incidence_usecs = alert.get("latestTimestampUsecs", 0)
    occurance_time = get_date_time_from_usecs(incidence_usecs).strftime(DATE_FORMAT)

    enriched_alert = alert.copy()
    enriched_alert["alertId"] = str(alert.get("id", ""))
    enriched_alert["objectId"] = property_dict.get("entity_id", "")
    enriched_alert["jobId"] = property_dict.get("job_id", "")

    return {
        "name": alert["alertDocument"]["alertName"],
        "type": "Cohesity-Helios-Ransomware-Incident",
        "event_id": alert.get("id"),
        "occurred": occurance_time,
        "CustomFields": {
            "cohesityheliosalertid": alert.get("id", ""),
            "cohesityheliosalertdescription": alert["alertDocument"]["alertDescription"],
            "cohesityheliosalertcause": alert["alertDocument"]["alertCause"],
            "cohesityheliosobjectid": property_dict.get("entity_id", ""),
            "cohesityheliosclusterid": alert.get("clusterId", ""),
            "cohesityheliosclustername": alert.get("clusterName", ""),
        },
        "rawJSON": json.dumps(enriched_alert),
        "severity": convert_to_demisto_severity_int(alert.get("severity")),
    }


def get_ransomware_alert_details(alert) -> dict[str, Any]:
    """Helper method to parse ransomware alert for readable output."""
    property_dict = _get_property_dict(alert.get("propertyList", []))
    occurance_time = get_date_time_from_usecs(alert.get("latestTimestampUsecs", 0)).strftime(DATE_FORMAT)

    return {
        "alert_id": alert["id"],
        "occurrence_time": occurance_time,
        "severity": alert.get("severity"),
        "alert_description": alert["alertDocument"]["alertDescription"],
        "alert_cause": alert["alertDocument"]["alertCause"],
        "cluster_id": alert.get("clusterId"),
        "cluster_name": alert.get("clusterName"),
        "entity_id": property_dict.get("entity_id"),
        "job_id": property_dict.get("job_id"),
    }


""" COMMAND FUNCTIONS """


def get_ransomware_alerts_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Gets ransomware alerts detected by Cohesity Helios.

        :type client: ``Client``
        :param Client:  cohesity helios client to use.

        :type args: ``Dict[str, Any]``
        :param args: Dictionary with get ransomware alerts parameters.

    Returns command result with the list of fetched ransomware alerts.
    """
    start_time_usecs = datestring_to_usecs(args.get("created_after", ""))
    end_time_usecs = datestring_to_usecs(args.get("created_before", ""))
    alert_severity_list = argToList(args.get("alert_severity_list", []))
    alert_id_list = argToList(args.get("alert_id_list", []))
    region_id_list = argToList(args.get("region_id_list", []))
    cluster_id_list = argToList(args.get("cluster_id_list", []))
    alert_state_list = argToList(args.get("alert_state_list", []))
    limit = args.get("limit", MAX_FETCH_DEFAULT)

    resp = client.get_ransomware_alerts(
        start_time_usecs=start_time_usecs,
        end_time_usecs=end_time_usecs,
        alert_ids=alert_id_list,
        alert_state_list=alert_state_list,
        alert_severity_list=alert_severity_list,
        region_ids=region_id_list,
        cluster_ids=cluster_id_list,
        max_fetch=limit,
    )
    demisto.debug(f"Got {len(resp)} alerts between {start_time_usecs} and {end_time_usecs}.")

    # Parse alerts for readable output.
    ransomware_alerts = []
    for alert in resp:
        alert_details = get_ransomware_alert_details(alert)
        ransomware_alerts.append(alert_details)

    readable_output = tableToMarkdown(
        "Cohesity Helios Ransomware Alerts",
        ransomware_alerts,
        ["alert_id", "severity", "cluster_name", "entity_id", "alert_description", "alert_cause"],
        headerTransform=string_to_table_header,
    )
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix="CohesityHelios.RansomwareAlert",
        outputs_key_field="alert_id",
        outputs=ransomware_alerts,
    )


def ignore_ransomware_anomaly_command(client: Client, args: dict[str, Any]) -> str:
    """Ignore detected anomalous object on Helios."""
    alert_id = args.get("alert_id", "")
    if not alert_id:
        raise ValueError("CohesityHelios error: alert_id is required to ignore an anomalous object.")

    try:
        client.suppress_ransomware_alert_by_id(alert_id)
    except DemistoException as e:
        return_error(f"Failed to suppress alert {alert_id}", error=str(e))

    return f"Ignored alert {alert_id}."


def restore_latest_clean_snapshot(client: Client, args: dict[str, Any]) -> str:
    """Restore latest clean snapshot of given object.

    Uses the /mcm/argus/api/v1/public/incidences API to get full incidence details
    including latestCleanSnapshotId, clusterId, entityName, etc.
    Only alert_id is required — everything else comes from the incidence API.
    """
    alert_id = args.get("alert_id", "")
    if not alert_id:
        raise ValueError("CohesityHelios error: alert_id is required for restore.")

    try:
        incidence = client.get_incidence_details(alert_id)
    except DemistoException as e:
        return_error(f"Failed to get incidence details for alert {alert_id}", error=str(e))
    details = incidence.get("antiRansomwareDetails") or {}

    snapshot_id = details.get("latestCleanSnapshotId", "")
    cluster_id = str(details.get("clusterId", ""))
    entity_name = details.get("entityName", "")
    entity_id = details.get("entityId", "")
    environment = details.get("protectionEnvType", "kVMware")

    if demisto.is_debug:
        demisto.results(
            f"Incidence details: entity_name={entity_name}, entity_id={entity_id}, "
            f"cluster_id={cluster_id}, snapshot_id={snapshot_id}, environment={environment}"
        )

    if not snapshot_id:
        raise ValueError(
            f"CohesityHelios error: no clean snapshot available for entity {entity_name} (id={entity_id}). Cannot restore."
        )

    if not cluster_id:
        raise ValueError(f"CohesityHelios error: cluster_id not found in incidence details for alert_id={alert_id}.")

    recovery_name = datetime.now().strftime("Recover_VM_%b_%d_%Y_%-I_%M_%p")
    request_payload = {
        "name": recovery_name,
        "snapshotEnvironment": environment,
        "vmwareParams": {
            "objects": [{"snapshotId": snapshot_id, "archivalTargetInfo": None}],
            "recoveryAction": "RecoverVMs",
            "recoverVmParams": {
                "targetEnvironment": environment,
                "vmwareTargetParams": {
                    "powerOnVms": True,
                    "attemptDifferentialRestore": False,
                    "continueOnError": False,
                    "overwriteExistingVm": True,
                    "recoveryTargetConfig": {
                        "recoverToNewSource": False,
                    },
                    "recoveryProcessType": "InstantRecovery",
                },
            },
        },
    }

    try:
        client.create_recovery(cluster_id, request_payload)
    except DemistoException as e:
        return_error(f"Recovery failed for {entity_name} (id={entity_id})", error=str(e))

    try:
        client.resolve_ransomware_alert_by_id(alert_id)
    except DemistoException as e:
        return_error(f"Recovery succeeded but failed to resolve alert {alert_id}", error=str(e))

    return f"Restored {entity_name} (id={entity_id}) from latest clean snapshot."


def fetch_incidents_command(client: Client):
    """Fetches incidents since last run or past 7 days in case of first run
    and sends them to Cortex XSOAR.

    :type client: ``Client``
    :param Client:  cohesity helios client to use
    """
    # Get last run details.
    last_run = demisto.getLastRun()

    # Compute start and end time to fetch for incidents.
    start_time_usecs = (
        int(last_run.get("start_time"))
        if (last_run and "start_time" in last_run)
        else get_usecs_from_date_time(datetime.now() - timedelta(days=7))
    )

    # Fetch all new incidents.
    params = demisto.params()
    max_fetch = params.get("max_fetch")
    max_fetch = int(params.get("max_fetch")) if (max_fetch and max_fetch.isdigit()) else MAX_FETCH_DEFAULT

    ransomware_resp = client.get_ransomware_alerts(start_time_usecs=start_time_usecs, max_fetch=max_fetch)
    demisto.debug(f"Got {len(ransomware_resp)} alerts from {start_time_usecs}.")

    # Get incidents for ransomware alerts.
    incidents = []
    new_start_time_usecs = start_time_usecs
    for alert in ransomware_resp:
        new_start_time_usecs = max(new_start_time_usecs, alert.get("latestTimestampUsecs", 0))
        incident = create_ransomware_incident(alert)
        incidents.append(incident)

    # Update last run to 1 usec more than last found alert.
    new_start_time_usecs += 1
    demisto.setLastRun({"start_time": new_start_time_usecs})
    demisto.debug(f"Next run start time usecs {new_start_time_usecs}.")

    # Send incidents to Cortex-XSOAR.
    demisto.incidents(incidents)

    return incidents


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ""
    try:
        client.get_ransomware_alerts(start_time_usecs=1631471400000)
        message = "ok"
    except DemistoException as e:
        if "Forbidden" in str(e) or "Authorization" in str(e):
            message = "Authorization Error: make sure API Key is correctly set"
        else:
            raise e
    return message


""" MAIN FUNCTION """


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    # Get API key for authentication.
    api_key = params.get("apikey")

    # Get helios service API url.
    base_url = params["url"]

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get("insecure", False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        # Prepare client and set authentication headers.
        headers: dict = {
            "apikey": api_key,
            "Content-Type": "application/json",
        }
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "cohesity-helios-get-ransomware-alerts":
            return_results(get_ransomware_alerts_command(client, demisto.args()))

        elif demisto.command() == "cohesity-helios-ignore-anomalous-object":
            return_results(ignore_ransomware_anomaly_command(client, demisto.args()))

        elif demisto.command() == "cohesity-helios-restore-latest-clean-snapshot":
            return_results(restore_latest_clean_snapshot(client, demisto.args()))

        elif demisto.command() == "fetch-incidents":
            fetch_incidents_command(client)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
