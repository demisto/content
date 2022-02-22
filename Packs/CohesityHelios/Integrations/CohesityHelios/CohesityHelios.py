"""Cohesity Helios Integration for Cortex XSOAR (aka Demisto).
"""
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from datetime import datetime, timedelta
from dateparser import parse
from typing import Dict, Any
import json
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
MAX_FETCH_DEFAULT = 20
NUM_OF_RETRIES = 3
BACKOFF_FACTOR = 1.0

''' CLIENT CLASS '''


class Client(BaseClient):
    """ Client class to interact with Cohesity Helios.
    """

    def get_ransomware_alerts(self, start_time_usecs=None, end_time_usecs=None, max_fetch=MAX_FETCH_DEFAULT,
                              alert_ids=[], alert_state_list=[], alert_severity_list=[],
                              region_ids=[], cluster_ids=[]):
        """Gets the Cohesity Helios ransomware alerts.
        """
        # Prepare default request params.
        request_params = {
            "maxAlerts": max_fetch,
            "alertCategoryList": "kSecurity",
            "alertStateList": "kOpen",
            "_includeTenantInfo": True
        }

        # Populate request params filters.
        if start_time_usecs is not None:
            request_params["startDateUsecs"] = int(start_time_usecs)
        if end_time_usecs is not None:
            request_params["endDateUsecs"] = int(end_time_usecs)
        if alert_ids != []:
            request_params["alertIdList"] = alert_ids
        if alert_state_list != []:
            request_params["alertStateList"] = alert_state_list
        if alert_severity_list != []:
            request_params["alertSeverityList"] = alert_severity_list
        if region_ids != []:
            request_params["region_ids"] = region_ids
        if cluster_ids != []:
            request_params["clusterIdentifiers"] = cluster_ids

        resp = self._http_request(
            method='GET',
            url_suffix='/mcm/alerts',
            params=request_params,
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR
        )

        # Filter ransomware alerts.
        ransomware_alerts = []
        for alert in resp:
            if alert['alertCode'] == 'CE01516011':
                ransomware_alerts.append(alert)

        return ransomware_alerts

    def suppress_ransomware_alert_by_id(self, alert_id: str):
        """Patch API call to suppress ransomware alert by id.
        """
        return self._http_request(
            method='PATCH',
            url_suffix='/mcm/alerts/' + alert_id,
            json_data={"status": "kSuppressed"},
            return_empty_response=True,
            empty_valid_codes=[200],
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR
        )

    def resolve_ransomware_alert_by_id(self, alert_id: str):
        """Patch API call to resolve ransomware alert by id.
        """
        return self._http_request(
            method='PATCH',
            url_suffix='/mcm/alerts/' + alert_id,
            json_data={"status": "kResolved"},
            return_empty_response=True,
            empty_valid_codes=[200],
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR
        )

    def restore_vm_object(self, cluster_id, payload):
        """Posts recover vm object details to Helios.
        """
        if self._headers is not None:
            client_headers = self._headers.copy()
        else:
            client_headers = {}

        client_headers['clusterid'] = cluster_id

        return self._http_request(
            method='POST',
            url_suffix='/irisservices/api/v1/public/restore/recover',
            json_data=payload,
            headers=client_headers,
            retries=NUM_OF_RETRIES,
            backoff_factor=BACKOFF_FACTOR
        )


''' HELPER FUNCTIONS '''


def get_date_time_from_usecs(time_in_usecs):
    """Get date time from epoch usecs"""
    return datetime.fromtimestamp(time_in_usecs / 1000000.0)


def get_usecs_from_date_time(dt):
    """Get epoch milllis from date time"""
    return int(dt.timestamp() * 1000000)


def get_current_usecs():
    """Get current epoch usecs"""
    dt = datetime.now()
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
        property_dict[property['key']] = property['value']
    return property_dict


def convert_to_demisto_severity_int(severity: str):
    """Maps Cohesity helios severity to Cortex XSOAR severity

    :type severity: ``str``

    :return: Cortex XSOAR Severity
    :rtype: ``int``
    """
    return {
        'kInfo': IncidentSeverity.INFO,   # Informational alert
        'kWarning': IncidentSeverity.LOW,  # low severity
        'kCritical': IncidentSeverity.HIGH  # critical severity
    }.get(severity, IncidentSeverity.UNKNOWN)


def create_ransomware_incident(alert) -> Dict[str, Any]:
    """Helper method to create ransomware incident from alert.
    """
    property_dict = _get_property_dict(alert['propertyList'])
    incidence_usecs = alert.get("latestTimestampUsecs", 0)
    occurance_time = get_date_time_from_usecs(
        incidence_usecs).strftime(DATE_FORMAT)

    return {
        "name": alert['alertDocument']['alertName'],
        "type": "Cohesity-Helios-Ransomware-Incident",
        "event_id": alert.get("id"),
        "occurred": occurance_time,
        "CustomFields": {
            "alert_description": alert['alertDocument']['alertDescription'],
            "alert_cause": alert['alertDocument']['alertCause'],
            "anomalous_object": property_dict.get('object'),
            "environment": property_dict.get('environment'),
            "anomaly_strength": property_dict.get('anomalyStrength')
        },
        "rawJSON": json.dumps(alert),
        "severity": convert_to_demisto_severity_int(alert.get('severity'))
    }


def get_ransomware_alert_details(alert) -> Dict[str, Any]:
    """Helper method to parse ransomware alert for details.
    """
    # Get alert properties.
    property_dict = _get_property_dict(alert['propertyList'])
    occurance_time = get_date_time_from_usecs(
        alert.get("latestTimestampUsecs", 0)).strftime(DATE_FORMAT)

    return {
        "alert_id": alert['id'],
        "occurrence_time": occurance_time,
        "severity": alert.get('severity'),
        "alert_description": alert['alertDocument']['alertDescription'],
        "alert_cause": alert['alertDocument']['alertCause'],
        "anomalous_object_name": property_dict.get('object'),
        "anomalous_object_env": property_dict.get('environment'),
        "anomaly_strength": property_dict.get('anomalyStrength')
    }


''' COMMAND FUNCTIONS '''


def get_ransomware_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Gets ransomware alerts detected by Cohesity Helios.

        :type client: ``Client``
        :param Client:  cohesity helios client to use.

        :type args: ``Dict[str, Any]``
        :param args: Dictionary with get ransomware alerts parameters.

    Returns command result with the list of fetched ransomware alerts.
    """
    start_time_usecs = datestring_to_usecs(args.get('created_after', ''))
    end_time_usecs = datestring_to_usecs(args.get('created_before', ''))
    alert_severity_list = argToList(args.get('alert_severity_list', []))
    alert_id_list = argToList(args.get('alert_id_list', []))
    region_id_list = argToList(args.get('region_id_list', []))
    cluster_id_list = argToList(args.get('cluster_id_list', []))
    alert_state_list = argToList(args.get('alert_state_list', []))
    limit = args.get('limit', MAX_FETCH_DEFAULT)

    # Fetch ransomware alerts via client.
    resp = client.get_ransomware_alerts(
        start_time_usecs=start_time_usecs,
        end_time_usecs=end_time_usecs, alert_ids=alert_id_list,
        alert_state_list=alert_state_list,
        alert_severity_list=alert_severity_list,
        region_ids=region_id_list,
        cluster_ids=cluster_id_list,
        max_fetch=limit)
    demisto.debug(f"Got {len(resp)} alerts between {start_time_usecs} and {end_time_usecs}.")

    # Parse alerts for readable output.
    ransomware_alerts = []
    for alert in resp:
        alert_details = get_ransomware_alert_details(alert)
        ransomware_alerts.append(alert_details)

    readable_output = tableToMarkdown('Cohesity Helios Ransomware Alerts',
                                      ransomware_alerts,
                                      ["alert_id", "alert_description", "alert_cause", "anomalous_object_env",
                                          "anomalous_object_name", "anomaly_strength"],
                                      headerTransform=string_to_table_header)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='CohesityHelios.RansomwareAlert',
        outputs_key_field='alert_id',
        outputs=ransomware_alerts,
    )


def ignore_ransomware_anomaly_command(client: Client, args: Dict[str, Any]) -> str:
    """Ignore detected anomalous object on Helios.

        :type client: ``Client``
        :param Client:  cohesity helios client to use.

        :type args: ``Dict[str, Any]``
        :param args: Dictionary with ignore anomaly parameters.

        :return: success message of the ignore anomaly operation.
        :rtype: ``str``
    """
    # Filter ransomware alert for given object name.
    alert_id = ''
    object_name = args.get('object_name')
    demisto.debug(f"Performing ignore anomaly operation for object {object_name}.")
    resp = client.get_ransomware_alerts()
    for alert in resp:
        property_dict = _get_property_dict(alert['propertyList'])
        if property_dict.get('object', "") == object_name:
            alert_id = alert.get('id')
            break

    if alert_id == '':
        raise ValueError(f'CohesityHelios error: no anomalous object found by the given name: {object_name}. ')

    # Suppress ransomware alert.
    client.suppress_ransomware_alert_by_id(alert_id)

    return f"Ignored object {object_name}."


def restore_latest_clean_snapshot(client: Client, args: Dict[str, Any]) -> str:
    """Restore latest clean snapshot of given object.

        :type client: ``Client``
        :param Client:  cohesity helios client to use.

        :type args: ``Dict[str, Any]``

        :return: success message of the restore operation.
        :rtype: ``str``
    """
    # Filter ransomware alert for given object name.
    alert_id = ''
    restore_properties = {}
    object_name = args.get('object_name')
    demisto.debug(f"Performing restore operation for object {object_name}.")

    resp = client.get_ransomware_alerts()
    for alert in resp:
        if alert['severity'] == 'kCritical' and alert['alertState'] == 'kOpen':
            restore_properties = _get_property_dict(alert['propertyList'])
            if restore_properties.get('object', "") == object_name:
                alert_id = alert['id']
                break

    if alert_id == '':
        raise ValueError(f"CohesityHelios error: no anomalous object found by the given name {object_name}.")

    # Prepare restore vm properties.
    request_payload = {
        "name": "Cortex_XSOAR_triggered_restore_task_" + restore_properties["object"],
        "type": "kRecoverVMs",
        "vmwareParameters": {
            "poweredOn": True,
            "prefix": "Recover-",
            "suffix": "-VM-" + str(get_current_usecs())
        },
        "objects": [
            {
                "jobId": int(restore_properties["jobId"]),
                "jobRunId": int(restore_properties["jobInstanceId"]),
                "startedTimeUsecs": int(restore_properties["jobStartTimeUsecs"]),
                "sourceName": restore_properties["object"],
                "protectionSourceId": int(restore_properties["entityId"])
            }
        ]
    }
    cluster_id = restore_properties['cid']

    # Post restore request to helios
    client.restore_vm_object(cluster_id, request_payload)

    # Resolve ransomware alert.
    client.resolve_ransomware_alert_by_id(alert_id)

    return f"Restored object {object_name}."


def fetch_incidents_command(client: Client):
    """ Fetches incidents since last run or past 7 days in case of first run
        and sends them to Cortex XSOAR.

        :type client: ``Client``
        :param Client:  cohesity helios client to use
    """
    # Get last run details.
    last_run = demisto.getLastRun()

    # Compute start and end time to fetch for incidents.
    start_time_usecs = int(last_run.get('start_time')) if (
        last_run and 'start_time' in last_run) else get_usecs_from_date_time(
            datetime.now() - timedelta(days=7))

    # Fetch all new incidents.
    params = demisto.params()
    max_fetch = params.get('max_fetch')
    max_fetch = int(params.get('max_fetch')) if (
        max_fetch and max_fetch.isdigit()) else MAX_FETCH_DEFAULT

    ransomware_resp = client.get_ransomware_alerts(
        start_time_usecs=start_time_usecs,
        max_fetch=max_fetch)
    demisto.debug(f"Got {len(ransomware_resp)} alerts from {start_time_usecs}.")

    # Get incidents for ransomware alerts.
    incidents = []
    new_start_time_usecs = start_time_usecs
    for alert in ransomware_resp:
        new_start_time_usecs = max(new_start_time_usecs,
                                   alert.get("latestTimestampUsecs", 0))
        incident = create_ransomware_incident(alert)
        incidents.append(incident)

    # Update last run to 1 usec more than last found alert.
    new_start_time_usecs += 1
    demisto.setLastRun({
        'start_time': new_start_time_usecs
    })
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

    message: str = ''
    try:
        client.get_ransomware_alerts(start_time_usecs=1631471400000)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    params = demisto.params()
    # Get API key for authentication.
    api_key = params.get('apikey')

    # Get helios service API url.
    base_url = params['url']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # Prepare client and set authentication headers.
        headers: Dict = {
            'apikey': api_key,
            'Content-Type': 'application/json',
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'cohesity-helios-get-ransomware-alerts':
            return_results(get_ransomware_alerts_command(client, demisto.args()))

        elif demisto.command() == 'cohesity-helios-ignore-anomalous-object':
            return_results(ignore_ransomware_anomaly_command(client, demisto.args()))

        elif demisto.command() == 'cohesity-helios-restore-latest-clean-snapshot':
            return_results(restore_latest_clean_snapshot(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            fetch_incidents_command(client)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
