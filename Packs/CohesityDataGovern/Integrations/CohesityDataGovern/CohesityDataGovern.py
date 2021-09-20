"""Cohesity Data governance Integration for Cortex XSOAR (aka Demisto)

This is an empty Integration with some basic structure according
to the code conventions.

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting

This is an empty structure file. Check an example at;
https://github.com/demisto/content/blob/master/Packs/HelloWorld/Integrations/HelloWorld/HelloWorld.py

"""
import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

from datetime import datetime, timedelta
from typing import Dict, Any
import json
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # Helper functions to interact with helios services.
    def get_was_alerts(self, start_time_millis, end_time_millis) -> Dict[str, Any]:
        """Gets the Wide Access Shield Alerts.

        :return: dict containing the Wide Access Shields alerts
        returned from the API
        :rtype: ``Dict[str, Any]``
        """
        return self._http_request(
            method='GET',
            url_suffix='/mcm/argus/api/v1/public/shields/WIDE_ACCESS/incidences',
            params={
                "startTimeMsecs": start_time_millis,
                "endTimeMsecs": end_time_millis
            }
        )

    def get_ransomware_alerts(self, start_time_millis: int):
        """Gets the Cohesity ransomware alerts.
        """
        resp = self._http_request(
            method='GET',
            url_suffix='/mcm/alerts',
            params={
                "maxAlerts": 1000,
                "alertCategoryList": "kSecurity",
                "alertStateList": "kOpen",
                "_includeTenantInfo": True,
                "startDateUsecs": start_time_millis
            }
        )

        # filter ransomware alerts.
        ransomware_alerts = []
        for alert in resp:
            ransomware_alerts.append(alert)

        return ransomware_alerts


''' HELPER FUNCTIONS '''


def get_date_time_from_millis(time_in_millis):
    return datetime.fromtimestamp(time_in_millis / 1000.0)


def get_millis_from_date_time(dt):
    return int(dt.timestamp() * 1000)

# Get current data time millis


def get_current_date_time():
    dt = datetime.now()
    return int(dt.timestamp() * 1000)


def get_nMin_prev_date_time(nMins: int):
    dt = datetime.now() - timedelta(minutes=nMins)
    return int(dt.timestamp() * 1000)


# Helper function to get alert properties dict.
def _get_property_dict(property_list):
    '''
    get property dictionary from list of property dicts
    with keys, values
    :param property_list:
    :return:
    '''
    property_dict = {}
    for property in property_list:
        property_dict[property['key']] = property['value']
    return property_dict


# Helper method to create wide-access incident from alert.
def create_wide_access_incident(alert) -> Dict[str, Any]:
    occurance_time = get_date_time_from_millis(
        alert.get("incidenceTimeMsecs")).isoformat()[:-3] + 'Z'

    return {
        "name": "wide-access-incident",
        "event_id": alert.get("id"),
        "occurred": occurance_time,
        "rawJSON": json.dumps(alert)
    }

# Helper method to create wide-access incident from alert.


def create_ransomware_incident(alert) -> Dict[str, Any]:
    property_dict = _get_property_dict(alert['propertyList'])
    occurance_time = get_date_time_from_millis(
        alert.get("incidenceTimeMsecs")).isoformat()[:-3] + 'Z'

    return {
        "name": alert['alertDocument']['alertName'],
        "event_id": alert.get("id"),
        "occurred": occurance_time,
        "rawJSON": json.dumps(alert)
    }

# Helper method to create ransomware incident from alert.


def parse_ransomware_alert(alert) -> Dict[str, Any]:
    demisto.results(alert)

    # Get alert properties.
    property_dict = _get_property_dict(alert['propertyList'])
    external_id = property_dict.get('object', '') + '___' +\
        property_dict.get('entityId', '') + '___' +\
        property_dict.get('source', '') + '___' +\
        property_dict.get('cluster', '') + '___' +\
        property_dict.get('cid', '')

    return {
        "alert_id": alert['alertDocument']['alertId'],
        "description": "Anomalous object from Cohesity"
        " Helios. The object is under source \'"
        + property_dict.get("source", "")
        + "\' on cluster \'" + property_dict.get("cluster", "") + "\'" + "\n"
        + "# Alert Info \n\n"
        + "*Alert Name* : " + alert['alertDocument']['alertName'] + "\n\n"
        + "*Alert Description* : " + alert['alertDocument']['alertDescription'] + "\n\n"
        + "*Alert Cause* : " + alert['alertDocument']['alertCause'] + "\n\n"
        + "*Alert Help Text* : " + alert['alertDocument']['alertHelpText'],
        "confidence": "High",
        "incident_time": {
            "opened": datetime.utcfromtimestamp(float(alert['firstTimestampUsecs']) / 1000000).isoformat(),
            "discovered": datetime.utcfromtimestamp(float(alert['firstTimestampUsecs']) / 1000000).isoformat(),
            "reported": datetime.utcfromtimestamp(float(alert['firstTimestampUsecs']) / 1000000).isoformat()
        },
        "schema_version": "1.1.3",
        "status": "New",
        "type": "incident",
        "source": "Cohesity Helios",
        "external_ids": [external_id],
        "title": "Cohesity Helios: " + property_dict.get("object", ""),
        "external_references": [
            {
                "source_name": property_dict.get('source', ''),
                "description": "The source in which the anomalous object is present"
            }
        ]
    }


''' COMMAND FUNCTIONS '''


def get_was_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """get_was_alerts command: Returns Wide Access Sheild Alerts.

    :type client: ``Client``
    :param Client: CohesityDataGovern client to use

    :type args: ``Dict[str, Any]``
    :param args:
        all command arguments, usually passed from ``demisto.args()``.

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains Wide Access Shield Alerts.

    :rtype: ``CommandResults``
    """
    nMins = int(args.get('num_minutes', "30"))

    # Fetch was alerts since last nHours.
    start_time_millis = get_nMin_prev_date_time(nMins)
    end_time_millis = get_current_date_time()
    resp = client.get_was_alerts(start_time_millis, end_time_millis)

    # Parse alerts for readable_output.
    raw_incidences = resp.get('incidences', {})
    incidences = []

    for raw_incidence in raw_incidences:
        occurance_time = get_date_time_from_millis(
            raw_incidence.get("incidenceTimeMsecs")).strftime("%m/%d/%Y, %H:%M:%S")

        incidence = {
            "id": raw_incidence.get("id"),
            "occurance_time": occurance_time,
            "rule_id": raw_incidence.get("ruleId")
        }
        incidences.append(incidence)

    md = tableToMarkdown('Alerts', incidences,
                         ["id", "occurance_time", "ruleID"])

    # return results.
    return CommandResults(
        readable_output=md,
        outputs_prefix='CohesityDataGovern.WASAlert',
        outputs_key_field='id',
        outputs=incidences,
    )


def get_ransomware_alerts_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Get_ransomware_alerts_command: Returns ransomware alerts detected
        in last n hours.
    """
    nMins = int(args.get('num_minutes', "30"))
    start_time_millis = get_nMin_prev_date_time(nMins)

    # Fetch ransomware alerts from client.
    resp = client.get_ransomware_alerts(start_time_millis)

    # Create ransomware incidents from alerts.
    incidences = []

    for alert in resp:
        incident = parse_ransomware_alert(alert)
        incidences.append(incident)

    # CohesityTBD: Parse alert response.
    return CommandResults(
        outputs_prefix='CohesityDataGovern.RansomwareAlert',
        outputs_key_field='alert_id',
        outputs=incidences,
    )


def fetch_incidents_command(client: Client, args: Dict[str, Any]):
    # Get last run details.
    last_run = demisto.getLastRun()

    current_time = datetime.now()
    week_ago = current_time - timedelta(days=7)

    start_time = week_ago
    if last_run and 'start_time' in last_run:
        start_time = get_date_time_from_millis(last_run.get('start_time'))

    start_time_millis = get_millis_from_date_time(start_time)
    end_time_millis = get_current_date_time()

    # Fetch all new incidents.
    incidents = []

    # Fetch new WAS alerts
    resp = client.get_was_alerts(start_time_millis, end_time_millis)

    # Parse alerts for readable_output.
    was_incidences = resp.get('incidences', {})
    for alert in was_incidences:
        incident = create_wide_access_incident(alert)
        incidents.append(incident)

    # Fetch new ransomware alerts.
    ransomware_resp = client.get_ransomware_alerts(start_time_millis)

    # Parse alerts for readable_output.
    for alert in ransomware_resp:
        incident = create_ransomware_incident(alert)
        incidents.append(incident)

    # Update last run.
    demisto.setLastRun({
        'start_time': end_time_millis
    })

    # Send incidents to Cortex-XSOAR.
    demisto.incidents(incidents)


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
        client.get_was_alerts(1631471400000, 1632076199999)
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message

# TODO: ADD additional command functions that translate XSOAR inputs/outputs to Client


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # Get API key for authentication.
    api_key = demisto.params().get('apikey')

    # Get helios service API url.
    base_url = demisto.params()['url']

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # Prepare client and set authentication headers.
        headers: Dict = {
            'apikey': api_key
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

        elif demisto.command() == 'cohesity-get-was-alerts':
            return_results(get_was_alerts_command(client, demisto.args()))

        elif demisto.command() == 'cohesity-get-ransomware-alerts':
            return_results(get_ransomware_alerts_command(client, demisto.args()))

        elif demisto.command() == 'fetch-incidents':
            return_results(fetch_incidents_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
