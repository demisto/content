import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from datetime import datetime

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CLIENT_ID = demisto.params().get('client_id')
SECRET_KEY = demisto.params().get('secret_key')
SERVER = "https://api.wootuno.wootcloud.com"
USE_SSL = not demisto.params().get('insecure', False)
# Service base URL
API_VERSION = '/v1/'
# Headers to be sent in requests
HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Host': 'api.wootuno.wootcloud.com'
}
# How much time to begin retrieving incidents before the first fetch
FETCH_TIME = demisto.params().get('fetch_time', '3 days')
# Fetch filters
ALERT_TYPE = demisto.params().get('alert_type')  # Bluetooth, Packet, Anomaly
SEVERITY_TYPE = demisto.params().get('severity_type')  # Warning, Critical, Notice, Info


''' HELPER FUNCTIONS '''


def item_to_incident(item):
    incident = {}
    # Incident Title
    incident['name'] = 'Incident: ' + item.get('id')
    # Incident occurrence time, usually item creation date in service
    incident['timestamp'] = item.get('timestamp')
    # The raw response from the service, providing full info regarding the item
    incident['rawJSON'] = json.dumps(item)
    return incident


def iter_all_alerts(client, type, start, end, severity=None, skip=None, limit=10, site_id=None):
    """
    Iterate through packet, bluetooth, or anomaly alerts generated in requested time span.
    """
    first = client.get_woot_alerts(type, start, end, severity, skip, limit, site_id, getAll=True)

    alert_type = ''
    if type == 'packet':
        alert_type = 'packet_alerts'
    elif type == 'bluetooth':
        alert_type = 'alerts'  # NOTE: bluetooth alert has same as anamoly alert
    elif type == 'anomaly':
        alert_type = 'alerts'

    total = first['total']
    alerts = first[alert_type]
    step = limit
    while step < total:
        alerts += client.get_woot_alerts(type, start, end, severity, step, limit, site_id, getAll=True)[alert_type]
        step += limit
    return alerts


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def get_woot_alerts(self, type, start, end, severity=None, skip=None, limit=None, site_id=None, getAll=False):
        """
        Lists/fetches packet, bluetooth, or anomaly alerts generated in requested time span.
        """
        if type == "packet":
            url = 'packetalerts'
            prefix = 'WootCloud.PacketAlert'
        elif type == "bluetooth":
            url = 'btalerts'
            prefix = 'WootCloud.BluetoothAlert'
        elif type == "anomaly":
            url = 'anomalies'
            prefix = 'WootCloud.AnomalyAlert'
        else:
            raise ValueError('Type error: {} is not one of the types'.format(type))

        payload = {
            "starttime": str(start),
            "endtime": str(end),
            "filter": {
                "severity": [str(severity)] if severity else None
            },
            "skip": int(skip) if skip else None,
            "limit": int(limit) if limit else None,
            "site_id": str(site_id) if site_id else None
        }
        result = self._http_request('POST', 'events/' + url, json_data=payload)
        # res_json = json.loads(result)

        if getAll:
            return result
        else:
            # total_alerts = res_json.get('total')
            total_alerts = result.get('total')
            if not total_alerts:
                return CommandResults(outputs=result, outputs_prefix=prefix, outputs_key_field='id')
            if type == 'packet':
                result_data = result['packet_alerts']
            else:
                result_data = result['alerts']
            readable_dict = []
            for alert in result_data:
                readable_dict.append({
                    'id': alert.get('id'),
                    'timestamp': alert.get('timestamp'),
                    'severity': alert.get('severity'),
                    'signature': alert.get('signature')
                }
                )
            readable_output = tableToMarkdown("Results for alerts", readable_dict)
            return CommandResults(outputs=result_data, outputs_prefix=prefix, outputs_key_field='id',
                                  readable_output=readable_output)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    """
    Performs basic get request to get information on all WootCloud provided assets
    """
    # using wootassets to test API
    try:
        client._http_request('GET', 'wootassets')
        return 'ok'
    except Exception as e:
        return 'Test failed: {}'.format(e)


def fetch_single_alert(client, alert_id, type):
    """ Fetches single packet by ID. """
    if type == "packet":
        url = 'packetalerts'
        prefix = 'WootCloud.PacketAlert'
    elif type == "bluetooth":
        url = 'btalerts'
        prefix = 'WootCloud.BluetoothAlert'
    elif type == "anomaly":
        url = 'anomalies'
        prefix = 'WootCloud.AnomalyAlert'
    else:
        raise ValueError('{} is not one of the types'.format(type))
    result = client._http_request('GET', f'events/{url}/{alert_id}')
    return CommandResults(outputs=result, outputs_prefix=prefix, outputs_key_field='id')


def fetch_incidents(client, alert_type):
    """
    fetches alerts and turns them into incidents.
    """
    last_run = demisto.getLastRun()
    # Get the last fetch time, if exists
    last_fetch = last_run.get('time')

    # Handle first time fetch, fetch incidents retroactively
    if last_fetch is None:
        fetch_time, _ = parse_date_range(FETCH_TIME)
        last_fetch = fetch_time.strftime(DATE_FORMAT)

    incidents = []
    ###
    items = iter_all_alerts(client, alert_type, last_fetch, datetime.now().strftime(DATE_FORMAT),
                            severity=SEVERITY_TYPE)
    ###
    for item in items:
        incident = item_to_incident(item)
        incident_date = datetime.strptime(incident['timestamp'], DATE_FORMAT)
        # Update last run and add incident if the incident is newer than last fetch
        if incident_date.timestamp() > datetime.strptime(last_fetch, DATE_FORMAT).timestamp():
            last_fetch = incident_date.strftime(DATE_FORMAT)
            incidents.append(incident)
    demisto.setLastRun({'time': last_fetch})
    demisto.incidents(incidents)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(SERVER + API_VERSION, verify=USE_SSL, headers=HEADERS, auth=(CLIENT_ID, SECRET_KEY))

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            fetch_incidents(client, ALERT_TYPE)
        elif demisto.command() == 'wootcloud-get-pkt-alerts':
            starttime, endtime = parse_date_range(demisto.args().get('date_range'), DATE_FORMAT)
            alerts = client.get_woot_alerts('packet', starttime, endtime, severity=demisto.args().get('severity'),
                                            skip=demisto.args().get('skip'), limit=demisto.args().get('limit'),
                                            site_id=demisto.args().get('site_id'))
            return_results(alerts)
        elif demisto.command() == 'wootcloud-get-bt-alerts':
            starttime, endtime = parse_date_range(demisto.args().get('date_range'), DATE_FORMAT)
            alerts = client.get_woot_alerts('bluetooth', starttime, endtime,
                                            severity=demisto.args().get('severity'),
                                            skip=demisto.args().get('skip'),
                                            limit=demisto.args().get('limit'),
                                            site_id=demisto.args().get('site_id'))
            return_results(alerts)
        elif demisto.command() == 'wootcloud-get-anomaly-alerts':
            starttime, endtime = parse_date_range(demisto.args().get('date_range'), DATE_FORMAT)
            alerts = client.get_woot_alerts('anomaly', starttime, endtime,
                                            severity=demisto.args().get('severity'),
                                            skip=demisto.args().get('skip'),
                                            limit=demisto.args().get('limit'),
                                            site_id=demisto.args().get('site_id'))
            return_results(alerts)
        elif demisto.command() == 'wootcloud-fetch-packet-alert':
            alert = fetch_single_alert(client, demisto.args().get('alert_id'), 'packet')
            return_results(alert)
        elif demisto.command() == 'wootcloud-fetch-bluetooth-alert':
            alert = fetch_single_alert(client, demisto.args().get('alert_id'), 'bluetooth')
            return_results(alert)
        elif demisto.command() == 'wootcloud-fetch-anomaly-alert':
            alert = fetch_single_alert(client, demisto.args().get('alert_id'), 'anomaly')
            return_results(alert)
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
