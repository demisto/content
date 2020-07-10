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
USERNAME = demisto.params().get('client_id')
PASSWORD = demisto.params().get('secret_key')
SERVER = "https://api.wootuno.wootcloud.com"
SSL_VERIFY = True
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
    first = client.get_woot_alerts(type, start, end, severity, skip, limit, site_id)

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
        alerts += client.get_woot_alerts(type, start, end, severity, step, limit, site_id)[alert_type]
        step += limit
    return alerts


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """
    def __init__(self, server, ssl_verify, api_version, headers, username, password):
        self.server = server
        self.ssl_verify = ssl_verify
        self.api_version = api_version
        self.headers = headers
        self.username = username
        self.password = password

    def http_request(self, method, url_suffix, params=None, json=None):
        # A wrapper for requests lib to send our requests and handle requests and responses better
        res = requests.request(
            method,
            self.server + self.api_version + url_suffix,
            verify=self.ssl_verify,
            params=params,
            json=json,
            headers=self.headers,
            auth=requests.auth.HTTPBasicAuth(self.username, self.password)
        )
        # Handle error responses gracefully
        if res.status_code == 401:
            return_error("API credentials failed to authenticate. Please verify Client ID and API key are correct.")
        elif res.status_code not in {200}:
            return_error('Error in API call to WootCloud [%d] - %s' % (res.status_code, res.reason))

        return res.json()

    def get_woot_alerts(self, type, start, end, severity=None, skip=None, limit=None, site_id=None):
        """
        Lists/fetches packet, bluetooth, or anomaly alerts generated in requested time span.
        """
        if type == "packet":
            url = 'packetalerts'
        elif type == "bluetooth":
            url = 'btalerts'
        elif type == "anomaly":
            url = 'anomalies'
        else:
            return_error('Type error: %s is not one of the types' % type)

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
        return self.http_request('POST', 'events/' + url, json=payload)


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    """
    Performs basic get request to get information on all WootCloud provided assets
    """
    # using wootassets to test API
    try:
        client.http_request('GET', 'wootassets')
        return 'ok'
    except Exception as e:
        LOG(e)
        return 'not ok'


def fetch_single_alert(client, alert_id, type):
    """ Fetches single packet by ID. """
    if type == "packet":
        url = 'packetalerts'
    elif type == "bluetooth":
        url = 'btalerts'
    elif type == "anomaly":
        url = 'anomalies'
    else:
        return_error('Type error: %s is not one of the types' % type)
    return client.http_request('GET', 'events/%s/%s' % (url, alert_id))


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
        client = Client(SERVER, SSL_VERIFY, API_VERSION, HEADERS, USERNAME, PASSWORD)

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
            return_results(CommandResults(outputs=alerts['packet_alerts'],
                                          outputs_prefix='WootCloud.PacketAlert',
                                          outputs_key_field='id'))
        elif demisto.command() == 'wootcloud-get-bt-alerts':
            starttime, endtime = parse_date_range(demisto.args().get('date_range'), DATE_FORMAT)
            alerts = client.get_woot_alerts('bluetooth', starttime, endtime,
                                            severity=demisto.args().get('severity'),
                                            skip=demisto.args().get('skip'),
                                            limit=demisto.args().get('limit'),
                                            site_id=demisto.args().get('site_id'))
            return_results(CommandResults(outputs=alerts['alerts'],
                                          outputs_prefix='WootCloud.BluetoothAlert',
                                          outputs_key_field='id'))
        elif demisto.command() == 'wootcloud-get-anomaly-alerts':
            starttime, endtime = parse_date_range(demisto.args().get('date_range'), DATE_FORMAT)
            alerts = client.get_woot_alerts('anomaly', starttime, endtime,
                                            severity=demisto.args().get('severity'),
                                            skip=demisto.args().get('skip'),
                                            limit=demisto.args().get('limit'),
                                            site_id=demisto.args().get('site_id'))
            return_results(CommandResults(outputs=alerts['alerts'],
                                          outputs_prefix='WootCloud.AnomalyAlert',
                                          outputs_key_field='id'))
        elif demisto.command() == 'wootcloud-fetch-packet-alert':
            alert = fetch_single_alert(client, demisto.args().get('alert_id'), 'packet')
            return_results(CommandResults(outputs=alert, outputs_prefix='WootCloud.PacketAlert',
                                          outputs_key_field='id'))
        elif demisto.command() == 'wootcloud-fetch-bt-alert':
            alert = fetch_single_alert(client, demisto.args().get('alert_id'), 'bluetooth')
            return_results(CommandResults(outputs=alert, outputs_prefix='WootCloud.BluetoothAlert',
                                          outputs_key_field='id'))
        elif demisto.command() == 'wootcloud-fetch-anomaly-alert':
            alert = fetch_single_alert(client, demisto.args().get('alert_id'), 'anomaly')
            return_results(CommandResults(outputs=alert, outputs_prefix='WootCloud.AnomalyAlert',
                                          outputs_key_field='id'))
    # Log exceptions
    except Exception as e:
        LOG(e)
        LOG.print_log()
        raise


if __name__ == "builtins":
    main()
