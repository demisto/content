import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import json
import sys
from datetime import datetime

import requests
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
API_URL = f'{demisto.params()["APIUrl"].rstrip("/")}/externalApi'
API_KEY = demisto.params()['APIKey']
API_SECRET = demisto.params()['APISecret']
ALERT_SEVERITY = demisto.params()['AlertSeverity']

USE_SSL = not demisto.params().get('insecure', False)

if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

DEFAULT_HEADERS = {
    "x-api-key": API_KEY,
    "x-api-secret": API_SECRET,
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
}


SCADAFENCE_ALERT_SEVERITY_LEVEL = {
    'Information': 0,
    'Warning': 1,
    'Threat': 2,
    'Severe': 3,
    'Critical': 4
}

''' HELPER FUNCTIONS '''

INCIDENT_TYPES = {
    "IP conflict detected": "SCADAfence IP conlict"
}


def get_alert_severity():
    """
    validate severity values provided as parameter
    :return: set: valid severity values
    """
    s = ALERT_SEVERITY.replace(" ", "")
    s_arr = s.split(",")
    if sum([x in ['Information', 'Warning', 'Threat', 'Severe', 'Critical'] for x in s_arr]) == len(s_arr):
        return set(s_arr)
    raise Exception("Invalid alert severity values")


def http_request(method, url_suffix, params_dict, headers):
    """

    :param method: string: https method
    :param url_suffix: string: API route
    :param params_dict: dict: request parameters
    :param headers: dict: optional http headers
    :return: dict: response data
    """
    req_params = {}
    if params_dict is not None:
        req_params.update(params_dict)

    url = f'{API_URL}{url_suffix}'

    demisto.debug(f'running {method} request with url={url}\theaders={headers}\nparams={json.dumps(req_params)}')
    res_msg = ""
    try:

        if method in ['PATCH', 'POST']:
            data = req_params
            params = None
        else:
            params = req_params
            data = None
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               data=data,
                               params=params,
                               headers=headers
                               )
        if res.text:
            res_msg = res.text
        res.raise_for_status()

        if not res.text:
            return None
        return json.loads(res.text)

    except Exception as e:
        raise Exception(f"{e}\n{res_msg}")


def call_api(method, api_suffix, params):
    """
    Call the requested API path and return its result
    :param api_path: A string beginning with '/' followed by the desired service
    :rtype: dict
    :raises Exception: If the response code is not 200
    :return the response as a dict if possible, otherwise None
    """
    return http_request(method, api_suffix, params, DEFAULT_HEADERS)


def get_alerts(severity, ip, from_date):
    """
    API caller
    :param severity: string: required severity level
    :param from_date: string: lower time limit
    :return: call_api.http_request.data
    """
    api_suffix = "/alerts"
    return call_api('GET', api_suffix, {'severity': severity, 'ip': ip, 'from': from_date})


def fetch_incidents():
    """
    method for polling alerts from SCADAfence alerts API
    :return: list: demisto.incidents
    """
    last_run = demisto.getLastRun()

    last_updated = (datetime(1999, 1, 1, 0, 0, 0, 0), '1999-01-01T00:00:00.0Z')
    if last_run and 'createdOn' in last_run:
        ts_str = last_run.get('createdOn')
        last_updated = (datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%S.%fZ'), ts_str)

    severities = get_alert_severity()

    events = []
    incidents = []
    tmp_time = last_updated

    for severity in severities:
        events = get_alerts(severity, None, last_updated[1])

        for event in events:
            event_ts = datetime.strptime(event['createdOn'], '%Y-%m-%dT%H:%M:%S.%fZ')
            if event_ts > tmp_time[0]:
                tmp_time = (event_ts, event['createdOn'])

            incident = {
                'name': event['type'],
                'occurred': event['createdOn'],
                'severity': SCADAFENCE_ALERT_SEVERITY_LEVEL[event['severity']],
                'rawJSON': json.dumps(event)
            }
            incidents.append(incident)
    if tmp_time[0] > last_updated[0]:

        demisto.setLastRun({
            'createdOn': tmp_time[1]
        })

    demisto.incidents(incidents)


def map_optional_params(keys, api_keys):
    """
    mapping Demisto parameters to SCADAfence API parameters
    :param keys: list: expected demisto parameters
    :param api_keys: valid scadafence parameters
    :return: dict: mapped current function call parameters
    """
    params = {}
    param_keys = list(demisto.args().keys())
    for i, key in enumerate(keys):
        if key in param_keys:
            params[api_keys[i]] = demisto.args()[key]
    return params


def get_assets(asset_data):
    """
    getter for assets data by one or more parameters:
    IP, hostame, type (plc, hmi, IO, Telnel server etc)
    :param asset_data: dict
    :return: call_api.http_request.res.text
    """
    if asset_data:
        api_suffix = "/assets"
        return call_api('GET', api_suffix, asset_data)
    return_error("Invalid call for assets data (missing parameters)")


def get_asset_map(asset_details):
    """
    fetches asset connection data by one or more (combined) parameters
    :param asset_details: disct :{'ip': ip, 'host': hostname, 'mac': mac}
    :return: call_api.http_request.res.text
    """
    if asset_details:
        api_suffix = "/asset/map"
        return call_api('GET', api_suffix, asset_details)
    return_error("Invalid call for asset map (missing parameters)")


def get_assets_map():
    """
    fetches asset connection data by one or more (combined) parameters
    :param asset_details: disct :{'ip': ip, 'host': hostname, 'mac': mac}
    :return: call_api.http_request.res.text
    """
    api_suffix = "/asset/map"
    return call_api('GET', api_suffix, None)


def get_asset_traffic(asset_details):
    """
    fetches asset connection data by one or more (combined) parameters
    :param asset_details: disct :{'ip': ip, 'host': hostname, 'mac': mac}
    :return: call_api.http_request.res.text
    """
    if asset_details:
        api_suffix = "/asset/traffic"
        return call_api('GET', api_suffix, asset_details)
    return_error("Invalid call for asset traffic (missing parameters)")


def dest_endpoint(ep):
    return {
        'ip': ep['dest_ip'],
        'mac': ep['dest_mac'],
        'hostname': ep['dest_hostname'],
        'port': ep['dest_port'],
        'proto': ep['proto'],
        'traffic': ep['traffic']
    }


def src_endpoint(ep):
    return {
        'ip': ep['src_ip'],
        'mac': ep['src_mac'],
        'hostname': ep['src_hostname'],
        'port': ep['src_port'],
        'proto': ep['proto'],
        'traffic': ep['traffic']
    }


def get_endpoint_data(data):
    ret = []
    for ep in data:
        if 'ipAddress' in list(demisto.args().keys()):
            if demisto.args()['ipAddress'] == ep['src_ip']:
                ret.append(dest_endpoint(ep))
            else:
                ret.append(src_endpoint(ep))

        elif 'macAddress' in list(demisto.args().keys()):
            if demisto.args()['macAddress'] == ep['src_mac']:
                ret.append(dest_endpoint(ep))
            else:
                ret.append(src_endpoint(ep))

        else:
            if demisto.args()['hostName'] == ep['src_hostname']:
                ret.append(dest_endpoint(ep))
            else:
                ret.append(src_endpoint(ep))
    return ret


if demisto.command() == 'test-module':
    # This is the call made when pressing the integration test button.
    get_alerts('Critical', None, None)
    demisto.results('ok')
    sys.exit(0)

elif demisto.command() == 'scadafence-createAlert':

    ip = demisto.args()['ipAddress']
    severity = demisto.args()['severity']
    description = demisto.args()['description']
    active = demisto.args()['alertIsActive']
    remediation = demisto.args()['remediationText']

    api_suffix = "/alert"
    alert_data = {
        'ip': ip,
        'severity': severity,
        'details': description,
        'active': active,
        'remediation': remediation
    }
    data = call_api('POST', api_suffix, alert_data)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Create alert:', data),
        'EntryContext': {
            'SCADAfence.Alert': data
        }
    })

elif demisto.command() == 'scadafence-getAlerts':
    ip = None
    severity = None
    if 'ipAddress' in demisto.args():
        ip = demisto.args()['ipAddress']
    if 'severity' in demisto.args():
        severity = demisto.args()['severity']
    data = get_alerts(severity, ip, None)
    output = []
    for alert in data:
        output.append({
            'status': alert['status'],
            'severity': alert['severity'],
            'ip': alert['ip'],
            'details': alert['details'],
            'id': alert['id'],
            'remediation': alert['remediation']
        })
    md = tableToMarkdown('SCADAfence alerts', output)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'SCADAfence.Alert(val.id==obj.id)': output
        }
    })

elif demisto.command() == 'scadafence-setAlertStatus':
    api_suffix = f"/alerts/{demisto.args()['alertId']}"
    alert_status = demisto.args()['alertStatus']
    call_api('PATCH', api_suffix, {'status': alert_status})
    md = tableToMarkdown(f"Setting status for alert {demisto.args()['alertId']} to '{alert_status}':", {"success": True})
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': {"status": alert_status},
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'SCADAfence.Alert.status': alert_status
        }
    })


elif demisto.command() == 'scadafence-getAsset':
    params = map_optional_params(['ipAddress', 'hostName', 'assetType'], ['ip', 'host', 'type'])
    data = get_assets(params)
    md = tableToMarkdown('Asset details: ', data)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'SCADAfence.Asset(val.ip==obj.ip)': data
        }
    })

elif demisto.command() == 'scadafence-getAssetConnections':
    params = map_optional_params(['ipAddress', 'macAddress', 'hostName'], ['ip', 'mac', 'host'])
    data = get_asset_map(params)
    result = get_endpoint_data(data)
    md = tableToMarkdown('Asset connections: ', result)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'SCADAfence.Asset.Conn(val.ip==obj.ip)': result
        }
    })

elif demisto.command() == 'scadafence-getAllConnections':
    data = get_assets_map()
    md = tableToMarkdown('Asset connections: ', data)

    demisto.results({
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'SCADAfence.Connection': data
        }
    })

elif demisto.command() == 'scadafence-getAssetTraffic':

    params = map_optional_params(['ipAddress', 'macAddress', 'hostName'], ['ip', 'mac', 'host'])
    data = get_asset_traffic(params)
    data_x = {
        'TCP_tx_bytes': data['TCP']['Bytes sent'],
        'TCP_rx_bytes': data['TCP']['Bytes received'],
        'UDP_tx_bytes': data['UDP']['Bytes sent'],
        'UDP_rx_bytes': data['UDP']['Bytes received']
    }
    md = tableToMarkdown('Asset network activity: ', data_x)
    demisto.results({
        'Type': entryTypes['note'],
        'Contents': data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            'SCADAfence.AssetTraffic': data_x
        }
    })

elif demisto.command() == 'fetch-incidents':
    demisto.incidents(fetch_incidents())
