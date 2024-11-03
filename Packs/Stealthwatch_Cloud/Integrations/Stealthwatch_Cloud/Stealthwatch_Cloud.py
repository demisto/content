import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''
import requests
import json
import os
from datetime import datetime, timedelta
import collections
import urllib3

urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER = demisto.params().get('serverURL', '').strip('/')
SERVER_URL = SERVER + '/api/v3'
API_KEY = demisto.params().get('credentials_api_key', {}).get('password') or demisto.params().get('APIKey')

USE_SSL = not demisto.params().get('insecure')

DEFAULT_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': API_KEY
}

''' HELPER FUNCTIONS '''

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


def http_request(method, url_suffix, params_dict=None, headers=DEFAULT_HEADERS, data=None):
    req_params = {}  # type: Dict[Any,Any]
    if params_dict is not None:
        req_params.update(params_dict)

    url = SERVER_URL + url_suffix

    LOG(f'running {method} request with url={url}\tparams={json.dumps(req_params)}')

    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=req_params,
                               headers=headers,
                               data=data
                               )
        res.raise_for_status()
        try:
            return res.json()
        except ValueError:
            # in case the response doesn't have JSON
            return "Request completed"
    except Exception as e:
        LOG(e)
        raise (e)


def underscore_to_camelcase(word):
    return ' '.join(x.capitalize() or '_' for x in word.split('_'))


def create_incident_data_from_alert(alert):
    alert.pop('comments')
    alert.pop('observations')
    return {
        'name': 'Stealthwatch alert ' + str(alert.get('id', '')),
        'rawJSON': json.dumps(alert),
        'occurred': alert.get('created', '')
    }


def get_latest_id(alerts_data):
    latest_id = 0
    for alert in alerts_data:
        current_id = alert.get('id', None)
        if current_id is not None and current_id > latest_id:
            latest_id = current_id

    return latest_id


''' COMMANDS FUNCTIONS '''


def show_alert(alert_id):
    """
    Returns alert by specific id
    """

    api_endpoint = f"/alerts/alert/{alert_id}/"
    return http_request('GET', api_endpoint, {}, DEFAULT_HEADERS)


def show_alert_command():
    """
    corresponds to 'sw-show-alert' command. Returns information about a specific alert
    """
    alert_id = demisto.args().get('alertID')

    alert_data = show_alert(alert_id)

    if demisto.args().get('addComments', False) != 'true':
        alert_data.pop('comments')
        alert_data.pop('new_comment')

    alert_data.pop('observations')

    list_for_md = ['resolved', 'id', 'last_modified', 'obj_created', 'assigned_to']

    dict_for_md = {underscore_to_camelcase(k): v for k, v in alert_data.items() if k in list_for_md}
    md = tableToMarkdown(alert_data.get('text', ''), dict_for_md)

    return {
        'Type': entryTypes['note'],
        'Contents': alert_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            "Stealthwatch.Alert(val.id==obj.id)": alert_data
        }
    }


def update_alert(alert_id, data):
    """
    Updates alert by specific id
    """

    api_endpoint = f"/alerts/alert/{alert_id}/"
    return http_request('PUT', api_endpoint, data=json.dumps(data))


def update_alert_command():
    """
    corresponds to 'sw-update-alert' command. Returns information about a specific alert
    """
    args = demisto.args()
    alert_id = args.get('alertID')
    update_params = {}
    # adding the possible params for update
    possible_params = ['new_comment', 'tags', 'publish_time', 'resolved', 'snooze_settings', 'merit', 'assigned_to']
    for param in possible_params:
        current_param = args.get(param, False)
        if current_param:
            update_params[param] = current_param
    username = args.get('resolved_user', None)
    if username is not None:
        update_params['resolved_user'] = {
            'username': username
        }

    alert_data = update_alert(alert_id, update_params)

    alert_data.pop('comments')
    alert_data.pop('new_comment')
    alert_data.pop('observations')

    list_for_md = ['resolved', 'id', 'last_modified', 'obj_created', 'assigned_to']

    dict_for_md = {k: v for k, v in alert_data.items() if k in list_for_md}
    md = tableToMarkdown(alert_data.get('text', ''), dict_for_md)

    return {
        'Type': entryTypes['note'],
        'Contents': alert_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            "Stealthwatch.Alert(val.id==obj.id)": alert_data
        }
    }


def list_alerts(params):
    """
    Retrieves alerts
    """

    api_endpoint = "/alerts/alert/"
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def build_alert_dic(alert):
    dic = collections.OrderedDict()  # type: Dict[str,str]
    list_for_md = ['id', 'last_modified', 'resolved', 'text', 'obj_created', 'assigned_to', 'description']
    for item in list_for_md:
        dic[underscore_to_camelcase(item)] = alert[item]

    return dic


def list_alerts_command():
    """
    corresponds to 'sw-list-alerts' command. Returns a list of Stealthwatch alerts
    """
    args = demisto.args()
    list_params = {}
    # adding the possible params for update
    possible_params = ['status', 'tags', 'search', 'assignee', 'limit']
    for param in possible_params:
        current_param = args.get(param, False)
        if current_param:
            list_params[param] = current_param

    alerts_data = list_alerts(list_params).get('objects')
    md_dicts_list = []

    for alert in alerts_data:
        if demisto.args().get('addComments', False) != 'true':
            alert.pop('comments')
            alert.pop('new_comment')
        alert.pop('observations')
        md_dicts_list.append(build_alert_dic(alert))

    md = tableToMarkdown("The following alerts were retrieved", md_dicts_list)
    return {
        'Type': entryTypes['note'],
        'Contents': alerts_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': md,
        'EntryContext': {
            "Stealthwatch.Alert(val.id==obj.id)": alerts_data
        }
    }


def domain_block(params):
    """
    Updates domain blacklist status
    """

    api_endpoint = "/blacklist/domains/"
    return http_request('POST', api_endpoint, {}, DEFAULT_HEADERS, params)


def block_domain_command():
    """
    corresponds to 'sw-block-domain-or-ip' command. Adds a domain to the blacklist
    """
    domain = demisto.args().get('domain')
    ip = demisto.args().get('ip')

    if not (domain or ip):
        return {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": 'Please enter either domain or ip'
        }

    if domain and ip:
        return {
            "Type": entryTypes["error"],
            "ContentsFormat": formats["text"],
            "Contents": 'Please enter only domain or ip, not both'
        }

    identifier = None
    if domain:
        identifier = domain
    else:
        identifier = ip

    domain_params = {
        "identifier": identifier,
        "category": "domain",
        "list_on": "blacklist"
    }

    domain_result = domain_block(json.dumps(domain_params))

    ec = None

    if domain:
        ec = {
            "Stealthwatch.Domain(val.identifier==obj.identifier)": domain_result
        }
    else:
        ec = {
            "Stealthwatch.IP(val.identifier==obj.identifier)": domain_result
        }

    return {
        'Type': entryTypes['note'],
        'Contents': domain_result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Blacklist ' + domain + ' result', domain_result),
        'EntryContext': ec
    }


def domain_unblock(domain_id):
    """
    Removes domain from the blacklist
    """

    api_endpoint = f"/blacklist/domains/{domain_id}/"
    return http_request('DELETE', api_endpoint, None, DEFAULT_HEADERS, None)


def unblock_domain_command():
    """
    corresponds to 'sw-unblock-domain' command. Removes a domain to the blacklist
    """
    domain_id = demisto.args().get('id')

    domain_result = domain_unblock(domain_id)

    return {
        'Type': entryTypes['note'],
        'Contents': domain_result,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': 'Unblocked domain with id: ' + domain_id,
    }


def list_domains(list_params):
    """
    Lists blacklisted domains
    """

    api_endpoint = "/blacklist/domains/"
    return http_request('GET', api_endpoint, list_params, DEFAULT_HEADERS, {})


def list_blocked_domains_command():
    """
    corresponds to 'sw-list-blocked-domains' command. Returns a list of the blocked domains
    """
    args = demisto.args()
    list_params = {}
    # adding the possible params for update
    possible_params = ['search', 'limit']
    for param in possible_params:
        current_param = args.get(param, False)
        if current_param:
            list_params[param] = current_param

    specific_domain = args.get('domain', None)
    if specific_domain is not None:
        list_params['identifier'] = specific_domain

    domains_data = list_domains(list_params)

    domains_result = domains_data.get('objects', {})

    data_output = []
    for obs in domains_result:
        data_output.append({underscore_to_camelcase(k): v for k, v in list(obs.items())})

    return {
        'Type': entryTypes['note'],
        'Contents': domains_data,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Current blacklisted domains are', data_output),
        'EntryContext': {
            "Stealthwatch.Domain(val.identifier==obj.identifier)": domains_result
        }
    }


def list_observations(params):
    """
    Lists observations
    """

    api_endpoint = "/observations/all/"
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def list_observations_command():
    """
    corresponds to 'sw-list-observations' command. Returns a list of Stealthwatch observations
    """
    args = demisto.args()
    list_params = {
        "ordering": 'creation_time'
    }
    # adding the possible params for update
    possible_params = ['alert', 'id', 'search', 'limit']
    for param in possible_params:
        current_param = args.get(param, False)
        if current_param:
            list_params[param] = current_param

    observations_data = list_observations(list_params).get('objects')

    data_output = []
    for obs in observations_data:
        data_output.append({underscore_to_camelcase(k): v for k, v in list(obs.items())})

    return {
        'Type': entryTypes['note'],
        'Contents': data_output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Found the following observations', data_output),
        'EntryContext': {
            "Stealthwatch.Observation(val.id==obj.id)": observations_data
        }
    }


def list_sessions(params):
    """
    Lists observations
    """

    api_endpoint = "/snapshots/session-data/"
    return http_request('GET', api_endpoint, params, DEFAULT_HEADERS)


def list_sessions_command():
    """
    corresponds to 'sw-list-sessions' command. Returns a list of Stealthwatch
    sessions
    """
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    list_params = {}

    ip = demisto.args().get('ip')
    connected_ip = demisto.args().get('connectedIP')
    connected_device_id = demisto.args().get('connectedDeviceId')
    limit = demisto.args().get('limit')
    start_time = demisto.args().get('startTime', None)
    end_time = demisto.args().get('endTime', None)
    session_type = demisto.args().get('sessionType', 'all')

    if start_time and end_time:
        list_params['start_datetime'] = start_time
        list_params['end_datetime'] = end_time
    elif end_time is None:
        start_time_object = datetime.strptime(start_time, date_format)
        start_time_object = start_time_object - timedelta(minutes=5)
        end_time_object = start_time_object + timedelta(minutes=5)
        start_time = start_time_object.strftime(date_format)
        end_time = end_time_object.strftime(date_format)

    list_params['ip'] = ip
    list_params['connected_ip'] = connected_ip
    list_params['limit'] = limit
    list_params['start_datetime'] = start_time
    list_params['end_datetime'] = end_time
    list_params['connected_device_id'] = connected_device_id

    unique_session_ids = []  # type: List[str]
    final_sessions_data = []
    sessions_data = list_sessions(list_params).get('objects')
    for sess in sessions_data:
        if sess['connected_ip'] not in unique_session_ids:
            unique_session_ids.append(sess['connected_ip'])
            if demisto.get(sess, 'connected_device_id'):
                sess['connected_device_is_external'] = False
                if session_type == 'internal':
                    final_sessions_data.append(sess)
            else:
                sess['connected_device_is_external'] = True
                if session_type == 'external':
                    final_sessions_data.append(sess)
            if session_type == 'all':
                final_sessions_data.append(sess)

    data_output = []
    for sess in final_sessions_data:
        data_output.append({underscore_to_camelcase(k): v for k, v in list(sess.items())})

    return {
        'Type': entryTypes['note'],
        'Contents': data_output,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Found the following session data', data_output),
        'EntryContext': {
            "Stealthwatch.Session(val.id==obj.id)": final_sessions_data
        }
    }


def fetch_incidents():
    date_format = "%Y-%m-%dT%H:%M:%SZ"

    list_params = {
        "ordering": 'created',
        "limit": 100
    }
    final_alerts = []
    last_fetch_string = demisto.getLastRun().get('last_fetch_time', None)
    ids = demisto.getLastRun().get('ids', None)
    first_time = (not last_fetch_string and ids is not None)

    if last_fetch_string is None or not last_fetch_string:
        now = datetime.now()
        last_fetch = now - timedelta(days=20)
    else:
        last_fetch = parse_date_string(last_fetch_string)

    # Couldn't find a way to sort descending so looking for last offset of 100 alerts
    alerts_response = list_alerts(list_params)
    num_alerts = alerts_response.get('meta', {'total_count': 100}).get('total_count')
    offset = 0 if num_alerts < 100 else num_alerts - 100
    list_params['offset'] = offset
    alerts_response = list_alerts(list_params)

    alerts_data = alerts_response.get('objects', [])
    max_fetch_time = last_fetch_string if last_fetch_string else now.strftime(date_format)

    for alert in alerts_data:
        created = alert.get('created')
        if parse_date_string(created) > last_fetch:
            incident_from_alert = create_incident_data_from_alert(alert)
            if first_time:
                if alert.get('id') not in ids:
                    final_alerts.append(incident_from_alert)
            else:
                final_alerts.append(incident_from_alert)
            if parse_date_string(created) > parse_date_string(max_fetch_time):
                max_fetch_time = created

    demisto.setLastRun({
        'last_fetch_time': max_fetch_time
    })
    demisto.incidents(final_alerts)


''' EXECUTION CODE '''


def main():
    demisto.debug(f'Command being called is {demisto.command()}')
    if not API_KEY:
        raise DemistoException('Stealthwatch Cloud API key must be provided.')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            if list_alerts_command():
                demisto.results('ok')
            else:
                demisto.results('test failed')
        elif demisto.command() == 'sw-show-alert':
            demisto.results(show_alert_command())
        elif demisto.command() == 'sw-update-alert':
            demisto.results(update_alert_command())
        elif demisto.command() == 'sw-list-alerts':
            demisto.results(list_alerts_command())
        elif demisto.command() == 'sw-block-domain-or-ip':
            demisto.results(block_domain_command())
        elif demisto.command() == 'sw-unblock-domain':
            demisto.results(unblock_domain_command())
        elif demisto.command() == 'sw-list-blocked-domains':
            demisto.results(list_blocked_domains_command())
        elif demisto.command() == 'sw-list-observations':
            demisto.results(list_observations_command())
        elif demisto.command() == 'sw-list-sessions':
            demisto.results(list_sessions_command())
        elif demisto.command() == 'fetch-incidents':
            demisto.results(fetch_incidents())
    except Exception as e:
        return_error(f'error has occurred: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
