import json
import traceback
from typing import Dict, List, Optional, Tuple, Union
from datetime import datetime

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
apiVersion = "v1"
'''GLOBALS/PARAMS'''

INTEGRATION_NAME = 'NCURITY - Ncurion'
INTEGRATION_CONTEXT_NAME = 'Ncurion'


def login(base_url, username, password):
    api_url = base_url + '/napi/api/v1/apikey'
    payload = json.dumps({
        "username": username,
        "password": password
    })
    headers = {
        "Content-Type": "application/json"
    }
    verify_certificate = not demisto.params().get('insecure', False)
    response = requests.request("POST", api_url, data=payload, headers=headers, verify=verify_certificate)
    access_token = response.json().get("access_token")
    refresh_token = response.json().get("refresh_token")
    headers1 = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    return access_token, refresh_token, headers1


def loglist(base_url, access_token, refresh_token, headers1):
    base_url1 = base_url + '/logapi/api/v2/logmgr/0'
    verify_certificate = not demisto.params().get('insecure', False)
    loglist = requests.request("GET", base_url1, headers=headers1, verify=verify_certificate)
    data = loglist.text
    log_list = json.loads(data)
    return log_list


def raw_response_to_context_rules(items: Union[Dict, List]) -> Union[Dict, List]:
    if isinstance(items, list):
        return [raw_response_to_context_rules(item) for item in items]
    return {
        'Id': items.get('id'),
        'Name': items.get('name'),
        'Host': items.get('host'),
        'Log_storage_month_period': items.get('log_storage_month_period'),
        'Useno': items.get('useno'),
        'Sync_state': items.get('sync_state'),
        'Is_connected': items.get('is_connected'),
        'Description': items.get('description'),
        'Created_at': items.get('created_at'),
        'Updated_at': items.get('updated_at')
    }


def switch_list_to_list_counter(data: Union[Dict, List]) -> Union[Dict, List]:
    if isinstance(data, list):
        return [switch_list_to_list_counter(dat) for dat in data]
    new_data = {}
    for item in data:
        if type(data[item]) == list:
            new_data[item] = len(data[item])
        elif data[item] and type(data[item]) == dict:
            counter = 0
            for in_item in data[item]:
                if type(data[item][in_item]) == list:
                    counter += len(data[item][in_item])
                elif data[item][in_item]:
                    counter = 1 if counter == 0 else counter
            new_data[item] = counter
        else:
            new_data[item] = data[item]
    return new_data


def get_log_list(base_url, username, password):
    access_token, refresh_token, headers1 = login(base_url, username, password)
    logserver_url = base_url + '/logapi/api/v2/logmgr/0'
    verify_certificate = not demisto.params().get('insecure', False)
    log_list = requests.request("GET", logserver_url, headers=headers1, verify=verify_certificate)
    data = log_list.text
    items = json.loads(data)
    context_entry = raw_response_to_context_rules(items)
    api_log_out(base_url, access_token, refresh_token, headers1)
    results = CommandResults(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.logsever',
        outputs_key_field='id',
        outputs=context_entry
    )
    return_results(results)


def fetch_incidents(base_url, username, password, last_run: Dict[str, int], first_fetch_time: Optional[int]) 
                    -> Tuple[Dict[str, int], List[dict]]:
    access_token, refresh_token, headers1 = login(base_url, username, password)
    log_list = loglist(base_url, access_token, refresh_token, headers1)
    log_server_id = [e["id"] for e in log_list if e["is_connected"] == True]
    last_fetch = last_run.get('last_fetch', None)

    if len(log_server_id) == 0:
        return_output('ok')
    else:
            max_fetch = demisto.params().get('max_fetch')
            #incidents: List[Dict[str, Any]] = []
            incidents = []
            now_time = datetime.datetime.utcnow()
            params1 = {"start": f"{last_fetch}", "end": f"{now_time}", "size": max_fetch}
            verify_certificate = not demisto.params().get('insecure', False)

            for i in log_server_id:

                base_url_log = base_url + f'/logapi/api/v1/logserver/search/alert/search/{i}'

                response_log = requests.request("GET", base_url_log, headers=headers1, params=params1, verify=verify_certificate)
                data = response_log.json()
                for hit in data:
                    incident = {
                        'name': hit['alert']['category'] + hit['alert']['signature'],
                        'occured': hit['@timestamp'],
                        'rawJSON': json.dumps(hit)
                    }
                    incidents.append(incident)

    next_run = {'last_fetch': f'{now_time}'}

    logout = json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token
    })
    remove_url = base_url + '/napi/api/v1/apikey/remove'
    requests.request("POST", remove_url, headers=headers1, data=logout, verify=verify_certificate)
    return next_run, incidents


def api_log_out(base_url, access_token, refresh_token, headers1):
    logout = json.dumps({
        "access_token": access_token,
        "refresh_token": refresh_token
    })
    remove_url = base_url + '/napi/api/v1/apikey/remove'
    verify_certificate = not demisto.params().get('insecure', False)
    requests.request("POST", remove_url, headers=headers1, data=logout, verify=verify_certificate)


def main():
    params = demisto.params()
    base_url = params.get('base_url')
    username = params.get('username')
    password = params.get('password')

    first_fetch_time = arg_to_datetime(
        arg=demisto.params().get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True
    )
    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        if command == 'test-module':
            api_url = base_url + '/napi/api/v1/apikey'
            payload = json.dumps({
                "username": username,
                "password": password
            })
            headers = {
                "Content-Type": "application/json"
            }
            response = requests.request("POST", api_url, data=payload, headers=headers, verify=False)
            if response.status_code == 200:
                return_outputs('ok')
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                base_url, username, password,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_timestamp
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        elif command == 'ncurion-get-log-list':
            return_outputs(get_log_list(base_url, username, password))
    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
