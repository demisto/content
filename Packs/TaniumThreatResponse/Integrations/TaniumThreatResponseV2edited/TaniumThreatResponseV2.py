import copy

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import traceback
import os
import ast
import json
import urllib3
import urllib.parse
from dateutil.parser import parse
from typing import Any, Tuple


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' GLOBALS/PARAMS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'


class Client(BaseClient):
    def __init__(self, base_url, username, password, api_token=None, **kwargs):
        self.username = username
        self.password = password
        self.session = ''
        self.api_token = api_token
        super(Client, self).__init__(base_url, **kwargs)

    def do_request(self, method: str, url_suffix: str, data: dict = None, params: dict = None, resp_type: str = 'json',
                   headers: dict = None, body: Any = None):
        if headers is None:
            headers = {}
        if not self.session:
            self.update_session()
        headers['session'] = self.session
        res = self._http_request(method, url_suffix, headers=headers, json_data=data, data=body,
                                 params=params, resp_type='response', ok_codes=(200, 201, 202, 204, 400, 401, 403, 404))

        if res.status_code == 401:
            if self.api_token:
                err_msg = 'Unauthorized Error: please verify that the given API token is valid and that the IP of the ' \
                          'client is listed in the api_token_trusted_ip_address_list global setting.\n'
            else:
                err_msg = ''
            try:
                err_msg += str(res.json())
            except ValueError:
                err_msg += str(res)
            return_error(err_msg)

        # if session expired
        if res.status_code == 403:
            self.update_session()
            res = self._http_request(method, url_suffix, headers=headers, json_data=data, data=body,
                                     params=params, ok_codes=(200, 400, 404))
            return res

        if res.status_code == 404 or res.status_code == 400:
            if res.content:
                raise requests.HTTPError(str(res.content))
            if res.reason:
                raise requests.HTTPError(str(res.reason))
            raise requests.HTTPError(res.json().get('text'))

        if resp_type == 'json':
            try:
                return res.json()
            except json.JSONDecodeError:
                return res.content
        if resp_type == 'text':
            return res.text, res.headers.get('Content-Disposition')
        if resp_type == 'content':
            return res.content, res.headers.get('Content-Disposition')

        return res

    def update_session(self):
        if self.api_token:
            res = self._http_request('GET', 'api/v2/session/current', headers={'session': self.api_token},
                                     ok_codes=(200,))
            if res.get('data'):
                self.session = self.api_token
        elif self.username and self.password:
            body = {
                'username': self.username,
                'password': self.password
            }

            res = self._http_request('GET', '/api/v2/session/login', json_data=body, ok_codes=(200,))

            self.session = res.get('data').get('session')
        else:  # no API token and no credentials were provided, raise an error:
            return_error('Please provide either an API Token or Username & Password.')
        return self.session

    def login(self):
        return self.update_session()


''' ALERTS DOCS HELPER FUNCTIONS '''


def get_alert_item(alert):
    return {
        'ID': alert.get('id'),
        'AlertedAt': alert.get('alertedAt'),
        'ComputerIpAddress': alert.get('computerIpAddress'),
        'ComputerName': alert.get('computerName'),
        'CreatedAt': alert.get('createdAt'),
        'GUID': alert.get('guid'),
        'IntelDocId': alert.get('intelDocId'),
        'Priority': alert.get('priority'),
        'Severity': alert.get('severity'),
        'State': alert.get('state').title(),
        'Type': alert.get('type'),
        'UpdatedAt': alert.get('updatedAt')}


''' FETCH INCIDENTS HELPER FUNCTIONS '''


def alarm_to_incident(client, alarm):
    host = alarm.get('computerName', '')

    if details := alarm.get('details'):
        alarm_details = json.loads(details)
        alarm['details'] = alarm_details

    intel_doc = ''
    if intel_doc_id := alarm.get('intelDocId', ''):
        raw_response = client.do_request('GET', f'/plugin/products/detect3/api/v1/intels/{intel_doc_id}')
        intel_doc = raw_response.get('name')

    return {
        'name': f'{host} found {intel_doc}',
        'occurred': alarm.get('alertedAt'),
        'starttime': alarm.get('createdAt'),
        'rawJSON': json.dumps(alarm)}


def state_params_suffix(alerts_states_to_retrieve):
    valid_alert_states = ['unresolved', 'inprogress', 'resolved', 'suppressed']

    for state in alerts_states_to_retrieve:
        if state.lower() not in valid_alert_states:
            raise ValueError(f'Invalid state \'{state}\' in filter_alerts_by_state parameter.'
                             f'Possible values are \'unresolved\', \'inprogress\', \'resolved\' or \'suppressed\'.')

    alerts_string = ['state=' + state.lower() for state in alerts_states_to_retrieve]
    return '&'.join(alerts_string) if alerts_string else ''


''' COMMANDS + REQUESTS FUNCTIONS '''
''' GENERAL COMMANDS FUNCTIONS '''


def test_module(client, data_args):
    try:
        if client.login():
            return demisto.results('ok')
    except Exception as e:
        raise ValueError(f'Please check your credentials and try again. Error is:\n{str(e)}')


def fetch_incidents(client, alerts_states_to_retrieve, last_run, fetch_time, max_fetch):
    """
    Fetch events from this integration and return them as Demisto incidents

    returns:
        Demisto incidents
    """
    # Get the last fetch time and data if it exists
    last_fetch = last_run.get('time')
    last_id = int(last_run.get('id', '0'))
    alerts_states = argToList(alerts_states_to_retrieve)

    # Handle first time fetch, fetch incidents retroactively
    if not last_fetch:
        last_fetch, _ = parse_date_range(fetch_time, date_format=DATE_FORMAT)

    demisto.debug(f'Get last run: last_id {last_id}, last_time: {last_fetch}.\n')

    last_fetch = parse(last_fetch)
    current_fetch = last_fetch

    url_suffix = '/plugin/products/detect3/api/v1/alerts?' + state_params_suffix(alerts_states) + '&limit=500'

    raw_response = client.do_request('GET', url_suffix)

    # convert the data/events to demisto incidents
    incidents = []
    for alarm in raw_response:
        incident = alarm_to_incident(client, alarm)
        temp_date = parse(incident.get('starttime'))
        new_id = alarm.get('id')
        demisto.debug(f'Fetched new alert, id: {new_id}, created_at: {temp_date}.\n')

        # update last run
        if temp_date > last_fetch:
            last_fetch = temp_date
            demisto.debug(f'Last fetch changed from: {last_fetch} to: {temp_date}.\n')

        # avoid duplication due to weak time query
        if temp_date >= current_fetch and new_id > last_id:
            demisto.debug(f'Current fetch {current_fetch}.\nAdding new incident with id: {new_id}')
            incidents.append(incident)
            last_id = new_id

        if len(incidents) >= max_fetch:
            break

    next_run = {'time': datetime.strftime(last_fetch, DATE_FORMAT), 'id': str(last_id)}

    demisto.debug(f'Set last run: last_id {last_id}, last_time: {last_fetch}.\n')
    demisto.debug(f'Fetched {len(incidents)} incidents.')

    return incidents, next_run


''' ALERTS COMMANDS FUNCTIONS '''


def get_alerts(client, data_args) -> Tuple[str, dict, Union[list, dict]]:
    """ Get alerts from tanium.

        :type client: ``Client``
        :param client: client which connects to api.
        :type data_args: ``dict``
        :param data_args: request arguments.

        :return: human readable format, context output and the original raw response.
        :rtype: ``tuple``

    """
    limit = arg_to_number(data_args.get('limit'))
    offset = arg_to_number(data_args.get('offset'))
    ip_address = data_args.get('computer_ip_address')
    computer_name = data_args.get('computer_name')
    scan_config_id = data_args.get('scan-config-id')
    intel_doc_id = data_args.get('intel_doc_id')
    severity = data_args.get('severity')
    priority = data_args.get('priority')
    type_ = data_args.get('type')
    state = data_args.get('state')

    params = assign_params(type=type_,
                           priority=priority,
                           severity=severity,
                           intelDocId=intel_doc_id,
                           scanConfigId=scan_config_id,
                           computerName=computer_name,
                           computerIpAddress=ip_address,
                           limit=limit,
                           offset=offset, state=state.lower() if state else None)

    raw_response = client.do_request('GET', '/plugin/products/detect3/api/v1/alerts/', params=params)

    alerts = []
    for item in raw_response:
        alert = get_alert_item(item)
        alerts.append(alert)

    context = createContext(alerts, removeNull=True)
    headers = ['ID', 'Type', 'State', 'Severity', 'Priority', 'AlertedAt', 'CreatedAt', 'UpdatedAt', 'ComputerIpAddress',
               'ComputerName', 'GUID', 'State', 'IntelDocId']
    outputs = {'Tanium.Alert(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Alerts', alerts, headers=headers,
                                     headerTransform=pascalToSpace, removeNull=True)
    return human_readable, outputs, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')

    api_token = password if '_token' in username else None

    # Remove trailing slash to prevent wrong URL path to service
    server = params['url'].strip('/')
    # Should we use SSL
    use_ssl = not params.get('insecure', False)

    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()

    client = Client(
        server,
        username,
        password,
        api_token=api_token,
        verify=use_ssl
    )

    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'tanium-tr-list-alerts': get_alerts
    }

    try:
        if command == 'fetch-incidents':
            # demisto.getLastRun() will returns an obj with the previous run in it.
            last_run = demisto.getLastRun()
            alerts_states_to_retrieve = demisto.params().get('filter_alerts_by_state')
            first_fetch = demisto.params().get('first_fetch')
            max_fetch = int(demisto.params().get('max_fetch', '50'))

            incidents, next_run = fetch_incidents(client, alerts_states_to_retrieve, last_run, first_fetch, max_fetch)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

    except Exception as e:
        if command == 'fetch-incidents':
            LOG(traceback.format_exc())
            LOG.print_log()
            raise

        else:
            error_msg = str(e)
            return_error('Error in Tanium Threat Response Integration: {}'.format(error_msg), traceback.format_exc())


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
