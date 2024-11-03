import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import itertools
import time
from datetime import datetime, timedelta
from collections.abc import Callable

from urllib3 import disable_warnings

disable_warnings()

CONTEXT_INTEGRATION_NAME = 'McAfeeESM.'


class EmptyFile(Exception):
    pass


class McAfeeESMClient(BaseClient):
    demisto_format = '%Y-%m-%dT%H:%M:%SZ'

    def __init__(self, params: dict):
        self.args = demisto.args()
        self.__user_name = params.get('credentials', {}).get('identifier', '')
        self.__password = params.get('credentials', {}).get('password', '')
        self.difference = int(params.get('timezone', 0))
        self.version = params.get('version', '10.2')
        super(McAfeeESMClient, self).__init__(
            '{}/rs/esm/v2/'.format(params.get('url', '').strip('/')),
            proxy=params.get('proxy', False),
            verify=not params.get('insecure', False)
        )
        self._headers = {'Content-Type': 'application/json'}
        self.__login()
        self.__cache: dict = {
            'users': [],
            'org': [],
            'status': []
        }

    def __del__(self):
        self.__logout()
        super().__del__()

    def _is_status_code_valid(self, *_other):  # noqa
        return True

    def __request(self, mcafee_command: str, data: Union[str, dict] = None, params: dict = None):
        if data:
            data = json.dumps(data)
        result = self._http_request('POST', mcafee_command, data=data,
                                    params=params, resp_type='request', timeout=60)
        if result.ok:
            if result.content:
                return result.json()
            else:
                return {}
        else:
            raise DemistoException(f'{mcafee_command} failed with error[{result.content.decode()}].')

    def __login(self):
        params = {
            'username': base64.b64encode(self.__user_name.encode('ascii')).decode(),
            'password': base64.b64encode(self.__password.encode('ascii')).decode(),
            'locale': 'en_US'
        }
        res = self._http_request('POST', 'login', data=json.dumps(params), resp_type='response', timeout=20)
        self._headers['Cookie'] = 'JWTToken={}'.format(res.cookies.get('JWTToken'))
        self._headers['X-Xsrf-Token'] = res.headers.get('Xsrf-Token')
        if None in (self._headers['X-Xsrf-Token'], self._headers['Cookie']):
            raise DemistoException(f'Failed login\nurl: {self._base_url}login\nresponse '
                                   f'status: {res.status_code}\nresponse: {res.text}\n')

    def __logout(self):
        self._http_request('DELETE', 'logout', resp_type='response')

    def test_module(self) -> tuple[str, dict, str]:
        params = demisto.params()

        # check credentials
        self.get_organization_list(raw=True)

        # check fetch parameters
        if params.get('isFetch'):
            start_id = params.get('startingFetchID', '0')
            if not start_id.isdigit():
                raise DemistoException(f'Invalid startingFetchID value. Expected: numeric value, Received "{start_id}"')

        return 'ok', {}, 'ok'

    def __username_and_id(self, user_name: str = None, user_id: str = None) -> dict:
        """

        :param user_name: the user name for search (the user id)
        :param user_id: the user id for search (the user name)
        :return: {"name": <user name>, "id": <user id>}
        """
        if user_name:
            if user_name.lower() == 'me':
                user_name = self.__user_name

            looking_in = 'username'
            looking_for = user_name
        elif user_id:
            looking_in = 'id'
            looking_for = user_id
        else:
            return {}

        if not self.__cache.get('users'):
            _, _, self.__cache['users'] = self.get_user_list()
        for user in self.__cache['users']:
            if user.get(looking_in) == looking_for:
                return {
                    'id': user.get('id'),
                    'name': user.get('username')
                }

        demisto.debug(f'{looking_for} is not a {looking_in}(user).')
        return {}

    def __org_and_id(self, org_name: str = None, org_id: str = None) -> dict:
        """

        :param org_name: the org name for search (the org id)
        :param org_id: the org id for search (the org name)
        :return: {"name": <org name>, "id": <org id>}
        """
        if not org_id:
            if not org_name:
                org_name = 'None'

            looking_for = org_name
            looking_in = 'name'
        else:
            looking_for = org_id
            looking_in = 'id'
        if not self.__cache['org']:
            _, _, self.__cache['org'] = self.get_organization_list(raw=True)
        for org in self.__cache['org']:
            if org.get(looking_in) == looking_for:
                return org
        demisto.debug(f'{looking_for} is not a {looking_in}(org).')
        return {}

    def __status_and_id(self, status_name: str = None, status_id: str = None) -> dict:
        """

        :param status_name: the status name for search (the status id)
        :param status_id: the status id for search (the status name)
        :return: {"name": <status name>, "id": <status id>}
        """
        if not status_id:
            looking_for = status_name if status_name else 'Open'
            looking_in = 'name'
        else:
            looking_for = status_id
            looking_in = 'id'
        if not self.__cache['status']:
            def filter_statuses_data(status_dict: dict):
                try:
                    status_dict.pop('showInCasePane')
                    status_dict.pop('default')
                except KeyError:
                    pass
                return status_dict

            self.__cache['status'] = list(map(filter_statuses_data, (self.get_case_statuses(raw=True))[2]))
        for status in self.__cache['status']:
            if status.get(looking_in) == looking_for:
                return status
        demisto.debug(f'{looking_for} is not a {looking_in}(status).')
        return {}

    def get_user_list(self, raw: bool = False) -> tuple[str, dict, dict]:
        """
        :param raw: ignore the human outputs if True
        :return: list of all Users
        """
        path = 'userGetUserList'
        headers = ['ID', 'Name', 'Email', 'Groups', 'IsMaster', 'IsAdmin', 'SMS']
        raw_response = self.__request(path, data={"authPW": {"value": self.__password}})
        result = raw_response
        context_entry: list = [dict] * len(result)
        human_readable = ''
        if not raw:
            for i in range(len(result)):
                context_entry[i] = {
                    'ID': result[i].get('id'),
                    'Name': result[i].get('username'),
                    'Email': result[i].get('email'),
                    'SMS': result[i].get('sms'),
                    'IsMaster': result[i].get('master'),
                    'IsAdmin': result[i].get('admin'),
                }
                if 'groups' in result[i]:
                    context_entry[i]['Groups'] = ''.join(str(result[i]['groups']))

            human_readable = tableToMarkdown(name='User list', t=context_entry, headers=headers)
        returned_context_entry = {f'{CONTEXT_INTEGRATION_NAME}User(val.ID && val.ID == obj.ID)': context_entry}
        return human_readable, returned_context_entry, raw_response

    def get_organization_list(self, raw: bool = False) -> tuple[str, dict, list[dict]]:
        """
        :param raw: ignore the human outputs if True
        :return: list of all organizations
        """
        path = 'caseGetOrganizationList'
        raw_response = self.__request(path)
        entry: list = [None] * len(raw_response)
        context_entry: dict = {}
        human_readable: str = ''
        if not raw:
            for i in range(len(raw_response)):
                entry[i] = {
                    'ID': raw_response[i].get('id'),
                    'Name': raw_response[i].get('name')
                }
            context_entry = {f'{CONTEXT_INTEGRATION_NAME}Organization(val.ID && val.ID == obj.ID)': entry}
            human_readable = tableToMarkdown(name='Organizations', t=raw_response)

        return human_readable, context_entry, raw_response

    def get_case_list(self, start_time: str = None, raw: bool = False) -> tuple[str, dict, list]:
        """
        :param raw: ignore the human outputs if True
        :return: list of all Users
        """
        path = 'caseGetCaseList'
        since = self.args.get('since', '1 year')
        context_entry = []
        human_readable: str = ''
        if not raw and not start_time:
            _, start_time, _ = set_query_times(since=since, difference=self.difference)
            start_time = convert_time_format(str(start_time), difference=self.difference)
        raw_response: list = self.__request(path)
        result = raw_response
        for case in result:
            case = dict_times_set(case, self.difference)
            if not start_time or not start_time > case.get('openTime'):
                temp_case = {
                    'ID': case.get('id'),
                    'Summary': case.get('summary'),
                    'OpenTime': case.get('openTime'),
                    'Severity': case.get('severity')
                }
                if 'statusId' in case:
                    status_id = case.get('statusId', {})
                    if isinstance(status_id, dict):
                        status_id = status_id.get('value')
                    temp_case['Status'] = self.__status_and_id(status_id=status_id).get('name')
                context_entry.append(temp_case)
        if not raw:
            human_readable = tableToMarkdown(name=f'cases since {since}', t=context_entry)
        returned_context_entry = {f'{CONTEXT_INTEGRATION_NAME}Case(val.ID && val.ID == obj.ID)': context_entry}
        return human_readable, returned_context_entry, raw_response

    def get_case_event_list(self) -> tuple[str, dict, list[dict]]:
        path = 'caseGetCaseEventsDetail'
        ids = argToList(self.args.get('ids'))
        raw_response = self.__request(path, data={'eventIds': {'list': ids}})
        result = raw_response
        case_event: list = [None] * len(result)
        for i in range(len(result)):
            result[i] = dict_times_set(result[i], self.difference)
            case_event[i] = {
                'ID': result[i].get('id'),
                'LastTime': result[i].get('lastTime'),
                'Message': result[i].get('message')
            }

        context_entry = {f'{CONTEXT_INTEGRATION_NAME}CaseEvent(val.ID && val.ID == obj.ID)': case_event}
        human_readable = tableToMarkdown(name='case event list', t=result)
        return human_readable, context_entry, raw_response

    def get_case_detail(self, case_id: str = None, raw: bool = False) -> tuple[str, dict, dict]:
        path = 'caseGetCaseDetail'
        raw_response = self.__request(path, data={'id': case_id if case_id else self.args.get('id')})
        result = raw_response
        result = dict_times_set(result, difference=self.difference)
        status_id = result.get('statusId', {})
        if not isinstance(status_id, int):
            status_id = status_id.get('value')
        context_entry = {
            'Assignee': self.__username_and_id(user_id=result.get('assignedTo')).get('name'),
            'ID': result.get('id'),
            'Summary': result.get('summary'),
            'Status': self.__status_and_id(status_id=status_id).get('name'),
            'OpenTime': result.get('openTime'),
            'Severity': result.get('severity'),
            'Organization': self.__org_and_id(org_id=result.get('orgId')).get('name'),
            'EventList': result.get('eventList'),
            'Notes': result.get('notes')
        }
        human_readable = ''
        readable_outputs = context_entry
        del readable_outputs['Notes']
        del readable_outputs['EventList']
        if not raw:
            human_readable = tableToMarkdown(name='Case', t=readable_outputs)
        returned_context_entry = {f'{CONTEXT_INTEGRATION_NAME}Case(val.ID && val.ID == obj.ID)': context_entry}
        return human_readable, returned_context_entry, raw_response

    def get_case_statuses(self, raw: bool = False) -> tuple[str, dict, dict]:
        path = 'caseGetCaseStatusList'
        headers = ['id', 'name', 'default', 'showInCasePane']
        raw_response = self.__request(path)
        human_readable = ''
        if not raw:
            human_readable = tableToMarkdown(name='case statuses', t=raw_response, headers=headers)
        return human_readable, {}, raw_response

    def add_case(self) -> tuple[str, dict, dict]:
        path = 'caseAddCase'

        assignee = self.args.get('assignee')
        if not assignee:
            assignee = 'ME'

        case_details = {
            'summary': self.args.get('summary'),
            'assignedTo': self.__username_and_id(user_name=assignee).get('id'),
            'severity': self.args.get('severity'),
            'orgId': self.__org_and_id(org_name=self.args.get('organization')).get('id'),
            'statusId': {'value': self.__status_and_id(status_name=self.args.get('status')).get('id')}
        }
        result = self.__request(path, data={'caseDetail': case_details})
        human_readable, context_entry, raw_response = self.get_case_detail(result.get('value'))
        return human_readable, context_entry, raw_response

    def edit_case(self) -> tuple[str, dict, dict]:
        path = 'caseEditCase'
        _, _, result = self.get_case_detail(case_id=self.args.get('id'))
        if 'organization' in self.args:
            result['orgId'] = self.__org_and_id(org_name=self.args.get('organization')).get('id')
        if 'summary' in self.args:
            result['summary'] = self.args['summary']
        if 'assignee' in self.args:
            result['assignedTo'] = self.args['assignee']
        if 'severity' in self.args:
            result['severity'] = self.args['severity']
        if 'status' in self.args:
            result['statusId'] = {'value': self.__status_and_id(status_name=self.args['status']).get('id')}
        if 'notes' in self.args:
            result['notes'] = self.args['notes']

        self.__request(path, data={'caseDetail': result})
        return self.get_case_detail(case_id=self.args.get('id'))

    def add_case_status(self) -> tuple[str, dict, dict]:
        path = 'caseAddCaseStatus'
        status_details = {
            'name': self.args.get('name'),
            'default': False
        }
        if 'should_show_in_case_pane' in self.args:
            status_details['showInCasePane'] = self.args['should_show_in_case_pane']
        raw_response = self.__request(path, data={'status': status_details})
        self.__cache['status'] = {}
        status_id = status_details['name']
        return f'Added case status : {status_id}', {}, raw_response

    def edit_case_status(self) -> tuple[str, dict, dict]:
        path = 'caseEditCaseStatus'
        status_id = self.__status_and_id(status_name=self.args.get('original_name')).get('id')
        status_details = {
            'status': {
                'id': status_id,
                'name': self.args.get('new_name')
            }
        }

        if 'show_in_case_pane' in self.args:
            status_details['status']['showInCasePane'] = self.args.get('show_in_case_pane')
        raw_response = self.__request(path, data=status_details)
        self.__cache['status'] = {}
        return f'Edited case status with ID: {status_id}', {}, raw_response

    def delete_case_status(self) -> tuple[str, dict, dict]:
        path = 'caseDeleteCaseStatus'
        status_id = self.__status_and_id(status_name=self.args.get('name')).get('id')
        self.__request(path, data={'statusId': {'value': status_id}})
        self.__cache['status'] = {}
        return f'Deleted case status with ID: {status_id}', {}, {}

    def fetch_fields(self) -> tuple[str, dict, dict[str, list]]:
        path = 'qryGetFilterFields'
        raw_response = self.__request(path)
        result = raw_response
        for field_type in result:
            field_type['types'] = ','.join(set(field_type['types']))
        human_readable = tableToMarkdown(name='Fields', t=result)
        return human_readable, {}, raw_response

    def fetch_alarms(self, since: str = None, start_time: str = None, end_time: str = None, raw: bool = False) \
            -> tuple[str, dict, list]:
        path = 'alarmGetTriggeredAlarms'
        human_readable = ''
        context_entry: list = []
        since = since if since else self.args.get('timeRange')
        start_time = start_time if start_time else self.args.get('customStart')
        end_time = end_time if end_time else self.args.get('customEnd')

        since, start_time, end_time = set_query_times(since, start_time, end_time, self.difference)
        params = {
            'triggeredTimeRange': since
        }
        if since == 'CUSTOM':
            params['customStart'] = start_time
            params['customEnd'] = end_time

        data = {}
        if assigned_user := self.args.get('assignedUser'):
            if assigned_user.lower() == 'me':
                assigned_user = self.__user_name
            data = {
                'assignedUser': {
                    'username': assigned_user,
                    'id': self.__username_and_id(user_name=assigned_user).get('id')
                }
            }

        demisto.debug(f'sending request to fetch alarms with {start_time=}, {end_time=}')
        raw_response = self.__request(path, data=data, params=params)
        result = raw_response

        for i in range(len(result)):
            result[i] = dict_times_set(result[i], self.difference)

        if not raw:
            context_entry = [None] * len(result)
            for i in range(len(result)):
                context_entry[i] = {
                    'ID': result[i].get('id'),
                    'summary': result[i].get('summary'),
                    'assignee': result[i].get('assignee'),
                    'severity': result[i].get('severity'),
                    'triggeredDate': result[i].get('triggeredDate'),
                    'acknowledgedDate': result[i].get('acknowledgedDate'),
                    'acknowledgedUsername': result[i].get('acknowledgedUsername'),
                    'alarmName': result[i].get('alarmName'),
                    'conditionType': result[i].get('conditionType')
                }

            table_headers = ['id', 'acknowledgedDate', 'acknowledgedUsername', 'alarmName', 'assignee', 'conditionType',
                             'severity', 'summary', 'triggeredDate']
            human_readable = tableToMarkdown(name='Alarms', t=result, headers=table_headers)
        returned_context_entry = {f'{CONTEXT_INTEGRATION_NAME}Alarm(val.ID && val.ID == obj.ID)': context_entry}
        return human_readable, returned_context_entry, raw_response

    def acknowledge_alarms(self) -> tuple[str, dict, dict]:
        try:
            self.__handle_alarms('Acknowledge')
        except DemistoException as error:
            # bug in ESM API performs the job but an error is return.
            if not expected_errors(error):
                raise error
        return 'Alarms has been Acknowledged.', {}, {}

    def unacknowledge_alarms(self) -> tuple[str, dict, dict]:
        try:
            self.__handle_alarms('Unacknowledge')
        except DemistoException as error:
            # bug in ESM API performs the job but an error is return.
            if not expected_errors(error):
                raise error
        return 'Alarms has been Unacknowledged.', {}, {}

    def delete_alarm(self) -> tuple[str, dict, dict]:
        self.__handle_alarms('Delete')
        return 'Alarms has been Deleted.', {}, {}

    def __handle_alarms(self, command: str):
        path = f'alarm{command}TriggeredAlarm'
        alarm_ids = argToList(str(self.args.get('alarmIds')))
        alarm_ids = [int(i) for i in alarm_ids]
        data = {
            'triggeredIds': {"alarmIdList": alarm_ids} if not self.version < '11.3' else alarm_ids
        }
        self.__request(path, data=data)

    def get_alarm_event_details(self) -> tuple[str, dict, dict]:
        path = 'ipsGetAlertData'
        raw_response = self.__request(path, data={'id': self.args.get('eventId')})
        result = raw_response
        result = dict_times_set(result, self.difference)
        context_entry = self.__alarm_event_context_and_times_set(result)
        human_readable = tableToMarkdown(name='Alarm events', t=context_entry)
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}AlarmEvent': context_entry}, raw_response

    def list_alarm_events(self) -> tuple[str, dict, dict]:
        path = 'notifyGetTriggeredNotificationDetail'
        raw_response = self.__request(path, data={'id': self.args.get('alarmId')})
        result = raw_response
        result = dict_times_set(result, self.difference)
        human_readable: str = ''
        context_entry: list = []
        if 'events' in result:
            context_entry = [dict] * len(result['events'])
            for event in range(len(result['events'])):
                context_entry[event] = self.__alarm_event_context_and_times_set(result['events'][event])
            human_readable = tableToMarkdown(name='Alarm events', t=context_entry)

        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}'
                                f'AlarmEvent(val.ID && val.ID == obj.ID)': context_entry}, raw_response

    def complete_search(self):
        time_out = int(self.args.get('timeOut', 30))
        interval = min(10, time_out)
        search_id = self.__search()
        i = 0
        while not self.__generic_polling(search_id):
            i += 1
            time.sleep(interval)  # pylint: disable=sleep-exists
            if i * interval >= time_out:
                raise DemistoException(f'Search: {search_id} time out.')

        return self.__search_fetch_result(search_id)

    def __search(self) -> int:
        path = 'qryExecuteDetail'
        query_type = self.args.get('queryType')
        time_range = self.args.get('timeRange')
        custom_start = self.args.get('customStart')
        custom_end = self.args.get('customEnd')
        offset = self.args.get('offset')
        time_range, custom_start, custom_end = set_query_times(time_range, custom_start, custom_end, self.difference)
        time_config = {
            'timeRange': time_range
        }
        if time_range == 'CUSTOM':
            time_config['customStart'] = custom_start
            time_config['customEnd'] = custom_end
        params = {
            'reverse': False,
            'type': query_type if query_type else 'EVENT'
        }
        config = {
            'filters': json.loads(self.args.get('filters')),
            'limit': self.args.get('limit', 0)
        }
        fields = self.args.get('fields')
        if fields:
            config['fields'] = [{'name': field} for field in argToList(fields)]
        if offset:
            config['offset'] = offset

        config.update(time_config)
        result = self.__request(path, data={'config': config}, params=params)
        return result.get('resultID')

    def __generic_polling(self, search_id: Union[str, int]) -> bool:
        if not search_id:
            search_id = self.args.get('SearchID')
        path = 'qryGetStatus'
        status = self.__request(path, data={'resultID': str(search_id)})
        return status.get('complete')

    def __search_fetch_result(self, search_id: int) -> tuple[str, dict, dict]:
        path = 'qryGetResults'
        params = {
            'startPos': 0,
            'reverse': False,
            'numRows': self.args.get('ratePerFetch', 50)
        }
        result_ready = False
        raw_response: dict[str, list] = {
            'columns': [],
            'rows': []
        }

        while not result_ready:
            try:
                temp = self.__request(path, data={'resultID': search_id}, params=params)
                if not raw_response['columns']:
                    raw_response['columns'] = temp.get('columns')
                if len(temp.get('rows', {})) < params['numRows']:
                    result_ready = True

                raw_response['rows'].extend(temp.get('rows'))
                params['startPos'] += params['numRows']

            except DemistoException as error:
                if not expected_errors(error):
                    raise
                else:
                    result_ready = True
        result = raw_response
        result = table_times_set(result, self.difference)
        entry: list = [{}] * len(result['rows'])
        headers = [str(field.get('name')).replace('.', '') for field in result['columns']]
        for i in range(len(result['rows'])):
            entry[i] = {headers[j]: result['rows'][i]['values'][j] for j in range(len(headers))}

        condition = '(val.AlertIPSIDAlertID && val.AlertIPSIDAlertID == obj.AlertIPSIDAlertID)' \
            if 'AlertIPSIDAlertID' in headers else ''
        context_entry = {f'{CONTEXT_INTEGRATION_NAME}results{condition}': entry}
        return search_readable_outputs(result), context_entry, raw_response

    def __alarm_event_context_and_times_set(self, result: dict) -> dict:
        context_entry = {
            'ID': result.get('eventId', result.get('alertId')),
            'SubType': result.get('subtype', result.get('eventSubType')),
            'Severity': result.get('severity'),
            'Message': result.get('ruleName', result.get('ruleMessage')),
            'LastTime': result.get('lastTime'),
            'SrcIP': result.get('srcIp', result.get('sourceIp')),
            'DstIP': result.get('destIp', result.get('destIp')),
            'DstMac': result.get('destMac'),
            'SrcMac': result.get('srcMac'),
            'DstPort': result.get('destPort'),
            'SrcPort': result.get('srcPort'),
            'FirstTime': result.get('firstTime'),
            'NormalizedDescription': result.get('normDesc')
        }
        if 'cases' in result:
            cases: list = [None] * len(result['cases'])
            for i in range(len(result['cases'])):
                case_status = self.__status_and_id(
                    status_id=result['cases'][i].get('statusId', {}).get('value')
                )
                cases[i] = {
                    'ID': result['cases'][i].get('id'),
                    'OpenTime': result['cases'][i].get('openTime'),
                    'Severity': result['cases'][i].get('severity'),
                    'Status': case_status.get('name'),
                    'Summary': result['cases'][i].get('summary')
                }
            context_entry['Case'] = cases
        return context_entry

    def fetch_incidents(self, params: dict):
        last_run = demisto.getLastRun()
        current_run = {}
        incidents = []
        if params.get('fetchType', 'alarms') in ('alarms', 'both'):
            start_time = last_run.get(
                'alarms', {}).get(
                'time', parse_date_range(params.get('fetchTime'), self.demisto_format)[0])
            start_id = int(last_run.get('alarms', {}).get('id', params.get('startingFetchID')))
            temp_incidents, current_run['alarms'] = \
                self.__alarms_to_incidents(start_time, start_id, int(params.get('fetchLimitAlarms', 5)))
            incidents.extend(temp_incidents)

        if params.get('fetchType') in ('cases', 'both'):
            start_id = int(last_run.get('cases', {}).get('id', params.get('startingFetchID')))
            temp_incidents, current_run['cases'] = \
                self.__cases_to_incidents(start_id=start_id, limit=int(params.get('fetchLimitCases', 5)))
            incidents.extend(temp_incidents)

        demisto.setLastRun(current_run)
        demisto.incidents(incidents)

    def __alarms_to_incidents(self, start_time: str, start_id: int = 0, limit: int = 1) -> tuple[list, dict]:
        current_time = datetime.utcnow().strftime(self.demisto_format)
        current_run = {}
        _, _, all_alarms = self.fetch_alarms(start_time=start_time, end_time=current_time, raw=True)
        all_alarms = filtering_incidents(all_alarms, start_id=start_id, limit=limit)
        if all_alarms:
            current_run['time'] = all_alarms[0].get('triggeredDate', start_time)
            current_run['id'] = all_alarms[0]['id']
            current_run_time = current_run['time']
            demisto.debug(f'{len(all_alarms)=}, setting current time to {current_run_time=}')
        else:
            current_run['time'] = start_time
            current_run['id'] = start_id
            demisto.debug(f'No alarms were found, setting current time to {start_time=}')
        all_alarms = create_incident(all_alarms, alarms=True)
        return all_alarms, current_run

    def __cases_to_incidents(self, start_id: int = 0, limit: int = 1) -> tuple[list, dict]:
        _, _, all_cases = self.get_case_list(raw=True)
        all_cases = filtering_incidents(all_cases, start_id=start_id, limit=limit)
        current_run = {'id': all_cases[0].get('id', start_id) if all_cases else start_id}
        all_cases = create_incident(all_cases, alarms=False)
        return all_cases, current_run

    def __get_watchlists(self, args: dict):
        command = 'sysGetWatchlists'
        params = {
            'hidden': args.get('hidden', True),
            'dynamic': args.get('dynamic', True),
            'writeOnly': args.get('write_only', False),
            'indexedOnly': args.get('indexed_only', False),
        }
        return self.__request(command, params=params)

    def __get_watchlist_id(self, watchlist_name: str):
        try:
            return list(filter(lambda x: x.get('name') == watchlist_name, self.__get_watchlists(dict())))[0].get('id')
        except IndexError:
            raise DemistoException(f'Can not find the watchlist {watchlist_name}')

    def get_watchlists_names_and_ids(self):
        raw_watch_lists = self.__get_watchlists(self.args)
        watch_lists = list(map(format_watchlist_params, raw_watch_lists))
        human_readable = tableToMarkdown('McAfee ESM Watchlist', t=watch_lists)
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}Watchlist': watch_lists}, raw_watch_lists

    def add_watchlist(self):
        command = 'sysAddWatchlist'
        watchlist_name = self.args.get('name')
        watchlist_type = self.args.get('type')
        data = {
            "watchlist": {
                "name": watchlist_name,
                "type": {"name": watchlist_type,
                         "id": 0},
                "customType": {"name": "",
                               "id": 0},
                "dynamic": "False",
                "enabled": "True",
            }}
        watchlist_id = self.__request(command, data=data)
        context_entry = {
            'name': watchlist_name,
            'id': watchlist_id.get('value'),
            'type': watchlist_type,
        }
        human_readable = f'Watchlist {watchlist_name} created.'
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}Watchlist': context_entry}, watchlist_id

    def delete_watchlist(self):
        command = 'sysRemoveWatchlist'
        ids_to_delete = argToList(self.args.get('ids', ''))
        ids_to_delete.extend(list(map(self.__get_watchlist_id, argToList(self.args.get('names')))))
        if self.version.startswith('11.'):
            data = {"ids": {"watchlistIdList": ids_to_delete}}
            self.__request(command, data)
        else:
            for single_id in ids_to_delete:
                data = {"id": single_id}
                self.__request(command, data)
        return 'Watchlists removed', {}, {}

    def watchlist_add_entry(self):
        command = 'sysAddWatchlistValues'
        watchlist_id = self.args.get('watchlist_id')
        data = {
            'watchlist': watchlist_id if watchlist_id else self.__get_watchlist_id(self.args.get('watchlist_name', '')),
            'values': argToList(self.args.get('values', ''))
        }
        raw_response = self.__request(command, data=data)
        human_readable = 'Watchlist successfully updated.'
        return human_readable, {}, raw_response

    def watchlist_delete_entry(self):
        command = 'sysRemoveWatchlistValues'
        watchlist_id = self.args.get('watchlist_id')
        data = {
            'watchlist': watchlist_id if watchlist_id else self.__get_watchlist_id(self.args.get('watchlist_name', '')),
            'values': argToList(self.args.get('values', ''))
        }
        self.__request(command, data=data)
        human_readable = 'Watchlist successfully updated.'
        return human_readable, {}, {}

    def __get_watchlist_file_id(self, watchlist_id: int):
        command = 'sysGetWatchlistDetails'
        result = self.__request(command, data={'id': watchlist_id})
        # v10.x uses 'valueCount' while v11.x uses 'recordCount'.
        count_results = result.get('recordCount') or result.get('valueCount')
        if not count_results:
            raise EmptyFile
        value_file = result.get('valueFile', {})
        file_token = value_file.get('fileToken', value_file.get('id'))
        watchlist_name = result.get('name')
        return file_token, watchlist_name

    def watchlist_data_list(self):
        watchlist_id = self.args.get('watchlist_id')
        watchlist_id = watchlist_id if watchlist_id else self.__get_watchlist_id(self.args.get('watchlist_name', ''))

        try:
            file_token, watchlist_name = self.__get_watchlist_file_id(watchlist_id)
        except EmptyFile:
            return 'the watchlist is empty.', {}, {}

        else:
            max_values = int(self.args.get('limit', 50))
            offset = int(self.args.get('offset', 0))
            file_data = []
            for i, line in enumerate(self.watchlist_values(file_token)):
                if i < offset:
                    continue
                file_data.append(line)
                if len(file_data) >= max_values:
                    break
            human_readable = tableToMarkdown(f'results from {watchlist_name} watchlist',
                                             t={'data': file_data})
            context_entry = {f'{CONTEXT_INTEGRATION_NAME}Watchlist': {'data': file_data, 'name': watchlist_name}}
            return human_readable, context_entry, file_data

    def watchlist_values(self, file_token: str, buff_size=400):
        """

        :param file_token: the token file (McAfee API call needed for the file creation)
        :param buff_size: the size of the bytes in every API call.
        :return: generate values (string)
        """
        command = 'sysGetWatchlistValues'
        data = {'file': {'id': file_token}}
        end = ''
        for i in itertools.count(start=0):
            params = {
                'pos': i * buff_size,
                'count': buff_size
            }
            result = self.__request(command, data=data, params=params)
            file_data = '{}{}'.format(end, result.get('data', ''))
            file_data = file_data.split('\n')
            more_data_exist = buff_size == result.get('bytesRead') or not file_data
            if more_data_exist:
                end = file_data[-1]
                file_data = file_data[:-1]

            for line in filter(lambda x: x, file_data):
                yield line

            if not more_data_exist:
                break


def filtering_incidents(incidents_list: list, start_id: int, limit: int = 1):
    """

    :param incidents_list: list of al incidents
    :param start_id: id to start from
    :param limit: limit
    :return: the filtered incidents
    """
    filtered_incident = []
    ignored_incident_ids = []
    for incident in incidents_list:
        if int(incident.get('id', 0)) > start_id:
            filtered_incident.append(incident)
        else:
            ignored_incident_ids.append(incident.get('id'))

    demisto.debug(f'filtered {len(ignored_incident_ids)} incidents by {start_id=}.\n{ignored_incident_ids=}')

    filtered_incident.sort(key=lambda incident: int(incident.get('id', 0)), reverse=True)
    if limit != 0:
        incidents_size = min(limit, len(filtered_incident))
        filtered_incident = filtered_incident[-incidents_size:]

    return filtered_incident


def expected_errors(error: DemistoException) -> bool:
    """

    :param error: the error
    :return: if the error is not real error
    """
    expected_error: list[str] = [
        'qryGetResults failed with error[Error deserializing EsmQueryResults, see logs for more information '  # noqa: W504
        + '(Error deserializing EsmQueryResults, see logs for more information '  # noqa: W504
        + '(Internal communication error, see logs for more details))].',
        'alarmUnacknowledgeTriggeredAlarm failed with error[ERROR_BadRequest (60)].',
        'alarmAcknowledgeTriggeredAlarm failed with error[ERROR_BadRequest (60)].'
    ]
    return str(error) in expected_error


def time_format(current_time: str, difference: int = 0) -> str:
    """

    :param current_time: the current time in the current format
    :param difference: the time zone offset
    :return: the time in the new format and in UTC time
    """
    to_return: str = ''
    try:
        to_return = convert_time_format(current_time, difference=difference, mcafee_format='%Y/%m/%d %H:%M:%S')
    except ValueError as error:
        if str(error) != f'time data \'{current_time}\' does not match format \'%Y/%m/%d %H:%M:%S\'':
            raise error

        try:
            to_return = convert_time_format(current_time, difference=difference, mcafee_format='%m/%d/%Y %H:%M:%S')
        except ValueError as error_2:
            if str(error_2) != f'time data \'{current_time}\' does not match format \'%m/%d/%Y %H:%M:%S\'':
                raise error_2

            try:
                to_return = convert_time_format(current_time, difference=difference, mcafee_format='%d-%m-%Y %H:%M:%S')
            except ValueError as error_3:
                if str(error_3) != f'time data \'{current_time}\' does not match format \'%d-%m-%Y %H:%M:%S\'':
                    raise error_3
                else:
                    raise ValueError(f'time data \'{current_time}\' does not match the time format.')
    return to_return


def convert_time_format(current_time: str,
                        difference: int = 0,
                        to_demisto: bool = True,
                        mcafee_format: str = '%Y/%m/%d %H:%M:%S') -> str:
    """

    :param current_time: the current_time
    :param difference: the difference (e.g. time zone)
    :param to_demisto: true if we want change the time zone from McAfee ESM time to demisto (e.g. UTC)
    :param mcafee_format: the standard format in McAfee Machine
    :return: the new format
    """
    if not current_time.endswith('(GMT)'):
        if not to_demisto and not current_time.endswith('Z'):
            current_time += 'Z'
        datetime_obj = datetime.strptime(
            current_time,
            mcafee_format if to_demisto else McAfeeESMClient.demisto_format
        )
        datetime_obj -= timedelta(hours=difference if to_demisto else -1 * difference)
    else:
        datetime_obj = datetime.strptime(current_time, '%m/%d/%Y %H:%M:%S(GMT)')

    return datetime_obj.strftime(McAfeeESMClient.demisto_format)


def set_query_times(since: str = None, start_time: str = None, end_time: str = None, difference: int = 0) -> \
        tuple[str | None, str | None, str | None]:
    """
    checks all time args
    :param since: since from args
    :param start_time: start_time from args
    :param end_time: end_time from args
    :param difference: the difference (e.g. time zone)
    :return: the args in the machine time and after validation
    """
    if not since:
        since = 'CUSTOM'
    elif start_time or end_time:
        raise ValueError('Invalid set times.')
    if since != 'CUSTOM' and ' ' in since:
        start_time, _ = parse_date_range(since, '%Y/%m/%d %H:%M:%S')
    else:
        if start_time:
            start_time = convert_time_format(start_time, difference=difference, to_demisto=False)
        if end_time:
            end_time = convert_time_format(end_time, difference=difference, to_demisto=False)

        if start_time and end_time and start_time > end_time:
            raise ValueError('Invalid set times.')
    return since, start_time, end_time


def list_times_set(list_to_set: list, indexes: list, difference: int = 0) -> list:
    """

    :param list_to_set: the raw list
    :param indexes: a list of the indexes for time fields
    :param difference: the difference (e.g. time zone)
    :return: the data list with utc times
    """
    for i in indexes:
        if list_to_set[i]:
            list_to_set[i] = time_format(list_to_set[i], difference=difference)
    return list_to_set


def dict_times_set(dict_to_set: dict, difference: int = 0) -> dict:
    """

    :param dict_to_set: the raw dict
    :param difference: the difference (e.g. time zone)
    :return: the data dict with utc times
    """
    for field in dict_to_set:
        if dict_to_set[field]:
            if 'time' in field.lower() or 'date' in field.lower():
                dict_to_set[field] = time_format(dict_to_set[field], difference=difference)
            elif isinstance(dict_to_set[field], dict):
                dict_to_set[field] = dict_times_set(dict_to_set[field], difference)
            elif isinstance(dict_to_set[field], list):
                for i in range(len(dict_to_set[field])):
                    if isinstance(dict_to_set[field][i], dict):
                        dict_to_set[field][i] = dict_times_set(dict_to_set[field][i], difference)
    return dict_to_set


def time_fields(field_list: list[dict]) -> list:
    """

    :param field_list: the list of fields for a given query
    :return: all fields (names only) that have a time value
    """
    indexes_list = []
    for i in range(len(field_list)):
        if 'time' in field_list[i]['name'].lower() or 'date' in field_list[i]['name'].lower():
            indexes_list.append(i)
    return indexes_list


def table_times_set(table_to_set: dict, difference: int = 0) -> dict:
    """

    :param table_to_set: the raw event/ alarm
    :param difference: the difference (e.g. time zone)
    :return: the event/ alarm with utc time
    """
    indexes_list = time_fields(table_to_set['columns'])
    for dict_ in table_to_set['rows']:
        dict_['values'] = list_times_set(dict_.get('values'), indexes_list, difference)
    return table_to_set


def search_readable_outputs(table: dict) -> str:
    """

    :param table: the raw data for a search
    :return: md format table
    """
    if 'columns' in table and 'rows' in table:
        line_1 = line_2 = '|'
        for header in table.get('columns', []):
            line_1 += str(header.get('name')) + '|'
            line_2 += '--|'
        rows = table['rows']
        data: list = [str] * len(rows)
        for i in range(len(rows)):
            middle = '~'.join(rows[i].get('values', []))
            middle = middle.replace('|', '\\|')
            middle = middle.replace('~', '|')
            data[i] = f'| {middle} |'

        start = f'Search results\n{line_1}\n{line_2}\n'
        return start + '\n'.join(data)
    else:
        return ''


def create_incident(raw_incidents: list[dict], alarms: bool) -> list[dict[str, dict]]:
    incidents = []
    for incident in raw_incidents:
        alarm_id = str(incident.get('id'))
        summary = str(incident.get('summary'))
        incident_type = 'alarm' if alarms else 'case'
        incidents.append({
            'name': f'McAfee ESM {incident_type}. id: {alarm_id}. {summary}',
            'severity': mcafee_severity_to_demisto(incident.get('severity', 0)),
            'occurred': incident.get('triggeredDate', incident.get('openTime', '')),
            'rawJSON': json.dumps(incident)
        })
    return incidents


def mcafee_severity_to_demisto(severity: int) -> int:
    if severity > 65:
        return 3
    elif severity > 32:
        return 2
    elif severity > 0:
        return 1
    else:
        return 0


def format_watchlist_params(raw_watchlist_params: dict):
    return {
        'id': raw_watchlist_params.get('id'),
        'name': raw_watchlist_params.get('name'),
        'type': dict_safe_get(raw_watchlist_params, ['type', 'name'])
    }


def main():
    client = McAfeeESMClient(demisto.params())
    command = demisto.command()
    commands: dict[str, Callable] = {
        'test-module': client.test_module,
        'esm-fetch-fields': client.fetch_fields,
        'esm-get-organization-list': client.get_organization_list,
        'esm-fetch-alarms': client.fetch_alarms,
        'esm-add-case': client.add_case,
        'esm-get-case-detail': client.get_case_detail,
        'esm-edit-case': client.edit_case,
        'esm-get-case-statuses': client.get_case_statuses,
        'esm-edit-case-status': client.edit_case_status,
        'esm-get-case-event-list': client.get_case_event_list,
        'esm-add-case-status': client.add_case_status,
        'esm-delete-case-status': client.delete_case_status,
        'esm-get-case-list': client.get_case_list,
        'esm-get-user-list': client.get_user_list,
        'esm-acknowledge-alarms': client.acknowledge_alarms,
        'esm-unacknowledge-alarms': client.unacknowledge_alarms,
        'esm-delete-alarms': client.delete_alarm,
        'esm-get-alarm-event-details': client.get_alarm_event_details,
        'esm-list-alarm-events': client.list_alarm_events,
        'esm-search': client.complete_search,
        'esm-get-watchlists': client.get_watchlists_names_and_ids,
        'esm-create-watchlist': client.add_watchlist,
        'esm-delete-watchlist': client.delete_watchlist,
        'esm-watchlist-add-entry': client.watchlist_add_entry,
        'esm-watchlist-delete-entry': client.watchlist_delete_entry,
        'esm-watchlist-list-entries': client.watchlist_data_list,
    }
    try:
        if command == 'fetch-incidents':
            client.fetch_incidents(demisto.params())
        elif command in commands:
            human_readable, context_entry, raw_response = commands[command]()
            return_results(CommandResults(readable_output=human_readable,
                                          outputs=context_entry, raw_response=raw_response))
        else:
            raise NotImplementedError(f'{command} is not a demisto command.')

    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
