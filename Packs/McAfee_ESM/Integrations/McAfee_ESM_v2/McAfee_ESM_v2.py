from typing import Dict, List, Tuple, Optional, Callable
from urllib3 import disable_warnings
from CommonServerPython import *
import demistomock as demisto
from datetime import timedelta, datetime
import time


disable_warnings()
CONTEXT_INTEGRATION_NAME = 'McAfeeESM.'


class McAfeeESMClient(BaseClient):

    demisto_format = '%Y-%m-%dT%H:%M:%SZ'

    def __init__(self, params: Dict):
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
        self.__cache: Dict = {
            'users': [],
            'org': [],
            'status': []
        }

    def __del__(self):
        self.__logout()

    def _is_status_code_valid(self, *_other):    # noqa
        return True

    def __request(self, mcafee_command, data=None, params=None):
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

    def test_module(self) -> Tuple[str, Dict, Dict]:
        self.get_organization_list(raw=True)
        return 'ok', {}, {}

    def __username_and_id(self, user_name: str = None, user_id: str = None) -> Dict:
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

        demisto.log(f'{looking_for} is not a {looking_in}(user).')
        return {}

    def __org_and_id(self, org_name: str = None, org_id: str = None) -> Dict:
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
        demisto.log(f'{looking_for} is not a {looking_in}(org).')
        return {}

    def __status_and_id(self, status_name: str = None, status_id: str = None) -> Dict:
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
            def filter_statuses_data(status_dict):
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
        demisto.log(f'{looking_for} is not a {looking_in}(status).')
        return {}

    def get_user_list(self, row: bool = False) -> Tuple[str, Dict, Dict]:
        path = 'userGetUserList'
        headers = ['ID', 'Name', 'Email', 'Groups', 'IsMaster', 'IsAdmin', 'SMS']
        result = self.__request(path, data={"authPW": {"value": self.__password}})
        context_entry: List = [Dict] * len(result)
        human_readable = ''
        if not row:
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
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}User(val.ID && val.ID == obj.ID)': context_entry}, result

    def get_organization_list(self, raw: bool = False) -> Tuple[str, Dict, List[Dict]]:
        path = 'caseGetOrganizationList'
        result = self.__request(path)
        entry: List = [None] * len(result)
        context_entry: Dict = {}
        human_readable: str = ''
        if not raw:
            for i in range(len(result)):
                entry[i] = {
                    'ID': result[i].get('id'),
                    'Name': result[i].get('name')
                }
            context_entry = {f'{CONTEXT_INTEGRATION_NAME}Organization(val.ID && val.ID == obj.ID)': entry}
            human_readable = tableToMarkdown(name='Organizations', t=result)

        return human_readable, context_entry, result

    def get_case_list(self, start_time: str = None, raw: bool = False) -> Tuple[str, Dict, List]:
        path = 'caseGetCaseList'
        since = self.args.get('since', '1 year')
        context_entry = []
        human_readable: str = ''
        if not raw and not start_time:
            _, start_time, _ = set_query_times(since=since, difference=self.difference)
            start_time = convert_time_format(str(start_time), difference=self.difference)
        result: List = self.__request(path)
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
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}Case(val.ID && val.ID == obj.ID)': context_entry}, result

    def get_case_event_list(self) -> Tuple[str, Dict, List[Dict]]:
        path = 'caseGetCaseEventsDetail'
        ids = argToList(self.args.get('ids'))
        result = self.__request(path, data={'eventIds': {'list': ids}})
        case_event: List = [None] * len(result)
        for i in range(len(result)):
            result[i] = dict_times_set(result[i], self.difference)
            case_event[i] = {
                'ID': result[i].get('id'),
                'LastTime': result[i].get('lastTime'),
                'Message': result[i].get('message')
            }

        context_entry = {f'{CONTEXT_INTEGRATION_NAME}CaseEvent(val.ID && val.ID == obj.ID)': case_event}
        human_readable = tableToMarkdown(name='case event list', t=result)
        return human_readable, context_entry, result

    def get_case_detail(self, case_id: str = None, raw: bool = False) -> Tuple[str, Dict, Dict]:
        path = 'caseGetCaseDetail'
        result = self.__request(path, data={'id': case_id if case_id else self.args.get('id')})
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
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}Case(val.ID && val.ID == obj.ID)': context_entry}, result

    def get_case_statuses(self, raw: bool = False) -> Tuple[str, Dict, Dict]:
        path = 'caseGetCaseStatusList'
        headers = ['id', 'name', 'default', 'showInCasePane']
        result = self.__request(path)
        human_readable = ''
        if not raw:
            human_readable = tableToMarkdown(name='case statuses', t=result, headers=headers)
        return human_readable, {}, result

    def add_case(self) -> Tuple[str, Dict, Dict]:
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
        human_readable, context_entry, result = self.get_case_detail(result.get('value'))
        return human_readable, context_entry, result

    def edit_case(self) -> Tuple[str, Dict, Dict]:
        path = 'caseEditCase'
        _, _, result = self.get_case_detail(case_id=self.args.get('id'))
        case_details: Dict = {
            'id': result.get('id'),
            'orgId': result.get('orgId'),
            'summary': result.get('summary'),
            'assignedTo': result.get('assignedTo'),
            'severity': result.get('severity'),
            'statusId': result.get('statusId')
        }

        if 'organization' in self.args:
            case_details['orgId'] = self.__org_and_id(org_name=self.args.get('organization')).get('id')
        if 'summary' in self.args:
            case_details['summary'] = self.args['summary']
        if 'assignee' in self.args:
            case_details['assignedTo'] = self.args['assignee']
        if 'severity' in self.args:
            case_details['severity'] = self.args['severity']
        if 'status' in self.args:
            case_details['statusId'] = {'value': self.__status_and_id(status_name=self.args['status']).get('id')}

        self.__request(path, data={'caseDetail': case_details})
        return self.get_case_detail(case_id=self.args.get('id'))

    def add_case_status(self) -> Tuple[str, Dict, Dict]:
        path = 'caseAddCaseStatus'
        status_details = {
            'name': self.args.get('name'),
            'default': False
        }
        if 'should_show_in_case_pane' in self.args:
            status_details['showInCasePane'] = self.args['should_show_in_case_pane']
        result = self.__request(path, data={'status': status_details})
        self.__cache['status'] = {}
        status_id = status_details['name']
        return f'Added case status : {status_id}', {}, result

    def edit_case_status(self) -> Tuple[str, Dict, Dict]:
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
        self.__request(path, data=status_details)
        self.__cache['status'] = {}
        return f'Edited case status with ID: {status_id}', {}, {}

    def delete_case_status(self) -> Tuple[str, Dict, Dict]:
        path = 'caseDeleteCaseStatus'
        status_id = self.__status_and_id(status_name=self.args.get('name')).get('id')
        self.__request(path, data={'statusId': {'value': status_id}})
        self.__cache['status'] = {}
        return f'Deleted case status with ID: {status_id}', {}, {}

    def fetch_fields(self) -> Tuple[str, Dict, Dict[str, list]]:
        path = 'qryGetFilterFields'
        result = self.__request(path)
        for field_type in result:
            field_type['types'] = ','.join(set(field_type['types']))
        human_readable = tableToMarkdown(name='Fields', t=result)
        return human_readable, {}, result

    def fetch_alarms(self, since: str = None, start_time: str = None, end_time: str = None, raw: bool = False)\
            -> Tuple[str, Dict, List]:
        path = 'alarmGetTriggeredAlarms'
        human_readable = ''
        context_entry: List = []
        since = since if since else self.args.get('timeRange')
        start_time = start_time if start_time else self.args.get('customStart')
        end_time = end_time if end_time else self.args.get('customEnd')
        assigned_user = self.args.get('assignedUser')
        if not assigned_user or assigned_user.lower() == 'me':
            assigned_user = self.__user_name

        since, start_time, end_time = set_query_times(since, start_time, end_time, self.difference)
        params = {
            'triggeredTimeRange': since
        }
        if since == 'CUSTOM':
            params['customStart'] = start_time
            params['customEnd'] = end_time

        data = {
            'assignedUser': {
                'username': assigned_user,
                'id': self.__username_and_id(user_name=assigned_user).get('id')
            }
        }
        result = self.__request(path, data=data, params=params)

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
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}Alarm(val.ID && val.ID == obj.ID)': context_entry}, result

    def acknowledge_alarms(self) -> Tuple[str, Dict, Dict]:
        try:
            self.__handle_alarms('Acknowledge')
        except DemistoException as error:
            # bug in ESM API performs the job but an error is return.
            if not expected_errors(error):
                raise error
        return 'Alarms has been Acknowledged.', {}, {}

    def unacknowledge_alarms(self) -> Tuple[str, Dict, Dict]:
        try:
            self.__handle_alarms('Unacknowledge')
        except DemistoException as error:
            # bug in ESM API performs the job but an error is return.
            if not expected_errors(error):
                raise error
        return 'Alarms has been Unacknowledged.', {}, {}

    def delete_alarm(self) -> Tuple[str, Dict, Dict]:
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

    def get_alarm_event_details(self) -> Tuple[str, Dict, Dict]:
        path = 'ipsGetAlertData'
        result = self.__request(path, data={'id': self.args.get('eventId')})
        result = dict_times_set(result, self.difference)
        context_entry = self.__alarm_event_context_and_times_set(result)
        human_readable = tableToMarkdown(name='Alarm events', t=context_entry)
        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}AlarmEvent': context_entry}, result

    def list_alarm_events(self) -> Tuple[str, Dict, Dict]:
        path = 'notifyGetTriggeredNotificationDetail'
        result = self.__request(path, data={'id': self.args.get('alarmId')})
        result = dict_times_set(result, self.difference)
        human_readable: str = ''
        context_entry: List = []
        if 'events' in result:
            context_entry = [Dict] * len(result['events'])
            for event in range(len(result['events'])):
                context_entry[event] = self.__alarm_event_context_and_times_set(result['events'][event])
            human_readable = tableToMarkdown(name='Alarm events', t=context_entry)

        return human_readable, {f'{CONTEXT_INTEGRATION_NAME}'
                                f'AlarmEvent(val.ID && val.ID == obj.ID)': context_entry}, result

    def complete_search(self):
        time_out = self.args.get('timeOut', 30)
        interval = min(10, time_out)
        search_id = self.__search()
        i = 0
        while not self.__generic_polling(search_id):
            i += 1
            time.sleep(interval)
            if i * interval == time_out:
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

    def __generic_polling(self, search_id: int) -> bool:
        if not search_id:
            search_id = self.args.get('SearchID')
        path = 'qryGetStatus'
        status = self.__request(path, data={'resultID': str(search_id)})
        return status.get('complete')

    def __search_fetch_result(self, search_id: int) -> Tuple[str, Dict, Dict]:
        path = 'qryGetResults'
        params = {
            'startPos': 0,
            'reverse': False,
            'numRows': self.args.get('ratePerFetch', 50)
        }
        result_ready = False
        result: Dict[str, List] = {
            'columns': [],
            'rows': []
        }

        while not result_ready:
            try:
                temp = self.__request(path, data={'resultID': search_id}, params=params)
                if not result['columns']:
                    result['columns'] = temp.get('columns')
                if len(temp.get('rows', {})) < params['numRows']:
                    result_ready = True

                result['rows'].extend(temp.get('rows'))
                params['startPos'] += params['numRows']

            except DemistoException as error:
                if not expected_errors(error):
                    raise error
        result = table_times_set(result, self.difference)
        entry: List = [{}] * len(result['rows'])
        headers = [str(field.get('name')).replace('.', '') for field in result['columns']]
        for i in range(len(result['rows'])):
            entry[i] = {headers[j]: result['rows'][i]['values'][j] for j in range(len(headers))}

        condition = '(val.AlertIPSIDAlertID && val.AlertIPSIDAlertID == obj.AlertIPSIDAlertID)'\
            if 'AlertIPSIDAlertID' in headers else ''
        context_entry = {f'{CONTEXT_INTEGRATION_NAME}results{condition}': entry}
        return search_readable_outputs(result), context_entry, result

    def __alarm_event_context_and_times_set(self, result: Dict) -> Dict:
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
            cases: List = [None] * len(result['cases'])
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
            context_entry[f'Case'] = cases
        return context_entry

    def fetch_incidents(self, params: Dict):
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

    def __alarms_to_incidents(self, start_time: str, start_id: int = 0, limit: int = 1) -> Tuple[List, Dict]:
        current_time = datetime.utcnow().strftime(self.demisto_format)
        current_run = {}
        _, _, all_alarms = self.fetch_alarms(start_time=start_time, end_time=current_time, raw=True)
        all_alarms = filtering_incidents(all_alarms, start_id=start_id, limit=limit)
        if all_alarms:
            current_run['time'] = all_alarms[0].get('triggeredDate', current_time)
            current_run['id'] = all_alarms[0]['id']
        else:
            current_run['time'] = current_time
            current_run['id'] = start_id
        all_alarms = create_incident(all_alarms, alarms=True)
        return all_alarms, current_run

    def __cases_to_incidents(self, start_id: int = 0, limit: int = 1) -> Tuple[List, Dict]:
        _, _, all_cases = self.get_case_list(raw=True)
        all_cases = filtering_incidents(all_cases, start_id=start_id, limit=limit)
        current_run = {'id': all_cases[0].get('id', start_id) if all_cases else start_id}
        all_cases = create_incident(all_cases, alarms=False)
        return all_cases, current_run


def filtering_incidents(incidents_list: List, start_id: int, limit: int = 1):
    incidents_list = [incident for incident in incidents_list if int(incident.get('id', 0)) > start_id]
    incidents_list.sort(key=lambda case: int(case.get('id', 0)), reverse=True)
    if limit != 0:
        cases_size = min(limit, len(incidents_list))
        incidents_list = incidents_list[-cases_size:]
    return incidents_list


def expected_errors(error: DemistoException) -> bool:
    expected_error: List[str] = [
        'qryGetResults failed with error[Error deserializing EsmQueryResults, see logs for more information ' +  # noqa: W504
        '(Error deserializing EsmQueryResults, see logs for more information ' +  # noqa: W504
        '(Internal communication error, see logs for more details))].',
        'alarmUnacknowledgeTriggeredAlarm failed with error[ERROR_BadRequest (60)].',
        'alarmAcknowledgeTriggeredAlarm failed with error[ERROR_BadRequest (60)].'
    ]
    return str(error) in expected_error


def time_format(current_time: str, difference: int = 0) -> str:
    to_return: str
    try:
        to_return = convert_time_format(current_time, difference=difference, mcafee_format='%Y/%m/%d %H:%M:%S')
    except ValueError as error:
        if str(error) != f'time data \'{current_time}\' does not match format \'%Y/%m/%d %H:%M:%S\'':
            raise error
        else:
            try:
                to_return = convert_time_format(current_time, difference=difference, mcafee_format='%m/%d/%Y %H:%M:%S')
            except ValueError as error_2:
                if str(error_2) == f'time data \'{current_time}\' does not match format \'%m/%d/%Y %H:%M:%S\'':
                    raise ValueError(f'time data \'{current_time}\' does not match the time format.')
                else:
                    raise error_2
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
        Tuple[Optional[str], Optional[str], Optional[str]]:
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


def list_times_set(list_to_set: List, indexes: List, difference: int = 0) -> List:
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


def dict_times_set(dict_to_set: Dict, difference: int = 0) -> Dict:
    """

    :param dict_to_set: the raw dict
    :param difference: the difference (e.g. time zone)
    :return: the data dict with utc times
    """
    for field in dict_to_set.keys():
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


def time_fields(field_list: List[Dict]) -> list:
    """

    :param field_list: the list of fields for a given query
    :return: all fields (names only) that have a time value
    """
    indexes_list = []
    for i in range(len(field_list)):
        if 'time' in field_list[i]['name'].lower() or 'date' in field_list[i]['name'].lower():
            indexes_list.append(i)
    return indexes_list


def table_times_set(table_to_set: Dict, difference: int = 0) -> Dict:
    """

    :param table_to_set: the raw event/ alarm
    :param difference: the difference (e.g. time zone)
    :return: the event/ alarm with utc time
    """
    indexes_list = time_fields(table_to_set['columns'])
    for dict_ in table_to_set['rows']:
        dict_['values'] = list_times_set(dict_.get('values'), indexes_list, difference)
    return table_to_set


def search_readable_outputs(table: Dict) -> str:
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
        data: List = [str] * len(rows)
        for i in range(len(rows)):
            middle = '~'.join(rows[i].get('values', []))
            middle = middle.replace('|', '\\|')
            middle = middle.replace('~', '|')
            data[i] = f'| {middle} |'

        start = f'Search results\n{line_1}\n{line_2}\n'
        return start + '\n'.join(data)
    else:
        return ''


def create_incident(raw_incidents: List[Dict], alarms: bool) -> List[Dict[str, Dict]]:
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


def main():
    params = demisto.params()
    client = McAfeeESMClient(params)
    command = demisto.command()
    commands: Dict[str, Callable] = {
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
        'esm-search': client.complete_search
    }
    try:
        if command == 'fetch-incidents':
            client.fetch_incidents(params)
        elif command in commands:
            human_readable, context_entry, raw_response = commands[command]()
            return_outputs(human_readable, context_entry, raw_response)
        else:
            raise DemistoException(f'{command} is not a command.')

    except Exception as error:
        return_error(str(error), error)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
