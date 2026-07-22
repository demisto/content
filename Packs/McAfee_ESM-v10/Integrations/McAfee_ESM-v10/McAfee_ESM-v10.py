import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """
import base64
import json
import re
import sys
import requests
import time
import traceback
from datetime import datetime, timedelta
from distutils.util import strtobool

MAX_CASES_PER_FETCH = 30

# by default filters only "Closed" cases
FILTERED_OUT_STATUSES = [2, ]
VERIFY = demisto.params()['insecure'] is False
requests.packages.urllib3.disable_warnings()
VERSION = demisto.params()['version']
IS_V2_API = VERSION in ['10.2', '10.3', '11.1']

ESM_URL = demisto.params()['ip'] + ":" + demisto.params()['port']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
ESM_DATE_FORMAT = demisto.params()['time_format']
TIMEZONE = float(demisto.params().get('timezone'))


@logger
def parse_time(time_str):
    if ESM_DATE_FORMAT != 'auto-discovery':
        return ESM_DATE_FORMAT

    regex_to_format = {
        r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}': '%Y/%m/%d %H:%M:%S',  # '2018-12-31 16:54:32'
        r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}': '%d/%m/%Y %H:%M:%S',  # '31-12-2018 16:54:32'
    }

    selected_format = '%Y/%m/%d %H:%M:%S'
    for regex, time_format in regex_to_format.items():
        if re.match(regex, time_str):
            selected_format = time_format
            break

    return selected_format


@logger
def search_result_to_md(res):
    columns = res['columns']
    rows = res['rows']

    md = "### results:\n"

    if len(rows) == 0:
        return md + "No matching search result were found"

    # headers
    column_names = list(map(lambda column: column['name'], columns))
    md = md + ' | '.join(column_names) + '\n'
    md = md + ' | '.join(list(map(lambda column: "---", columns))) + '\n'

    # body
    for row in rows:
        md = md + ' | '.join(r.replace('|', '\\|') for r in row['values']) + '\n'

    return md


@logger
def search_results_to_context(res):
    columns = res['columns']
    rows = res['rows']
    fixed_searches = []
    for row in rows:
        values = row['values']
        i = 0
        for column in columns:
            if len(values[i]) != 0:
                column_string = column['name'].replace(".", "")
                column_string = column_string.replace(")", "")
                column_string = column_string.replace("(", "")
                fixed_searches.append({
                    column_string: values[i]
                })
            i += 1
    context = {'SearchResults(val.ID && val.ID == obj.ID)': fixed_searches}
    return context


def severity_to_level(severity):
    if severity > 65:
        return 3
    elif severity > 32:
        return 2
    else:
        return 1


class NitroESM(object):
    def __init__(self, esmhost, user, passwd):
        """ Init instance attributes """
        self.esmhost = esmhost
        self.user = user
        self.passwd = passwd
        self.url = 'https://{}/rs/esm/'.format(self.esmhost)
        self.session_headers = {'Content-Type': 'application/json'}
        self.is_logged_in = False
        self._case_statuses = None

    def __repr__(self):
        return 'NitroESM("{}", "{}")'.format(self.url, self.user)

    def login(self):
        b64_user = base64.b64encode(self.user.encode('utf-8')).decode()
        b64_passwd = base64.b64encode(self.passwd.encode('utf-8')).decode()
        params = {
            "username": b64_user,
            "password": b64_passwd,
            "locale": "en_US",
            "os": "Win32"
        }
        login_response = requests.post(self.url + 'login',
                                       json=params,
                                       headers=self.session_headers,
                                       verify=VERIFY)
        jwttoken = login_response.cookies.get('JWTToken')
        xsrf_token = login_response.headers.get('Xsrf-Token')
        if jwttoken is None or xsrf_token is None:
            raise Exception("Failed login\nurl: {}\n response status: {}\nresponse: {}\n".format(
                self.url + 'login',
                login_response.status_code,
                login_response.text))

        self.session_headers = {
            'Cookie': 'JWTToken=' + jwttoken,
            'X-Xsrf-Token': xsrf_token,
            'Content-Type': 'application/json'
        }
        self.is_logged_in = True

    def logout(self):
        if self.is_logged_in:
            try:
                url = self.url + ('v2/logout' if IS_V2_API else 'logout')
                requests.delete(url,
                                headers=self.session_headers,
                                data=json.dumps(''),
                                verify=VERIFY
                                )
                self.is_logged_in = False
            except Exception as e:
                demisto.error('McAfee ESM logout failed with the following error: %s' % (str(e),))

    @logger
    def cmdquery(self, cmd, query=None, params=None, no_answer=False, no_validation=False):
        """ Send query to ESM, return JSON result """
        LOG('querying endpoint: {}'.format(cmd))
        result = requests.post(self.url + cmd,
                               headers=self.session_headers,
                               params=params,
                               data=query, verify=VERIFY)
        if not no_validation:
            if no_answer:
                if result.status_code != 200:
                    raise ValueError(
                        'Error - ESM replied with:\n - status code: {} \n - body: {}'.format(result.status_code,
                                                                                             result.text))
            else:
                try:
                    res = result.json()
                    if VERSION != '10.0' and not cmd.startswith('v2'):
                        res = res['return']
                    return res
                except Exception as e:  # noqa: E722
                    LOG(str(e))
                    raise ValueError(
                        'Error - ESM replied with:\n - status code: {} \n - body: {}'.format(result.status_code,
                                                                                             result.text))

    @logger
    def execute_query(self, time_range, custom_start, custom_end, filters, fields, query_type):
        if time_range == 'CUSTOM' and (not custom_start or not custom_end):
            raise ValueError('you must specify customStart and customEnd when timeRange is CUSTOM')

        cmd = '%sqryExecuteDetail?reverse=false&type=%s' % ('v2/' if IS_V2_API else '', query_type,)

        if time_range == 'CUSTOM':
            cmd = cmd + '&customStart=' + custom_start + '&customEnd=' + custom_end

        q = {
            'config': {
                'timeRange': time_range,
                'filters': filters,
            }
        }
        if fields is not None:
            q['config']['fields'] = [{'name': v} for v in argToList(fields)]
        query = json.dumps(q)

        res = self.cmdquery(cmd, query)
        return res['resultID']

    @logger
    def get_query_result(self, result_id):
        cmd = '%sqryGetStatus' % ('v2/' if IS_V2_API else '',)
        query = json.dumps({'resultID': result_id})

        res = self.cmdquery(cmd, query)
        return res['complete']

    def wait_for_results(self, result_id, max_wait):

        # initial back off, sleep 3 sec between each time
        for i in range(5):
            ready = self.get_query_result(result_id)
            if ready:
                return
            else:
                time.sleep(3)

        # wait for response - 1 min between each try
        for i in range(max_wait):
            ready = self.get_query_result(result_id)
            if ready:
                return
            else:
                time.sleep(60)  # pylint: disable=sleep-exists

        raise ValueError('Waited more than {} min for query results : {}'.format(max_wait, result_id))

    @logger
    def fetch_results(self, result_id):
        cmd = '%sqryGetResults?startPos=0&reverse=false&numRows=10000' % ('v2/' if IS_V2_API else '',)

        query = json.dumps({'resultID': result_id})

        res = self.cmdquery(cmd, query)
        return res

    @logger
    def search(self, time_range, custom_start, custom_end, filters, fields, query_type, max_wait):
        # execute command
        result_id = self.execute_query(time_range, custom_start, custom_end, filters, fields, query_type)

        # wait for result to be ready
        self.wait_for_results(result_id, max_wait)

        # fetch result
        res = self.fetch_results(result_id)

        table = search_result_to_md(res)
        context = search_results_to_context(res)

        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': table,
            'EntryContext': context
        }

    @logger
    def fetch_all_fields(self):
        res = self.cmdquery('%sqryGetFilterFields' % ('v2/' if IS_V2_API else '',))

        # convert to an appropriate table
        for x in res:
            x['types'] = ','.join(x['types'])

        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': res,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tblToMd('Result:', res),
        }

    # alarms commands
    @logger
    def fetch_alarms(self, time_range, custom_start, custom_end, assigned_user):
        if time_range == 'CUSTOM' and (not custom_start or not custom_end):
            raise ValueError('you must specify customStart and customEnd when timeRange is CUSTOM')

        params = {
            'pageSize': 50,
            'pageNumber': 1,
            'triggeredTimeRange': time_range
        }

        if VERSION.startswith('11.'):
            cmd = 'alarmGetTriggeredAlarms'
        else:
            cmd = 'alarmGetTriggeredAlarmsPaged'
        if time_range == 'CUSTOM':
            params.update({
                'customStart': custom_start,
                'customEnd': custom_end,
            })

        query = ''
        if assigned_user == 'ME':
            user = self.get_user_obj(self.user)
            query = json.dumps({'assignedUser': user})
        elif assigned_user:
            query = json.dumps({'assignedUser': self.get_user_obj(assigned_user)})

        res = self.cmdquery(cmd, query, params=params)

        for alarm in res:
            alarm['ID'] = alarm['id']['value']
            del alarm["id"]

        return res

    @logger
    def update_alarms_status(self, action, alarm_ids):
        cmd = 'alarm%(action)sTriggeredAlarm' % {'action': action}
        query = json.dumps({'triggeredIds': [{'value': int(i)} for i in alarm_ids]})

        # the command return an error for a list of alarm ids however is execute the update successfully.
        self.cmdquery(cmd, query, no_validation=True)
        return 'Alarms has been %sd.' % (action,)

    @logger
    def acknowledge_alarms(self, alarm_ids):
        return self.update_alarms_status('Acknowledge', alarm_ids)

    @logger
    def unacknowledge_alarms(self, alarm_ids):
        return self.update_alarms_status('Unacknowledge', alarm_ids)

    @logger
    def delete_alarms(self, alarm_ids):
        return self.update_alarms_status('Delete', alarm_ids)

    @logger
    def get_alarm_event_details(self, event_id):
        cmd = ('%sipsGetAlertData' % ('v2/' if IS_V2_API else '',))
        query = json.dumps({'id': event_id})

        res = self.cmdquery(cmd, query)

        return res

    @logger
    def list_alarm_events(self, alarm_id):
        cmd = 'notifyGetTriggeredNotificationDetail'
        query = json.dumps({'id': alarm_id})

        res = self.cmdquery(cmd, query)

        return res

    # case statuses commands
    @logger
    def add_case_status(self, name, should_show_in_case_pane):
        """add a new type of case status with given parameters"""

        status_details = {
            'name': name,
            'default': False,
            'showInCasePane': should_show_in_case_pane
        }

        cmd = 'caseAddCaseStatus'
        query = json.dumps({'status': status_details})
        self.cmdquery(cmd, query)
        return 'Added case status : %s' % (name,)

    @logger
    def edit_case_status(self, original_name, new_name, show_in_case_pane):
        """edit a  case status with given id"""

        status_id = self.case_status_name_to_id(original_name)
        status_details = {
            'id': status_id,
            'name': new_name
        }

        if show_in_case_pane is not None:
            status_details['showInCasePane'] = show_in_case_pane

        cmd = 'caseEditCaseStatus'
        query = json.dumps({'status': status_details})
        self.cmdquery(cmd, query, no_answer=True)

        return 'Edit case status with ID: %d' % (status_id,)

    @logger
    def delete_case_status(self, name):
        """delete a new type of case status with given name"""

        status_id = self.case_status_name_to_id(name)
        status_id = {'value': status_id}

        cmd = 'caseDeleteCaseStatus'
        query = json.dumps({'statusId': status_id})
        self.cmdquery(cmd, query, no_answer=True)

        return 'Deleted case status with ID: %d' % (status_id['value'],)

    @logger
    def get_case_statuses(self):
        """get all case statuses"""

        cmd = 'caseGetCaseStatusList'
        query = json.dumps({"authPW": {"value": self.passwd}})

        return self.cmdquery(cmd, query)

    @logger
    def case_status_id_to_name(self, status_id, use_cache=True):
        """convert case status id to name"""
        if self._case_statuses is None:
            self._case_statuses = demisto.getIntegrationContext().get('case_statuses', None)

        if self._case_statuses is None or not use_cache or not any([s['id'] == status_id for s in self._case_statuses]):
            self._case_statuses = self.get_case_statuses()
            demisto.setIntegrationContext({
                'case_statuses': self._case_statuses
            })

        matches = [status['name'] for status in self._case_statuses if status['id'] == status_id]

        return matches[0] if matches else 'Unknown - %d' % (status_id,)

    @logger
    def case_status_name_to_id(self, status_name, use_cache=True):
        """convert case status name to id"""
        if self._case_statuses is None or not use_cache or not any(
                [s['name'].lower() == status_name.lower() for s in self._case_statuses]):
            self._case_statuses = self.get_case_statuses()

        matches = [status['id'] for status in self._case_statuses if status['name'].lower() == status_name.lower()]

        return matches[0] if matches else 0  # 0 is not a valid value

    # user commands
    @logger
    def get_users(self):
        """get all user's names"""

        cmd = 'userGetUserList'
        query = json.dumps({"authPW": {"value": self.passwd}})
        return self.cmdquery(cmd, query)

    @logger
    def get_user_obj(self, user_name):
        """get user object"""
        if user_name.lower() == 'me':
            user_name = self.user

        res = self.get_users()
        matches = [user for user in res if user['username'] == user_name]
        self_matches = [user['id']['value'] for user in res if user['username'] == self.user]

        # the login user must appear in the user list
        return matches[0] if matches else self_matches[0]

    @logger
    def user_name_to_id(self, user_name):
        """convert user name to id"""
        if user_name is None or user_name.lower() == 'me':
            user_name = self.user
        res = self.get_users()
        matches = [user['id']['value'] for user in res if user['username'] == user_name]
        self_matches = [user['id']['value'] for user in res if user['username'] == self.user]

        # the login user must appear in the user list
        return matches[0] if matches else self_matches[0]

    @logger
    def user_id_to_name(self, user_id):
        """convert user id to name"""
        res = self.get_users()
        matches = [user['username'] for user in res if user['id']['value'] == user_id]

        return matches[0] if matches else self.user

    # organization commands
    @logger
    def get_organizations(self):
        """get all organization names"""

        cmd = 'caseGetOrganizationList'
        return self.cmdquery(cmd, '')

    @logger
    def organization_name_to_id(self, organization_name):
        """convert organization name to id"""
        if organization_name is None:
            organization_name = ''
        res = self.get_organizations()
        matches = [org['id'] for org in res if org['name'].lower() == organization_name.lower()]

        return matches[0] if matches else 1

    @logger
    def organization_id_to_name(self, organization_id):
        """convert organization name to id"""
        res = self.get_organizations()
        matches = [org['name'] for org in res if org['id'] == organization_id]

        return matches[0] if matches else 'None'

    # cases commands
    @logger
    def get_cases(self, since_date_range=None):
        """get all cases associated with current user"""
        cmd = 'caseGetCaseList'
        res = self.cmdquery(cmd)
        cases = []
        if since_date_range:
            start_time, _ = parse_date_range(since_date_range, '%Y/%m/%d %H:%M:%S')
            for case in res:
                if case.get('openTime') > start_time:
                    cases.append(case)

        else:
            cases = res

        return cases

    def get_case_detail(self, case_id):
        cmd = 'caseGetCaseDetail'
        case_id = {'id': {'value': case_id}}
        query = json.dumps(case_id)
        res = self.cmdquery(cmd, query)

        return res

    def add_case(self, summary, severity, status, assignee, organization):
        if severity < 1:
            severity = 1
        elif severity > 100:
            severity = 100

        if status is None:
            status = 'Open'

        assignee = self.user_name_to_id(assignee)
        org_id = self.organization_name_to_id(organization)

        cmd = 'caseAddCase'
        case_details = {
            'summary': summary,
            'assignedTo': assignee,
            'severity': severity,
            'orgId': org_id,
            'statusId': {'value': self.case_status_name_to_id(status)},
        }

        query = json.dumps({'caseDetail': case_details})
        res = self.cmdquery(cmd, query)
        return res['value']

    def edit_case(self, case_id, summary, severity, status, assignee, organization):

        case = self.get_case_detail(case_id)

        if summary is not None:
            case['summary'] = summary

        if severity is not None:
            if severity < 1:
                severity = 1
            elif severity > 100:
                severity = 100
            case['severity'] = severity

        if status is not None:
            case['statusId'] = self.case_status_name_to_id(status)

        if assignee is not None:
            case['assignedTo'] = self.user_name_to_id(assignee)

        if organization is not None:
            case['orgId'] = self.organization_name_to_id(organization)

        # due to error 400 from api - java.util.ArrayList` out of VALUE_STRING
        del case['notes']
        del case['history']

        cmd = 'caseEditCase'
        query = json.dumps({'caseDetail': case})
        self.cmdquery(cmd, query, no_answer=True)

        return

    def get_case_event_list(self, event_ids):

        event_ids = {'list': event_ids}

        cmd = 'caseGetCaseEventsDetail'
        query = json.dumps({'eventIds': event_ids})
        res = self.cmdquery(cmd, query)

        return res


@logger
def alarms_to_entry(alarms):
    if not alarms:
        return "No alarms were found"

    context = {'Alarm(val.ID && val.ID == obj.ID)': alarms}
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': alarms,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd('Result:', alarms),
        'EntryContext': context
    }


@logger
def alarms_to_incidents(alarms):
    incidents = []
    for alarm in alarms:
        incidents.append({
            'name': alarm['summary'].encode('utf-8'),
            'details': 'Alarm {} , ID : {} , was triggered by condition type: {}'.format(
                alarm['alarmName'].encode('utf-8'),
                alarm['ID'],
                alarm['conditionType']),
            'severity': severity_to_level(alarm['severity']),
            'rawJSON': json.dumps(alarm)
        })
    return incidents


@logger
def cases_to_entry(esm, title, cases):
    if not cases:
        return 'No cases were found'

    headers = ['ID', 'Summary', 'Status', 'Severity', 'OpenTime']
    fixed_cases = []
    context_cases = []
    for case in cases:
        fixed_case = {
            'ID': case['id']['value'],
            'Summary': case['summary'],
            'Status': esm.case_status_id_to_name(
                case['statusId']['value'] if type(case['statusId']) is dict else case['statusId']),
            'OpenTime': case['openTime'],
            'Severity': case['severity']
        }

        if 'assignedTo' in case:
            fixed_case['Assignee'] = esm.user_id_to_name(case['assignedTo'])
            headers.append('Assignee')

        if 'orgId' in case:
            fixed_case['Organization'] = esm.organization_id_to_name(case['orgId'])
            headers.append('Organization')

        context_case = fixed_case.copy()
        if 'eventList' in case:
            fixed_case['Event List'] = json.dumps(case['eventList'])
            context_case['EventList'] = case['eventList']
            headers.append('Event List')

        if 'notes' in case:
            fixed_case['Notes'] = json.dumps(case['notes'])
            context_case['Notes'] = case['notes']
            headers.append('Notes')

        fixed_cases.append(fixed_case)
        context_cases.append(context_case)

    context = {'Case(val.ID && val.ID == obj.ID)': context_cases}

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': cases,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd(title, fixed_cases, headers),
        'EntryContext': context
    }


@logger
def cases_to_incidents(cases):
    incidents = []
    for case in cases:
        incident = {
            'name': case['summary'].encode('utf-8'),
            'details': 'Case %s with ID %s was triggerred' % (case['summary'].encode('utf-8'), case['id']['value']),
            'severity': severity_to_level(case['severity']),
            'rawJSON': json.dumps(case),
        }
        incidents.append(incident)

    return incidents


@logger
def case_statuses_to_entry(case_statuses):
    if not case_statuses:
        return 'No case statuses were found'

    headers = ['ID', 'Name', 'Is Default', 'Show In Case Pane']
    fixed_statuses = []
    for status in case_statuses:
        fixed_statuses.append({
            'ID': status['id'],
            'Name': status['name'],
            'Is Default': status['default'],
            'Show In Case Pane': status['showInCasePane']
        })

    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': fixed_statuses,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd('Result:', fixed_statuses, headers),
        'EntryContext': {}
    }


def organizations_to_entry(organizations):
    if not organizations:
        return 'No organizations were found'

    headers = ['ID', 'Name']
    fixed_organizations = []
    for organization in organizations:
        fixed_organizations.append({
            'ID': organization['id'],
            'Name': organization['name'],
        })

    context = {'Organizations(val.ID && val.ID == obj.ID)': fixed_organizations}
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': fixed_organizations,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd('Organizations:', fixed_organizations, headers),
        'EntryContext': context
    }


def case_events_to_entry(events):
    if not events:
        return 'No events were found'

    headers = ['ID', 'LastTime', 'Message']
    fixed_events = []
    for event in events:
        fixed_events.append({
            'ID': event['id']['value'],
            'LastTime': event['lastTime'],
            'Message': event['message'],
        })

    context = {'CaseEvents(val.ID && val.ID == obj.ID)': fixed_events}
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': fixed_events,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd('Case Events:', fixed_events, headers),
        'EntryContext': context
    }


def alarm_events_to_entry(esm, events):
    headers = ['ID', 'SubType', 'Severity', 'Message', 'LastTime', 'SrcIP', 'SrcPort', 'DstIP', 'DstPort', ]
    fixed_events = []
    for raw_event in events:
        # there are two type of event objects representation:
        # 1) the result of esm-list-alarm-events
        # 2) the result of esm-get-alarm-event-details
        # therefore, first try to get the field of the first option and fallback to the second option.
        cases = [{
            'ID': case['id'],
            'OpenTime': case['openTime'],
            'Severity': case['severity'],
            'Summary': case['summary'],
            'Status': esm.case_status_id_to_name(case['statusId']['value'])
        } for case in raw_event.get('cases', [])]
        event = {
            'ID': raw_event.get('eventId', '%s|%s' % (raw_event.get('ipsId', ''), raw_event.get('alertId', ''))),
            'SubType': raw_event.get('eventSubType', raw_event.get('subtype')),
            'Severity': raw_event['severity'],
            'Cases': cases,
            'Message': raw_event.get('ruleMessage', raw_event.get('ruleName')),
            'NormalizedDescription': raw_event.get('normDesc'),
            'FirstTime': raw_event.get('firstTime'),
            'LastTime': raw_event['lastTime'],

            'SrcMac': raw_event.get('srcMac'),
            'SrcIP': raw_event.get('sourceIp', raw_event.get('srcIp')),
            'SrcPort': raw_event.get('srcPort'),
            'DstMac': raw_event.get('destMac'),
            'DstIP': raw_event['destIp'],
            'DstPort': raw_event.get('destPort'),

            'Raw': raw_event,
        }

        fixed_events.append(event)

    context = {'EsmAlarmEvent(val.ID && val.ID == obj.ID)': createContext(fixed_events, removeNull=True)}
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': fixed_events,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd('Alarm Events:', fixed_events, headers=headers),
        'EntryContext': context
    }


@logger
def users_to_entry(users):
    # unreachable code - in order to send command, one must be logged in. therefore there is at least one user.
    if not users:
        return 'No users were found'

    headers = ['ID', 'Name', 'Email', 'SMS', 'IsMaster', 'IsAdmin']
    fixed_users = []
    for user in users:
        fixed_users.append({
            'ID': user['id']['value'],
            'Name': user['username'],
            'Email': user['email'],
            'SMS': user['sms'],
            'IsMaster': user['master'],
            'IsAdmin': user['admin'],
        })

    context = {'EsmUser(val.ID && val.ID == obj.ID)': fixed_users}
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': fixed_users,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tblToMd('Users:', fixed_users, headers),
        'EntryContext': context
    }


def main():
    esm = NitroESM(ESM_URL, USERNAME, PASSWORD)
    try:
        esm.login()
        final_result = 'No result set'

        if demisto.command() == 'fetch-incidents':
            last_run = demisto.getLastRun()
            demisto.debug('\n\nlast run:\n{}\n'.format(last_run))
            # for backward compatibility uses
            if 'value' in last_run and 'alarms' not in last_run:
                last_run['alarms'] = last_run['value']
            configuration_last_case = int(demisto.params().get('startingCaseID', 0))

            start_alarms = last_run.get('alarms')
            if start_alarms is None:
                start_alarms, _ = parse_date_range(demisto.params()['alarm_fetch_time'],
                                                   date_format='%Y-%m-%dT%H:%M:%S.%f', timezone=TIMEZONE)

            last_case = last_run.get('cases', 0)
            # if last_case < configuration_last_case:
            last_case = max(last_case, configuration_last_case)

            incidents = []  # type: list
            mode = demisto.params().get('fetchTypes', 'alarms').lower()  # alarms is default for backward compatibility

            next_run = None
            if mode in ('alarms', 'both'):
                end = (datetime.now() + timedelta(hours=TIMEZONE)).isoformat()

                demisto.debug("alarms: start - {} , end - {}".format(start_alarms, end))

                alarms = esm.fetch_alarms(
                    'CUSTOM',
                    start_alarms,
                    end,
                    ''
                )
                demisto.debug('alarms found:\n{}\n'.format(alarms))

                incidents = []
                for alarm in alarms:
                    triggered_date = alarm['triggeredDate']
                    if next_run is None or next_run < triggered_date:
                        next_run = triggered_date
                    alarm['events'] = esm.list_alarm_events(alarm['ID'])
                    incidents.append({
                        'name': alarm['summary'],
                        'details': 'Alarm {} , ID : {} , was triggered by condition type: {}'.format(
                            alarm['alarmName'],
                            alarm['ID'],
                            alarm['conditionType']),
                        'severity': severity_to_level(alarm['severity']),
                        'rawJSON': json.dumps(alarm)
                    })

            if mode in ('cases', 'both'):
                # get new cases
                cases = [case for case in esm.get_cases() if case['id']['value'] > last_case]
                cases.sort(key=lambda c: c['id']['value'])
                cases = cases[:MAX_CASES_PER_FETCH]

                if cases:
                    last_case = cases[-1]['id']['value']

                # update last run info
                last_run['cases'] = last_case

                demisto.debug('adding %d more cases, last id is: %d' % (len(cases), last_run['cases'],))
                if cases:
                    incidents.extend(cases_to_incidents(cases))

            if next_run is not None:
                next_run_datetime = datetime.strptime(next_run, parse_time(next_run))
                next_run = (next_run_datetime + timedelta(seconds=1)).isoformat()
            else:
                next_run = start_alarms

            last_run['value'] = next_run
            last_run['alarms'] = next_run

            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
            sys.exit(0)

        elif demisto.command() == 'test-module':
            if VERSION not in ['10.0', '10.1', '10.2', '10.3', '11.1']:
                final_result = 'version must be one of 10.x, got %s' % (VERSION,)
            else:
                esm.fetch_all_fields()
                final_result = 'ok'

        elif demisto.command() == 'esm-fetch-fields':
            res = esm.fetch_all_fields()
            final_result = res

        elif demisto.command() == 'esm-search':
            args = demisto.args()
            res = esm.search(
                demisto.get(args, 'timeRange'),
                demisto.get(args, 'customStart'),
                demisto.get(args, 'customEnd'),
                json.loads(args.get('filters')),
                args.get('fields'),
                demisto.get(args, 'queryType') or 'EVENT',
                demisto.get(args, 'maxWait') or 30
            )
            final_result = res

        elif demisto.command() == 'esm-get-case-list':
            since_date_range = demisto.args().get('since')
            res = esm.get_cases(since_date_range)
            final_result = cases_to_entry(esm, 'All cases:', res)

        elif demisto.command() == 'esm-get-case-detail':
            args = demisto.args()
            case_id = int(demisto.get(args, 'id'))
            res = esm.get_case_detail(case_id)
            final_result = cases_to_entry(esm, 'Case %d:' % (case_id,), [res])

        elif demisto.command() == 'esm-add-case':
            args = demisto.args()
            res = esm.add_case(
                demisto.get(args, 'summary'),
                int(demisto.get(args, 'severity')),
                demisto.get(args, 'status'),
                demisto.get(args, 'assignee'),
                demisto.get(args, 'organization'),
            )
            case = esm.get_case_detail(res)
            final_result = cases_to_entry(esm, 'New Case:', [case])

        elif demisto.command() == 'esm-edit-case':
            args = demisto.args()
            case_id = int(demisto.get(args, 'id'))
            severity = demisto.get(args, 'severity')
            esm.edit_case(
                case_id,
                demisto.get(args, 'summary'),
                int(severity) if severity else None,
                demisto.get(args, 'status'),
                demisto.get(args, 'assignee'),
                demisto.get(args, 'organization'),
            )
            case = esm.get_case_detail(case_id)
            final_result = cases_to_entry(esm, 'Edited Case:', [case])

        elif demisto.command() == 'esm-get-case-statuses':
            res = esm.get_case_statuses()
            final_result = case_statuses_to_entry(res)

        elif demisto.command() == 'esm-add-case-status':
            args = demisto.args()
            res = esm.add_case_status(
                demisto.get(args, 'name'),
                bool(strtobool(demisto.get(args, 'show_in_case_pane'))),
            )
            final_result = res

        elif demisto.command() == 'esm-edit-case-status':
            args = demisto.args()
            should_show = demisto.get(args, 'show_in_case_pane')
            res = esm.edit_case_status(
                demisto.get(args, 'original_name'),
                demisto.get(args, 'new_name'),
                bool(strtobool(should_show)) if should_show else None,
            )
            final_result = res

        elif demisto.command() == 'esm-delete-case-status':
            args = demisto.args()
            res = esm.delete_case_status(
                demisto.get(args, 'name')
            )
            final_result = res

        elif demisto.command() == 'esm-get-case-event-list':
            args = demisto.args()
            event_ids = demisto.get(args, 'ids').split(',')
            res = esm.get_case_event_list(event_ids)
            final_result = case_events_to_entry(res)

        elif demisto.command() == 'esm-get-organization-list':
            res = esm.get_organizations()
            final_result = organizations_to_entry(res)

        elif demisto.command() == 'esm-get-user-list':
            res = esm.get_users()
            final_result = users_to_entry(res)

        elif demisto.command() == 'esm-fetch-alarms':
            args = demisto.args()
            res = esm.fetch_alarms(
                demisto.get(args, 'timeRange'),
                demisto.get(args, 'customStart'),
                demisto.get(args, 'customEnd'),
                demisto.get(args, 'assignedUser')
            )
            final_result = alarms_to_entry(res)

        elif demisto.command() == 'esm-acknowledge-alarms':
            args = demisto.args()
            res = esm.acknowledge_alarms(argToList(demisto.get(args, 'alarmIds')))
            final_result = res

        elif demisto.command() == 'esm-unacknowledge-alarms':
            args = demisto.args()
            res = esm.unacknowledge_alarms(argToList(demisto.get(args, 'alarmIds')))
            final_result = res

        elif demisto.command() == 'esm-delete-alarms':
            args = demisto.args()
            res = esm.delete_alarms(argToList(demisto.get(args, 'alarmIds')))
            final_result = res

        elif demisto.command() == 'esm-get-alarm-event-details':
            args = demisto.args()
            res = esm.get_alarm_event_details(demisto.get(args, 'eventId'))
            final_result = alarm_events_to_entry(esm, [res])

        elif demisto.command() == 'esm-list-alarm-events':
            args = demisto.args()
            res = esm.list_alarm_events(demisto.get(args, 'alarmId'))
            final_result = alarm_events_to_entry(esm, res['events'])
        demisto.results(final_result)

    except Exception as ex:
        demisto.error('#### error in McAfee ESM v10: ' + str(ex))
        if demisto.command() == 'fetch-incidents':
            LOG(traceback.format_exc())
            LOG.print_log()
            raise
        else:
            return_error(str(ex), error=traceback.format_exc())
    finally:
        esm.logout()


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
