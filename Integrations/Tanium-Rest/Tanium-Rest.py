import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
''' IMPORTS '''

import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''

class Client:
    def __init__(self, username, password, domain, url, use_ssl):
        self.url = url
        self.base_url = self.url
        self.verify = use_ssl
        self.username = username
        self.password = password
        self.domain = domain
        self.session = ''

    def do_request(self, method, url_suffix, data=None):
        if not self.session:
            self.update_session()

        res = self.http_request(method, url_suffix, data)

        if res.status_code == 403:
            self.update_session()
            res = self.http_request(method, url_suffix, data)
            if res.status_code != 200:
                return_error('Error in API call to ' + self.url + url_suffix + ' response= ' + res.text)
            return res.json()

        return res.json()

    def http_request(self, method, url_suffix, data=None,headers={}):
        if self.session:
            headers['session'] = self.session
        # A wrapper for requests lib to send our requests and handle requests and responses better
        res = requests.request(
            method,
            self.url + url_suffix,
            verify=self.verify,
            data=json.dumps(data),
            headers=headers
        )

        if res.status_code ==404:
            return_error(res.json().get('text'))

        # Handle error responses gracefully
        if res.status_code not in {200,403}:
            return_error('Error in API call to Integration [%d] - %s' % (res.status_code, res.reason))

        return res

    def update_session(self):
        body = {
            'username': self.username,
            'domain': self.domain,
            'password': self.password
        }

        res = self.http_request('GET', 'session/login', body)
        if res.status_code != 200:
            return_error('')

        self.session = res.json().get('data').get('session')

    def parse_parameters(self, parameters):
        sensors = parameters.split(';')
        parameter_conditions=[]

        for sensor in sensors:
            sensor_name = sensor.split('{')[0]
            tmp_item = {'sensor': sensor_name, 'parameters': []}

            parameters_txt = sensor.split('{')[1][:-1]
            params = parameters_txt.split(',')
            for param in params:
                tmp_item['parameters'].append({
                    'key': '||' + param.split('=')[0] + '||',
                    'value': param.split('=')[1]
                })
            parameter_conditions.append(tmp_item)

        return parameter_conditions

    def add_parameters_to_question(self, question_response, parameters):
        if not parameters:
            return question_response

        for item in question_response.get('selects'):
            sensor = item.get('sensor').get('name')

            for parameter in parameters:
                if parameter['sensor'] == sensor:
                    item['sensor']['parameters'] = parameter['parameters']
                    item['sensor']['source_hash'] = item['sensor']['hash']
                    del item['sensor']['hash']

        return question_response

    def parse_question(self, text, parameters):
        parameters_condition = []

        if parameters:
            try:
                parameters_condition = self.parse_parameters(parameters)
            except Exception:
                return_error('parameters parsing failed ')

        res = self.do_request('POST', 'parse_question', {'text': text}).get('data')[0]

        res = self.add_parameters_to_question(res, parameters_condition)
        return res

    def create_question(self, question_body):
        res = self.do_request('POST', 'questions', question_body)
        return res.get('data').get('id'),res

    def parse_question_results(self, result):
        results_sets = result.get('data').get('result_sets')[0]
        if results_sets.get('estimated_total') != results_sets.get('mr_tested'):
            return None
        if results_sets.get('row_count') == 0:
            return []

        rows=[]
        columns = []
        for column in results_sets.get('columns'):
            columns.append(column.get('name'))

        for row in results_sets.get('rows'):
            i=0
            tmp_row = {}
            for item in row.get('data'):
                tmp_row[columns[i]] = item[0].get('text')
                i += 1
            rows.append(tmp_row)
        return rows

    def update_id(self, obj):
        if 'id' in obj:
            obj['ID'] = obj['id']
            del obj['id']
            return obj
        return obj

    def get_package_item(self, package):
        item = {}
        item['ContentSet'] = {}
        item['ModUser'] = {}
        item['Command'] = package['command']
        item['CommandTimeout'] = package['command_timeout']
        item['ContentSet']['Id'] = package['content_set']['id']
        item['ContentSet']['Name'] = package['content_set']['name']
        item['CreationTime'] = package['creation_time']
        item['DisplayName'] = package['display_name']
        item['ExpireSeconds'] = package['expire_seconds']
        item['ID'] = package['id']
        item['LastModifiedBy'] = package['last_modified_by']
        item['LastUpdate'] = package['last_update']
        item['ModUser']['Domain'] = package['mod_user']['domain']
        item['ModUser']['Id'] = package['mod_user']['id']
        item['ModUser']['Name'] = package['mod_user']['name']
        item['ModificationTime'] = package['modification_time']
        item['Name'] = package['name']
        item['SourceId'] = package['source_id']
        item['VerifyExpireSeconds'] = package['verify_expire_seconds']
        item['Parameters'] = self.get_parameter_item(package)

        files = package.get('files')
        files_list = []
        if files:
            for file in files:
                tmp = {}
                tmp['Id'] = file.get('id')
                tmp['Hash'] = file.get('hash')
                tmp['Name'] = file.get('name')
                files_list.append(tmp)

        item['Files'] = files_list
        return item

    def get_question_item(self, question):
        item = {}
        item['ID'] = question['id']
        item['Expiration'] = question['expiration']
        item['ExpireSeconds'] = question['expire_seconds']
        item['ForceComputerIdFlag'] = question['force_computer_id_flag']
        item['IsExpired'] = question['is_expired']
        item['QueryText'] = question['query_text']

        saved_question_id = question['saved_question']['id']
        if saved_question_id:
            item['SavedQuestionId'] = saved_question_id
        item['UserId'] = question['user']['id']
        item['UserName'] = question['user']['name']
        return item

    def get_saved_question_item(self, question):
        item = {}
        item['ArchiveEnabledFlag'] = question['archive_enabled_flag']
        item['ArchiveOwner'] = question['archive_owner']
        item['ExpireSeconds'] = question['expire_seconds']
        item['ID'] = question['id']
        item['IssueSeconds'] = question['issue_seconds']
        item['IssueSecondsNeverFlag'] = question['issue_seconds_never_flag']
        item['KeepSeconds'] = question['keep_seconds']
        item['ModTime'] = question['mod_time']
        item['ModUserDomain'] = question['mod_user']['domain']
        item['ModUserId'] = question['mod_user']['id']
        item['ModUserName'] = question['mod_user']['name']
        item['MostRecentQuestionId'] = question['most_recent_question_id']
        item['Name'] = question['name']
        item['QueryText'] = question['query_text']
        item['QuestionId'] = question['question']['id']
        item['RowCountFlag'] = question['row_count_flag']
        item['SortColumn'] = question['sort_column']
        item['UserId'] = question['user']['id']
        item['UserName'] = question['user']['name']
        return item

    def get_sensor_item(self, sensor):
        item = {}
        item['Category'] = sensor['category']
        item['ContentSetId'] = sensor['content_set']['id']
        item['ContentSetName'] = sensor['content_set']['name']
        item['CreationTime'] = sensor['creation_time']
        item['Description'] = sensor['description']
        item['Hash'] = sensor['hash']
        item['ID'] = sensor['id']
        item['IgnoreCaseFlag'] = sensor['ignore_case_flag']
        item['KeepDuplicatesFlag'] = sensor['keep_duplicates_flag']
        item['LastModifiedBy'] = sensor['last_modified_by']
        item['MaxAgeSeconds'] = sensor['max_age_seconds']
        item['ModUserDomain'] = sensor['mod_user']['domain']
        item['ModUserId'] = sensor['mod_user']['id']
        item['ModUserName'] = sensor['mod_user']['name']
        item['ModificationTime'] = sensor['modification_time']
        item['Name'] = sensor['name']
        item['SourceId'] = sensor['source_id']
        item['Parameters'] = self.get_parameter_item(sensor)
        return item

    def get_parameter_item(self, sensor):
        parameters = sensor.get('parameter_definition')
        params_list = []
        if parameters:
            try:
                parameters = json.loads(parameters).get('parameters')
            except ValueError:
                return {'Value': parameters}
            for param in parameters:
                tmp = {}
                tmp['key'] = param.get('key')
                tmp['Label'] = param.get('label')
                tmp['Values'] = param.get('values')
                tmp['ParameterType'] = param.get('parameterType')
                params_list.append(tmp)
        return params_list

    def get_action_item(self, action):
        item = {}
        item['ActionGroupId'] = action['action_group']['id']
        item['ActionGroupName'] = action['action_group']['name']
        item['ApproverId'] = action['approver']['id']
        item['ApproverName'] = action['approver']['name']
        item['CreationTime'] = action['creation_time']
        item['ExpirationTime'] = action['expiration_time']
        item['ExpireSeconds'] = action['expire_seconds']
        item['HistorySavedQuestionId'] = action['history_saved_question']['id']
        item['ID'] = action['id']
        item['Name'] = action['name']
        item['PackageId'] = action['package_spec']['id']
        item['PackageName'] = action['package_spec']['name']
        item['SavedActionId'] = action['saved_action']['id']
        item['StartTime'] = action['start_time']
        item['Status'] = action['status']
        item['StoppedFlag'] = action['stopped_flag']
        item['TargetGroupId'] = action['target_group']['id']
        item['TargetGroupName'] = action['target_group']['name']
        item['UserDomain'] = action['user']['domain']
        item['UserId'] = action['user']['id']
        item['UserName'] = action['user']['name']
        return item

    def get_saved_action_item(self, action):
        item = {}
        item['ActionGroupId'] = action['action_group_id']
        item['ApprovedFlag'] = action['approved_flag']
        item['ApproverId'] = action['approver']['id']
        item['ApproverName'] = action['approver']['name']
        item['CreationTime'] = action['creation_time']
        item['EndTime'] = action['end_time']
        item['ExpireSeconds'] = action['expire_seconds']
        item['ID'] = action['id']
        item['LastActionId'] = action['last_action']['id']
        item['LastActionStartTime'] = action['last_action']['start_time']
        item['TargetGroupId'] = action['target_group']['id']
        item['LastStartTime'] = action['last_start_time']
        item['Name'] = action['name']
        item['NextStartTime'] = action['next_start_time']
        item['PackageId'] = action['package_spec']['id']
        item['PackageName'] = action['package_spec']['name']
        item['PackageSourceHash'] = action['package_spec']['source_hash']
        item['StartTime'] = action['start_time']
        item['Status'] = action['status']
        item['UserId'] = action['user']['id']
        item['UserName'] = action['user']['name']
        return item

    def get_saved_action_pending_item(self, action):
        item = {}
        item['ApprovedFlag'] = action['approved_flag']
        item['ID'] = action['id']
        item['Name'] = action['name']
        item['OwnerUserId'] = action['owner_user_id']
        return item


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    client.do_request('GET', 'system_status')


def get_package(client, data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('id and name arguments are missing')
    if id:
        endpoint_url = 'packages/' + str(id)
    if name:
        endpoint_url = 'packages/by-name/' + name

    raw_response = client.do_request('GET', endpoint_url)
    package = client.get_package_item(raw_response.get('data'))
    params = package.get('Parameters')
    files = package.get('Files')


    context = createContext(package, removeNull=True)
    outputs = {'TaniumPackage(val.ID === obj.ID)': context}

    del package['Parameters']
    del package['Files']

    human_readable = tableToMarkdown('Package information', package)
    human_readable += tableToMarkdown('Parameters information', params)
    human_readable += tableToMarkdown('Files information', files)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_packages(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'packages')

    packages = []

    for package in raw_response.get('data')[:-1][:count]:
        package = client.get_package_item(package)

        del package['Files']
        del package['Parameters']
        packages.append(package)

    context = createContext(packages, removeNull=True)
    outputs = {'TaniumPackage(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Packages', packages)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_package(client, data_args):
    name = data_args.get('name')
    command = data_args.get('command')
    body = {'name': name, 'command': command}

    raw_response = client.do_request('POST', 'packages', body)
    package = client.get_package_item(raw_response.get('data'))

    params = package.get('Parameters')
    files = package.get('Files')

    context = createContext(package, removeNull=True)
    outputs = {'TaniumPackage(val.ID === obj.ID)': context}

    del package['Parameters']
    del package['Files']

    human_readable = tableToMarkdown('Package information', package)
    human_readable += tableToMarkdown('Parameters information', params)
    human_readable += tableToMarkdown('Files information', files)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

def ask_question(client, data_args):
    question_text = data_args.get('question-text')
    parameters = data_args.get('parameters')

    body = client.parse_question(question_text, parameters)
    id, res = client.create_question(body)
    context = {'ID': id,'text': question_text}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Question(val.ID === obj.ID)': context}
    return_outputs(readable_output='New question created. ID: ' + str(id), outputs=outputs, raw_response=res)


def get_question_results(client, data_args):
    id = data_args.get('question-id')
    res = client.do_request('GET', 'result_data/question/' + str(id))

    rows = client.parse_question_results(res)

    if rows is None:
        return return_outputs(readable_output='Question is still executing, Question id: ' + str(id),
                              outputs={}, raw_response=res)

    context = {'QuestionID': id,'Results':rows}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.QuestionResult(val.QuestionID === question_id)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_sensors(client, data_args):
    count = int(data_args.get('count'))
    res = client.do_request('GET', 'sensors/')

    sensors=[]
    for sensor in res.get('data')[:-1][:count]:
        sensor = client.get_sensor_item(sensor)
        del sensor['Parameters']
        sensors.append(sensor)

    context = createContext(sensors, removeNull=True)
    outputs = {'Tanium.Sensor(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Sensors list:', sensors)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_sensor(client, data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('id and name arguments are missing')
    if id:
        endpoint_url = 'sensors/' + str(id)
    if name:
        endpoint_url = 'sensors/by-name/' + name

    raw_response = client.do_request('GET', endpoint_url)
    sensor = client.get_sensor_item(raw_response.get('data'))

    context = createContext(sensor, removeNull=True)
    outputs = {'TaniumSensor(val.ID === obj.ID)': context}

    params = sensor['Parameters']
    del sensor['Parameters']

    human_readable = tableToMarkdown('Sensor information', sensor)
    human_readable += tableToMarkdown('Parameter information', params)

    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_saved_question(client, data_args):
    id = data_args.get('question-id')
    name = data_args.get('name')
    body ={'name':name,'question':{'id':id}}
    raw_response = client.do_request('POST', 'saved_questions', body)

    response = raw_response.get('data')
    response = client.update_id(response)

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID === obj.ID)': context}
    return_outputs(readable_output='Question saved. ID = ' + str(response['ID']), outputs=outputs, raw_response=raw_response)


def get_saved_questions(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_questions')

    questions=[]
    for question in raw_response.get('data')[:-1][:count]:
        question = client.get_saved_question_item(question)
        questions.append(question)

    context = createContext(questions, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved questions:', questions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_question_results(client, data_args):
    id = data_args.get('question-id')

    res = client.do_request('GET', 'result_data/saved_question/' + str(id))

    rows = client.parse_question_results(res)
    if rows is None:
        return return_outputs(readable_output='Question is still executing, Question id: ' + str(id),
                              outputs={}, raw_response=res)

    context = {'SavedQuestionID': id, 'Results':rows}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.SavedQuestionResult(val.Tanium.SavedQuestionID === obj.ID)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_system_status(client):
    raw_response = client.do_request('GET', 'system_status')
    response = raw_response.get('data')

    context = []
    for item in response:
        if item.get('computer_id'):
            context.append(item)

    context = createContext(context, removeNull=True)
    outputs = {'Tanium.SystemStatus(val.computer_id === obj.computer_id)': context}
    human_readable = tableToMarkdown('System status:', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_question_metadata(client, data_args):
    id = data_args.get('question-id')
    raw_response = client.do_request('GET', 'questions/' + str(id))
    question_data = raw_response.get('data')
    question_data = client.get_question_item(question_data)

    context = createContext(question_data, removeNull=True)
    outputs = {'Tanium.Question(val.Tanium.ID === obj.ID)': context}
    human_readable = tableToMarkdown('question results:', question_data)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_question_metadata(client, data_args):
    id = data_args.get('question-id')
    name = data_args.get('question-name')
    endpoint_url = ''
    if not id and not name:
        return_error('question id and question name arguments are missing')
    if id:
        endpoint_url = 'saved_questions/' + str(id)
    if name:
        endpoint_url = 'saved_questions/by-name/' + name

    raw_response = client.do_request('GET', endpoint_url)
    response = client.get_saved_question_item(raw_response.get('data'))

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved question information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_actions(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_actions')

    actions = []
    for action in raw_response.get('data')[:-1][:count]:
        action = client.get_saved_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved actions:', actions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_action(client, data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('id and name arguments are missing')
    if id:
        endpoint_url = 'saved_actions/' + str(id)
    if name:
        endpoint_url = 'saved_actions/by-name/' + name

    raw_response = client.do_request('GET', endpoint_url)
    response = client.get_saved_action_item(raw_response.get('data'))

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved action information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_saved_action(client, data_args):
    action_group_id = data_args.get('action-group-id')
    package_id = data_args.get('package-id')
    name = data_args.get('name')

    body = {'name': name, 'action_group': {'id': action_group_id}, 'package_spec': {'id': package_id}}
    raw_response = client.do_request('POST', 'saved_actions', body)
    response = client.get_saved_action_item(raw_response.get('data'))

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved action created', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_action(client, data_args):
    package_id = data_args.get('package-name')

    body = {'package_spec': {'name': package_id}}
    raw_response = client.do_request('POST', 'actions', body)
    action = client.get_action_item(raw_response.get('data'))

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action created', action)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_actions(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'actions')

    actions = []
    for action in raw_response.get('data')[:-1][:count]:
        action = client.get_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.Action(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Actions:', actions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_action(client, data_args):
    id = data_args.get('id')
    raw_response = client.do_request('GET', 'actions/' + str(id))
    action = raw_response.get('data')
    action = client.get_action_item(action)

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action information:', action)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_actions_pending(client,data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_action_approvals')

    actions = []
    for action in raw_response.get('data')[:count]:
        action = client.get_saved_action_pending_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.PendingSavedAction(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved actions pending approval:', actions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    domain = demisto.params().get('domain')
    # Remove trailing slash to prevent wrong URL path to service
    server = demisto.params()['url'][:-1] \
        if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
    # Service base URL
    base_url = server + '/api/v2/'
    # Should we use SSL
    use_ssl = not demisto.params().get('insecure', False)

    # Remove proxy if not set to true in params
    handle_proxy()
    LOG('Command being called is %s' % (demisto.command()))

    try:
        client = Client(username, password, domain, base_url, use_ssl)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module(client)
            demisto.results('ok')
        elif demisto.command() == 'tn-get-package':
            get_package(client, demisto.args())
        elif demisto.command() == 'tn-ask-question':
            ask_question(client, demisto.args())
        elif demisto.command() == 'tn-get-question-result':
            get_question_results(client, demisto.args())
        elif demisto.command() == 'tn-list-sensors':
            get_sensors(client, demisto.args())
        elif demisto.command() == 'tn-get-sensor':
            get_sensor(client, demisto.args())
        elif demisto.command() == 'tn-create-saved-question':
            create_saved_question(client, demisto.args())
        elif demisto.command() == 'tn-list-saved-questions':
            get_saved_questions(client, demisto.args())
        elif demisto.command() == 'tn-get-saved-question-result':
            get_saved_question_results(client, demisto.args())
        elif demisto.command() == 'tn-get-system-status':
            get_system_status(client)
        elif demisto.command() == 'tn-create-package':
            create_package(client, demisto.args())
        elif demisto.command() == 'tn-list-packages':
            get_packages(client, demisto.args())
        elif demisto.command() == 'tn-get-question-metadata':
            get_question_metadata(client, demisto.args())
        elif demisto.command() == 'tn-get-saved-question-metadata':
            get_saved_question_metadata(client, demisto.args())
        elif demisto.command() == 'tn-list-saved-actions':
            get_saved_actions(client, demisto.args())
        elif demisto.command() == 'tn-get-saved-action':
            get_saved_action(client, demisto.args())
        elif demisto.command() == 'tn-create-saved-action':
            create_saved_action(client, demisto.args())
        elif demisto.command() == 'tn-create-action':
            create_action(client, demisto.args())
        elif demisto.command() == 'tn-list-actions':
            get_actions(client, demisto.args())
        elif demisto.command() == 'tn-get-action':
            get_action(client, demisto.args())
        elif demisto.command() == 'tn-list-saved-actions-pending-approval':
            get_saved_actions_pending(client, demisto.args())

    # Log exceptions
    except Exception as e:
        return_error('error has occurred: {}'.format(str(e)), error=e)


if __name__ == 'builtins':
    main()


#body = parse_question('Get Running Processes from all machines')
#id =create_question(body)
#res = get_saved_question_results({'question-id':21144})
#x=5
#get_package({'id':132})
#get_package({'name':'Detect Intel for Unix Revision 4 Delta'})
#get_saved_question_results({'question-id':'21144'})
#get_system_status()
#res = create_package({'name':'testw','command':'cmd'})
#x=5
#get_sensors()

#ask_question({'question-text': 'Get File Size from all machines','parameters': 'File Size{filename=c:\\windows\\system32\\cmd.exe}'})
#parse_parameters('File Size{filename=blah,key2=val2},sensor2{key1=val1}')
#get_packages({'count':5})