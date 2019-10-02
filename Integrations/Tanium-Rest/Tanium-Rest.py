
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import urllib3

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' GLOBALS/PARAMS '''


class Client(BaseClient):
    def __init__(self, base_url, username, password, domain, **kwargs):
        self.username = username
        self.password = password
        self.domain = domain
        self.session = ''
        super(Client, self).__init__(base_url, **kwargs)

    def do_request(self, method, url_suffix, data=None):
        if not self.session:
            self.update_session()

        res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data, resp_type='response', ok_codes = [200, 403,404] )

        if res.status_code == 403:
            self.update_session()
            res = self._http_request(method, url_suffix,headers={'session': self.session}, json_data=data, ok_codes=[200, 403, 404])
            return res

        if res.status_code == 404:
            return_error(res.json().get('text'))

        return res.json()

    def update_session(self):
        body = {
            'username': self.username,
            'domain': self.domain,
            'password': self.password
        }

        res = self._http_request('GET', 'session/login', json_data=body, ok_codes = [200] )

        self.session = res.get('data').get('session')

    def parse_sensor_parameters(self, parameters):
        sensors = parameters.split(';')
        parameter_conditions = []

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

    def parse_action_parameters(self, parameters):
        parameters = parameters.split(';')
        parameter_conditions = []
        for param in parameters:
            parameter_conditions.append({
                'key': param.split('=')[0],
                'value': param.split('=')[1]})

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
        parameters_condition = []  # type: ignore

        if parameters:
            try:
                parameters_condition = self.parse_sensor_parameters(parameters)
            except Exception:
                return_error('Failed to parse question parameters.')

        res = self.do_request('POST', 'parse_question', {'text': text}).get('data')[0]

        res = self.add_parameters_to_question(res, parameters_condition)
        return res

    def create_question(self, question_body):
        res = self.do_request('POST', 'questions', question_body)
        return res.get('data').get('id'), res

    def parse_question_results(self, result):
        results_sets = result.get('data').get('result_sets')[0]
        if results_sets.get('estimated_total') != results_sets.get('mr_tested'):
            return None
        if results_sets.get('row_count') == 0:
            return []

        rows = []
        columns = []
        for column in results_sets.get('columns'):
            columns.append(column.get('name').replace(' ', ''))

        for row in results_sets.get('rows'):
            i = 0
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
        item = {}  # type: ignore
        item['ContentSet'] = {}
        item['ModUser'] = {}
        item['Command'] = package.get('command')
        item['CommandTimeout'] = package.get('command_timeout')
        content_set = package.get('content_set')
        if content_set:
            item['ContentSet']['Id'] = content_set.get('id')
            item['ContentSet']['Name'] = content_set.get('name')

        item['CreationTime'] = package.get('creation_time')
        item['DisplayName'] = package.get('display_name')
        item['ExpireSeconds'] = package.get('expire_seconds')
        item['ID'] = package.get('id')
        item['LastModifiedBy'] = package.get('last_modified_by')
        item['LastUpdate'] = package.get('last_update')
        mod_user = package.get('ModUser')
        if mod_user:
            item['ModUser']['Domain'] = mod_user.get('domain')
            item['ModUser']['Id'] = mod_user.get('id')
            item['ModUser']['Name'] = mod_user.get('name')

        item['ModificationTime'] = package.get('modification_time')
        item['Name'] = package.get('name')
        item['SourceId'] = package.get('source_id')
        item['VerifyExpireSeconds'] = package.get('verify_expire_seconds')
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
        item['ID'] = question.get('id')
        item['Expiration'] = question.get('expiration')
        item['ExpireSeconds'] = question.get('expire_seconds')
        item['ForceComputerIdFlag'] = question.get('force_computer_id_flag')
        item['IsExpired'] = question.get('is_expired')
        item['QueryText'] = question.get('query_text')

        saved_question_id = question.get('saved_question').get('id')
        if saved_question_id:
            item['SavedQuestionId'] = saved_question_id
        user = question.get('user')
        if user:
            item['UserId'] = user.get('id')
            item['UserName'] = user.get('name')
        return item

    def get_saved_question_item(self, question):
        item = {}
        item['ArchiveEnabledFlag'] = question.get('archive_enabled_flag')
        item['ArchiveOwner'] = question.get('archive_owner')
        item['ExpireSeconds'] = question.get('expire_seconds')
        item['ID'] = question.get('id')
        item['IssueSeconds'] = question.get('issue_seconds')
        item['IssueSecondsNeverFlag'] = question.get('issue_seconds_never_flag')
        item['KeepSeconds'] = question.get('keep_seconds')
        item['ModTime'] = question.get('mod_time')

        mod_user = question.get('ModUser')
        if mod_user:
            item['ModUserDomain'] = mod_user.get('domain')
            item['ModUserId'] = mod_user.get('id')
            item['ModUserName'] = mod_user.get('name')

        item['MostRecentQuestionId'] = question.get('most_recent_question_id')
        item['Name'] = question.get('name')
        item['QueryText'] = question.get('query_text')
        item['QuestionId'] = question.get('question').get('id')
        item['RowCountFlag'] = question.get('row_count_flag')
        item['SortColumn'] = question.get('sort_column')

        user = question.get('user')
        if user:
            item['UserId'] = user.get('id')
            item['UserName'] = user.get('name')
        return item

    def get_sensor_item(self, sensor):
        item = {}
        item['Category'] = sensor.get('category')
        content_set = sensor.get('content_set')
        if content_set:
            item['ContentSetId'] = content_set.get('id')
            item['ContentSetName'] = content_set.get('name')
        item['CreationTime'] = sensor.get('creation_time')
        item['Description'] = sensor.get('description')
        item['Hash'] = sensor.get('hash')
        item['ID'] = sensor.get('id')
        item['IgnoreCaseFlag'] = sensor.get('ignore_case_flag')
        item['KeepDuplicatesFlag'] = sensor.get('keep_duplicates_flag')
        item['LastModifiedBy'] = sensor.get('last_modified_by')
        item['MaxAgeSeconds'] = sensor.get('max_age_seconds')

        mod_user = sensor.get('mod_user')
        if mod_user:
            item['ModUserDomain'] = mod_user.get('domain')
            item['ModUserId'] = mod_user.get('id')
            item['ModUserName'] = mod_user.get('name')
        item['ModificationTime'] = sensor.get('modification_time')
        item['Name'] = sensor.get('name')
        item['SourceId'] = sensor.get('source_id')
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

        item['ActionGroupId'] = action.get('action_group').get('id')
        item['ActionGroupName'] = action.get('action_group').get('name')
        item['ApproverId'] = action.get('approver').get('id')
        item['ApproverName'] = action.get('approver').get('name')
        item['CreationTime'] = action.get('creation_time')
        item['ExpirationTime'] = action.get('expiration_time')
        item['ExpireSeconds'] = action.get('expire_seconds')
        item['HistorySavedQuestionId'] = action.get('history_saved_question').get('id')
        item['ID'] = action.get('id')
        item['Name'] = action.get('name')
        item['PackageId'] = action.get('package_spec').get('id')
        item['PackageName'] = action.get('package_spec').get('name')
        item['SavedActionId'] = action.get('saved_action').get('id')
        item['StartTime'] = action.get('start_time')
        item['Status'] = action.get('status')
        item['StoppedFlag'] = action.get('stopped_flag')
        item['TargetGroupId'] = action.get('target_group').get('id')
        item['TargetGroupName'] = action.get('target_group').get('name')

        user = action.get('user')
        if user:
            item['UserDomain'] = user.get('domain')
            item['UserId'] = user.get('id')
            item['UserName'] = user.get('name')
        return item

    def get_saved_action_item(self, action):
        item = {}
        item['ActionGroupId'] = action.get('action_group_id')
        item['ApprovedFlag'] = action.get('approved_flag')
        item['ApproverId'] = action.get('approver').get('id')
        item['ApproverName'] = action.get('approver').get('name')
        item['CreationTime'] = action.get('creation_time')
        item['EndTime'] = action.get('end_time')
        item['ExpireSeconds'] = action.get('expire_seconds')
        item['ID'] = action.get('id')
        item['LastActionId'] = action.get('last_action').get('id')
        item['LastActionStartTime'] = action.get('last_action').get('start_time')
        item['TargetGroupId'] = action.get('target_group').get('id')
        item['LastStartTime'] = action.get('last_start_time')
        item['Name'] = action.get('name')
        item['NextStartTime'] = action.get('next_start_time')

        package_spec = action.get('package_spec')
        if package_spec:
            item['PackageId'] = package_spec.get('id')
            item['PackageName'] = package_spec.get('name')
            item['PackageSourceHash'] = package_spec.get('source_hash')
        item['StartTime'] = action.get('start_time')
        item['Status'] = action.get('status')
        item['UserId'] = action.get('user').get('id')
        item['UserName'] = action.get('user').get('name')
        return item

    def get_saved_action_pending_item(self, action):
        item = {}
        item['ApprovedFlag'] = action.get('approved_flag')
        item['ID'] = action.get('id')
        item['Name'] = action.get('name')
        item['OwnerUserId'] = action.get('owner_user_id')
        return item

    def get_host_item(self, client):
        item = {}
        item['ComputerId'] = client.get('computer_id')
        item['FullVersion'] = client.get('full_version')
        item['HostName'] = client.get('host_name')
        item['IpAddressClient'] = client.get('ipaddress_client')
        item['IpAddressServer'] = client.get('ipaddress_server')
        item['LastRegistration'] = client.get('last_registration')
        item['Status'] = client.get('status')
        return item

    def get_group_item(self, group):
        item = {}
        item['ID'] = group.get('id')
        item['Name'] = group.get('name')
        item['Deleted'] = group.get('deleted_flag')
        item['Text'] = group.get('text')

        type = group.get('type')
        if type == 0:
            type = 'Filter-based group'
        elif type == 1:
            type = 'Action group'
        elif type == 2:
            type = 'Action policy pair group'
        elif type == 3:
            type = 'Ad hoc group'
        elif type == 4:
            type = 'Manual group'

        item['Type'] = type
        return item

''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client, data_args):
    client.do_request('GET', 'system_status')
    return demisto.results('ok')


def get_system_status(client, data_args):
    raw_response = client.do_request('GET', 'system_status')
    response = raw_response.get('data')

    context = []
    for item in response:
        if item.get('computer_id'):
            context.append(client.get_host_item(item))

    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Client(val.ComputerId === obj.ComputerId)': context}
    human_readable = tableToMarkdown('System status', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


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


def get_sensors(client, data_args):
    count = int(data_args.get('count'))
    res = client.do_request('GET', 'sensors/')

    sensors = []
    for sensor in res.get('data')[:-1][:count]:
        sensor = client.get_sensor_item(sensor)
        del sensor['Parameters']
        sensors.append(sensor)

    context = createContext(sensors, removeNull=True)
    outputs = {'TaniumSensor(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Sensors', sensors)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def ask_question(client, data_args):
    question_text = data_args.get('question-text')
    parameters = data_args.get('parameters')

    body = client.parse_question(question_text, parameters)
    id, res = client.create_question(body)
    context = {'ID': id}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Question(val.ID === obj.ID)': context}
    return_outputs(readable_output='New question created. ID = ' + str(id), outputs=outputs, raw_response=res)


def get_question_metadata(client, data_args):
    id = data_args.get('question-id')
    raw_response = client.do_request('GET', 'questions/' + str(id))
    question_data = raw_response.get('data')
    question_data = client.get_question_item(question_data)

    context = createContext(question_data, removeNull=True)
    outputs = {'Tanium.Question(val.Tanium.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Question results', question_data)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_question_result(client, data_args):
    id = data_args.get('question-id')
    res = client.do_request('GET', 'result_data/question/' + str(id))

    rows = client.parse_question_results(res)

    if rows is None:
        context = {'QuestionID': id, 'Status': 'Pending'}
        return return_outputs(readable_output='Question is still executing, Question id: ' + str(id),
                              outputs={'Tanium.QuestionResult(val.QuestionID === id)': context}, raw_response=res)

    context = {'QuestionID': id, 'Status': 'Completed', 'Results': rows}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.QuestionResult(val.QuestionID === id)': context}
    human_readable = tableToMarkdown('Question results', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def create_saved_question(client, data_args):
    id = data_args.get('question-id')
    name = data_args.get('name')
    body = {'name': name, 'question': {'id': id}}
    raw_response = client.do_request('POST', 'saved_questions', body)

    response = raw_response.get('data')
    response = client.update_id(response)

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID === obj.ID)': context}
    return_outputs(readable_output='Question saved. ID = ' + str(response['ID']), outputs=outputs,
                   raw_response=raw_response)


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


def get_saved_question_result(client, data_args):
    id = data_args.get('question-id')

    res = client.do_request('GET', 'result_data/saved_question/' + str(id))

    rows = client.parse_question_results(res)
    if rows is None:
        context = {'SavedQuestionID': id, 'Status': 'Pending'}
        return return_outputs(readable_output='Question is still executing, Question id: ' + str(id),
                              outputs={'Tanium.SavedQuestionResult(val.SavedQuestionID === id)': context},
                              raw_response=res)

    context = {'SavedQuestionID': id, 'Status': 'Completed', 'Results': rows}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.SavedQuestionResult(val.Tanium.SavedQuestionID === obj.ID)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_saved_questions(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_questions')

    questions = []
    for question in raw_response.get('data')[:-1][:count]:
        question = client.get_saved_question_item(question)
        questions.append(question)

    context = createContext(questions, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved questions', questions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_action(client, data_args):
    package_id = data_args.get('package-id')
    package_name = data_args.get('package-name')
    parameters = data_args.get('parameters')
    parameters_condition = []  # type: ignore

    if not package_id and not package_name:
        return_error('package id and package name are missing')

    if package_name:
        get_package_res = client.do_request('GET', 'packages/by-name/' + package_name)
        package_id = get_package_res.get('data').get('id')

    if parameters:
        try:
            parameters_condition = client.parse_action_parameters(parameters)
        except Exception:
            return_error('Failed to parse action parameters.')

    body = {'package_spec': {'source_id': package_id}}

    if parameters_condition:
        body['package_spec']['parameters'] = []
        for param in parameters_condition:
            body['package_spec']['parameters'].append(param)

    raw_response = client.do_request('POST', 'actions', body)
    action = client.get_action_item(raw_response.get('data'))

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action created', action)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_action(client, data_args):
    id = data_args.get('id')
    raw_response = client.do_request('GET', 'actions/' + str(id))
    action = raw_response.get('data')
    action = client.get_action_item(action)

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action information', action)
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
    human_readable = tableToMarkdown('Actions', actions)
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


def get_saved_actions(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_actions')

    actions = []
    for action in raw_response.get('data')[:-1][:count]:
        action = client.get_saved_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved actions', actions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_actions_pending(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_action_approvals')

    actions = []
    for action in raw_response.get('data')[:count]:
        action = client.get_saved_action_pending_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.PendingSavedAction(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved actions pending approval', actions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_manual_group(client, data_args):
    group_name = data_args.get('group-name')
    hosts = data_args.get('computer-names')
    ip_addresses = data_args.get('ip-addresses')

    if not ip_addresses and not hosts:
        return_error('computer-names and ip-addresses arguments are missing')

    body = {'name': group_name}

    hosts = hosts.split(',')
    ips = ip_addresses.split(',')
    hosts_list = []
    ips_list = []

    for host in hosts:
        hosts_list.append({'computer_name': host})
    for ip in ips:
        ips_list.append({'ip_address': ip})

    body['computer_specs'] = hosts_list
    body['computer_specs'].extend(ips_list)

    raw_response = client.do_request('POST', 'computer_groups', body)
    group = raw_response.get('data')
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Group created', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_filter_based_group(client, data_args):
    group_name = data_args.get('group-name')
    text_filter = data_args.get('text-filter')

    body = {'name': group_name, 'text': text_filter}

    raw_response = client.do_request('POST', 'groups', body)
    group = raw_response.get('data')
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Group created', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_group(client, data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('id and name arguments are missing')
    if id:
        endpoint_url = 'groups/' + str(id)
    if name:
        endpoint_url = 'groups/by-name/' + name

    raw_response = client.do_request('GET', endpoint_url)
    group = raw_response.get('data')
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Group information', group)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_groups(client, data_args):
    count = int(data_args.get('count'))
    type = data_args.get('group-type')
    groups = []
    raw_response = {}
    if type == 'Manual':
        raw_response = client.do_request('GET', 'computer_groups')
        for group in raw_response.get('data')[:count]:
            groups.append(client.get_group_item(group))
    elif type == 'FilterBased':
        raw_response = client.do_request('GET', 'groups')
        for group in raw_response.get('data')[:-1][:count]:
            groups.append(client.get_group_item(group))


    context = createContext(groups, removeNull=True)
    outputs = {'Tanium.Group(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Groups', groups)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def delete_group(client, data_args):
    id = data_args.get('id')
    raw_response = client.do_request('DELETE', 'groups/' + str(id))
    human_readable = 'Group has been deleted. ID = ' + str(id)
    return_outputs(readable_output=human_readable, outputs={}, raw_response=raw_response)


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
    command = demisto.command()
    client = Client(base_url, username, password, domain, verify=use_ssl)
    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        f'tn-get-system-status': get_system_status,
        f'tn-get-package': get_package,
        f'tn-create-package': create_package,
        f'tn-list-packages': get_packages,
        f'tn-get-sensor': get_sensor,
        f'tn-list-sensors': get_sensors,
        f'tn-ask-question': ask_question,
        f'tn-get-question-metadata': get_question_metadata,
        f'tn-get-question-result': get_question_result,
        f'tn-create-saved-question': create_saved_question,
        f'tn-get-saved-question-metadata': get_saved_question_metadata,
        f'tn-get-saved-question-result': get_saved_question_result,
        f'tn-list-saved-questions': get_saved_questions,
        f'tn-create-action': create_action,
        f'tn-get-action': get_action,
        f'tn-list-actions': get_actions,
        f'tn-create-saved-action': create_saved_action,
        f'tn-get-saved-action': get_saved_action,
        f'tn-list-saved-actions': get_saved_actions,
        f'tn-list-saved-actions-pending-approval': get_saved_actions_pending,
        f'tn-create-filter-based-group': create_filter_based_group,
        f'tn-create-manual-group': create_manual_group,
        f'tn-get-group': get_group,
        f'tn-list-groups': get_groups,
        f'tn-delete-group': delete_group
    }

    try:
        if command in commands:
            return commands[command](client, demisto.args())
        # Log exceptions
    except Exception as e:
        err_msg = f'Error in Tanium Rest Integration [{e}]'
        return_error(err_msg, error=e)
    finally:
        LOG.print_log()


if __name__ == 'builtins':
    main()
