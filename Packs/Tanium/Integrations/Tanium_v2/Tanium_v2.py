from typing import Dict

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

''' GLOBALS/PARAMS '''
GROUP_TYPES = {0: 'Filter-based group', 1: 'Action group', 2: 'Action policy pair group', 3: 'Ad hoc group',
               4: 'Manual group'}
DEMISTO_API_ACTION_NAME = 'via Demisto API'
DEFAULT_COMPLETION_PERCENTAGE = "95"


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

        res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                 resp_type='response', ok_codes=[200, 400, 403, 404])

        if res.status_code == 403:
            self.update_session()
            res = self._http_request(method, url_suffix, headers={'session': self.session}, json_data=data,
                                     ok_codes=[200, 400, 404])
            return res

        if res.status_code == 404 or res.status_code == 400:
            raise requests.HTTPError(res.json().get('text'))

        return res.json()

    def update_session(self):
        body = {
            'username': self.username,
            'domain': self.domain,
            'password': self.password
        }

        res = self._http_request('GET', 'session/login', json_data=body, ok_codes=[200])

        self.session = res.get('data').get('session')
        return self.session

    def login(self):
        return self.update_session()

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

    def parse_action_parameters(self, parameters: str) -> List[Any]:
        """
        Receives a string representing a key=value list separated by ';', and returns them as a list of dictionaries
        Args:
            parameters (str): string which contains keys and values

        Returns:
            parameter_conditions (List): list of dictionaries
        """
        parameters = parameters.split(';')
        parameter_conditions: List[Dict[str, str]] = list()
        add_to_the_previous_pram = ''
        # Goes over the parameters from the end and any param that does not contain a key and value is added to the previous param
        for param in reversed(parameters):
            param += add_to_the_previous_pram
            add_to_the_previous_pram = ''
            if '=' not in param or param.startswith('='):
                add_to_the_previous_pram = f';{param}'
                continue
            parameter_conditions.insert(0, {
                'key': param.split('=', 1)[0],
                'value': param.split('=', 1)[1]})
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
                raise ValueError('Failed to parse question parameters.')

            res = self.do_request('POST', 'parse_question', {'text': text}).get('data')[0]
        else:
            # if there are no parameters argument - try to gets the sensors from parse question api
            # for example, if the input text question is: `Get Folder Contents[c:\] from all machines`
            # after the regex is: `Get Folder Contents from all machines`
            text_without_params = re.sub(r'\[(.*?)\]', '', text)
            res = self.do_request('POST', 'parse_question', {'text': text_without_params}).get('data')[0]

            # call sensors/by-name/ for each sensor in the response and update parameters_condition
            # with the correct parameters
            for item in res.get('selects', []):
                sensor = item.get('sensor', {}).get('name')
                search_results = re.search(rf'{sensor}\[(.*)\]', text)
                if search_results:
                    parameters_str = search_results.group(1)
                    parameters = parameters_str.split(',')
                    endpoint_url = f'sensors/by-name/{sensor}'
                    sensor_response = self.do_request('GET', endpoint_url)
                    sensor_response = self.get_sensor_item(sensor_response.get('data'))

                    tmp_item = {'sensor': sensor, 'parameters': []}
                    for param, sensor_key in zip(parameters, sensor_response['Parameters']):
                        if param:
                            if param == '""':
                                param = ''
                            tmp_item['parameters'].append({
                                'key': '||' + sensor_key['Key'] + '||',
                                'value': param
                            })
                    parameters_condition.append(tmp_item)

        res = self.add_parameters_to_question(res, parameters_condition)
        return res

    def create_question(self, question_body):
        res = self.do_request('POST', 'questions', question_body)
        return res.get('data').get('id'), res

    def parse_question_results(self, result, completion_percentage):
        results_sets = result.get('data').get('result_sets')[0]
        estimated_total = results_sets.get('estimated_total')
        mr_tested = results_sets.get('mr_tested')

        if not estimated_total and not mr_tested:
            return None

        percentage = mr_tested / estimated_total * 100

        if percentage < completion_percentage:
            return None
        if results_sets.get('row_count') == 0:
            return []

        rows = []
        columns = []
        for column in results_sets.get('columns'):
            columns.append(column.get('name').replace(' ', ''))

        for row in results_sets.get('rows'):
            tmp_row = {}
            for item, column in zip(row.get('data', []), columns):
                item_value = list(map(lambda x: x.get('text', ''), item))
                item_value = ', '.join(item_value)

                if item_value != '[no results]':
                    tmp_row[column] = item_value
            rows.append(tmp_row)

        return rows

    def update_id(self, obj):
        if 'id' in obj:
            obj['ID'] = obj['id']
            del obj['id']
            return obj
        return obj

    def build_create_action_body(self, by_host, action_name,
                                 parameters, package_id='', package_name='', action_group_id='', action_group_name='',
                                 target_group_id='', target_group_name='', hostname='', ip_address=''):
        """
        This method used to build create_action request body by host or by target group
        """

        # package and action group are mandatory and can be pass by name or id
        if not package_id and not package_name:
            raise ValueError('package id and package name are missing, Please specify one of them.')
        if not action_group_id and not action_group_name:
            raise ValueError('action group id and action group name are missing, Please specify one of them.')

        if action_name:
            action_name = f'{action_name} {DEMISTO_API_ACTION_NAME}'
        else:
            action_name = DEMISTO_API_ACTION_NAME

        # get package expire_seconds value
        if package_id:
            get_package_res = self.do_request('GET', 'packages/' + str(package_id))
        elif package_name:
            get_package_res = self.do_request('GET', 'packages/by-name/' + package_name)
            package_id = get_package_res.get('data').get('id')

        expire_seconds = get_package_res.get('data').get('expire_seconds', 0)

        target_group = {}  # type: ignore

        if by_host:
            # use Tanium parse question request to set target group by hostname or ip address
            if not ip_address and not hostname:
                raise ValueError('hostname and ip address are missing, Please specify one of them.')

            if ip_address:
                group_question = f'Get Computer Name from all machines with ip address equals {ip_address}'
            if hostname:
                group_question = f'Get Computer Name from all machines with Computer Name equals {hostname}'

            group_res = self.parse_question(group_question, None)
            target_group = group_res.get('group')

            if not target_group:
                raise ValueError('Failed to parse target group question')
        else:
            # set target group by id or name
            if not target_group_id and not target_group_name:
                raise ValueError('target group id and target group name are missing, Please specify one of them.')

            if target_group_id:
                target_group = {'id': target_group_id}
            if target_group_name:
                target_group = {'name': target_group_name}

        action_group = {}  # type: ignore
        if action_group_id:
            action_group = {'id': action_group_id}
        if action_group_name:
            action_group = {'name': action_group_name}

        parameters_condition = []  # type: ignore
        if parameters:
            # build action parameters object
            try:
                parameters_condition = self.parse_action_parameters(parameters)
            except Exception:
                raise ValueError('Failed to parse action parameters.')

        # crete the body of the response
        body = {'package_spec': {'source_id': package_id}}

        if parameters_condition:
            # set the parameters value to request body
            body['package_spec']['parameters'] = []
            for param in parameters_condition:
                body['package_spec']['parameters'].append(param)

        body['name'] = action_name
        body['target_group'] = target_group
        body['action_group'] = action_group
        body['expire_seconds'] = expire_seconds

        return body

    def get_package_item(self, package):
        item = {
            'ContentSet': {},
            'ModUser': {},
            'Command': package.get('command'),
            'CommandTimeout': package.get('command_timeout'),
            'CreationTime': package.get('creation_time'),
            'DisplayName': package.get('display_name'),
            'ExpireSeconds': package.get('expire_seconds'),
            'ID': package.get('id'),
            'LastModifiedBy': package.get('last_modified_by'),
            'LastUpdate': package.get('last_update'),
            'ModificationTime': package.get('modification_time'),
            'Name': package.get('name'),
            'SourceId': package.get('source_id'),
            'VerifyExpireSeconds': package.get('verify_expire_seconds'),
            'Parameters': self.get_parameter_item(package)
        }

        content_set = package.get('content_set')
        if content_set:
            item['ContentSet']['Id'] = content_set.get('id')
            item['ContentSet']['Name'] = content_set.get('name')

        mod_user = package.get('ModUser')
        if mod_user:
            item['ModUser']['Domain'] = mod_user.get('domain')
            item['ModUser']['Id'] = mod_user.get('id')
            item['ModUser']['Name'] = mod_user.get('name')

        files = package.get('files')
        files_list = []
        if files:
            for file in files:
                files_list.append({
                    'ID': file.get('id'),
                    'Hash': file.get('hash'),
                    'Name': file.get('name')
                })

        item['Files'] = files_list
        return item

    def get_question_item(self, question):
        item = {
            'ID': question.get('id'),
            'Expiration': question.get('expiration'),
            'ExpireSeconds': question.get('expire_seconds'),
            'ForceComputerIdFlag': question.get('force_computer_id_flag'),
            'IsExpired': question.get('is_expired'),
            'QueryText': question.get('query_text')
        }

        saved_question_id = question.get('saved_question').get('id')
        if saved_question_id:
            item['SavedQuestionId'] = saved_question_id

        user = question.get('user')
        if user:
            item['UserId'] = user.get('id')
            item['UserName'] = user.get('name')
        return item

    def get_saved_question_item(self, question):
        item = {
            'ArchiveEnabledFlag': question.get('archive_enabled_flag'),
            'ArchiveOwner': question.get('archive_owner'),
            'ExpireSeconds': question.get('expire_seconds'),
            'ID': question.get('id'),
            'IssueSeconds': question.get('issue_seconds'),
            'IssueSecondsNeverFlag': question.get('issue_seconds_never_flag'),
            'KeepSeconds': question.get('keep_seconds'),
            'ModTime': question.get('mod_time'),
            'MostRecentQuestionId': question.get('most_recent_question_id'),
            'Name': question.get('name'),
            'QueryText': question.get('query_text'),
            'QuestionId': question.get('question').get('id'),
            'RowCountFlag': question.get('row_count_flag'),
            'SortColumn': question.get('sort_column'),
        }

        mod_user = question.get('ModUser')
        if mod_user:
            item['ModUserDomain'] = mod_user.get('domain')
            item['ModUserId'] = mod_user.get('id')
            item['ModUserName'] = mod_user.get('name')

        user = question.get('user')
        if user:
            item['UserId'] = user.get('id')
            item['UserName'] = user.get('name')
        return item

    def get_sensor_item(self, sensor):
        item = {
            'Category': sensor.get('category', ''),
            'CreationTime': sensor.get('creation_time', ''),
            'Description': sensor.get('description', ''),
            'Hash': sensor.get('hash', ''),
            'ID': sensor.get('id', ''),
            'IgnoreCaseFlag': sensor.get('ignore_case_flag', ''),
            'KeepDuplicatesFlag': sensor.get('keep_duplicates_flag', ''),
            'LastModifiedBy': sensor.get('last_modified_by', ''),
            'MaxAgeSeconds': sensor.get('max_age_seconds', ''),
            'ModificationTime': sensor.get('modification_time', ''),
            'Name': sensor.get('name', ''),
            'SourceId': sensor.get('source_id', ''),
            'Parameters': self.get_parameter_item(sensor)
        }

        content_set = sensor.get('content_set')
        if content_set:
            item['ContentSetId'] = content_set.get('id')
            item['ContentSetName'] = content_set.get('name')

        mod_user = sensor.get('mod_user')
        if mod_user:
            item['ModUserDomain'] = mod_user.get('domain')
            item['ModUserId'] = mod_user.get('id')
            item['ModUserName'] = mod_user.get('name')

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
                params_list.append({
                    'Key': param.get('key'),
                    'Label': param.get('label'),
                    'Values': param.get('values'),
                    'ParameterType': param.get('parameterType')
                })

        return params_list

    def get_action_item(self, action):
        item = {
            'ActionGroupId': action.get('action_group').get('id'),
            'ActionGroupName': action.get('action_group').get('name'),
            'CreationTime': action.get('creation_time'),
            'ExpirationTime': action.get('expiration_time'),
            'ExpireSeconds': action.get('expire_seconds'),
            'HistorySavedQuestionId': action.get('history_saved_question').get('id'),
            'ID': action.get('id'),
            'Name': action.get('name'),
            'PackageId': action.get('package_spec').get('id'),
            'PackageName': action.get('package_spec').get('name'),
            'SavedActionId': action.get('saved_action').get('id'),
            'StartTime': action.get('start_time'),
            'Status': action.get('status'),
            'StoppedFlag': action.get('stopped_flag'),
            'TargetGroupId': action.get('target_group').get('id'),
            'TargetGroupName': action.get('target_group').get('name')
        }

        user = action.get('user')
        if user:
            item['UserDomain'] = user.get('domain')
            item['UserId'] = user.get('id')
            item['UserName'] = user.get('name')

        approver = action.get('approver')
        if approver:
            item['ApproverId'] = approver.get('id')
            item['ApproverName'] = approver.get('name')

        return item

    def get_saved_action_item(self, action):
        item = {
            'ActionGroupId': action.get('action_group_id'),
            'ApprovedFlag': action.get('approved_flag'),
            'ApproverId': action.get('approver').get('id'),
            'ApproverName': action.get('approver').get('name'),
            'CreationTime': action.get('creation_time'),
            'EndTime': action.get('end_time'),
            'ExpireSeconds': action.get('expire_seconds'),
            'ID': action.get('id'),
            'LastActionId': action.get('last_action').get('id'),
            'LastActionStartTime': action.get('last_action').get('start_time'),
            'TargetGroupId': action.get('target_group').get('id'),
            'LastStartTime': action.get('last_start_time'),
            'Name': action.get('name'),
            'NextStartTime': action.get('next_start_time'),
            'StartTime': action.get('start_time'),
            'Status': action.get('status'),
            'UserId': action.get('user').get('id'),
            'UserName': action.get('user').get('name')
        }

        package_spec = action.get('package_spec')
        if package_spec:
            item['PackageId'] = package_spec.get('id')
            item['PackageName'] = package_spec.get('name')
            item['PackageSourceHash'] = package_spec.get('source_hash')

        return item

    def get_saved_action_pending_item(self, action):
        return {
            'ApprovedFlag': action.get('approved_flag'),
            'ID': action.get('id'),
            'Name': action.get('name'),
            'OwnerUserId': action.get('owner_user_id')
        }

    def get_host_item(self, client):
        return {
            'ComputerId': client.get('computer_id'),
            'FullVersion': client.get('full_version'),
            'HostName': client.get('host_name'),
            'IpAddressClient': client.get('ipaddress_client'),
            'IpAddressServer': client.get('ipaddress_server'),
            'LastRegistration': client.get('last_registration'),
            'Status': client.get('status')
        }

    def get_group_item(self, group):
        item = {
            'ID': group.get('id'),
            'Name': group.get('name'),
            'Deleted': group.get('deleted_flag'),
            'Text': group.get('text')
        }
        group_type = group.get('type')

        if group_type:
            item['Type'] = GROUP_TYPES[group_type]
        else:
            item['Type'] = 'Manual group'

        return item


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client, data_args):
    if client.login():
        return demisto.results('ok')
    raise ValueError('Test Tanium integration failed - please check your username and password')


def get_system_status(client, data_args):
    raw_response = client.do_request('GET', 'system_status')
    response = raw_response.get('data')

    context = []
    for item in response:
        if item.get('computer_id'):
            context.append(client.get_host_item(item))

    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Client(val.ComputerId && val.ComputerId === obj.ComputerId)': context}
    human_readable = tableToMarkdown('System status', context)
    return human_readable, outputs, raw_response


def get_package(client, data_args):
    id_ = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id_ and not name:
        raise ValueError('id and name arguments are missing, Please specify one of them.')
    if name:
        endpoint_url = 'packages/by-name/' + name
    if id_:
        endpoint_url = 'packages/' + str(id_)

    raw_response = client.do_request('GET', endpoint_url)
    package = client.get_package_item(raw_response.get('data'))
    params = package.get('Parameters')
    files = package.get('Files')

    context = createContext(package, removeNull=True)
    outputs = {'TaniumPackage(val.ID && val.ID === obj.ID)': context}

    del package['Parameters']
    del package['Files']

    human_readable = tableToMarkdown('Package information', package)
    human_readable += tableToMarkdown('Parameters information', params)
    human_readable += tableToMarkdown('Files information', files)
    return human_readable, outputs, raw_response


def create_package(client, data_args):
    name = data_args.get('name')
    command = data_args.get('command')
    body = {'name': name, 'command': command}

    raw_response = client.do_request('POST', 'packages', body)
    package = client.get_package_item(raw_response.get('data'))

    params = package.get('Parameters')
    files = package.get('Files')

    context = createContext(package, removeNull=True)
    outputs = {'TaniumPackage(val.ID && val.ID === obj.ID)': context}

    human_readable = tableToMarkdown('Package information', package)
    human_readable += tableToMarkdown('Parameters information', params)
    human_readable += tableToMarkdown('Files information', files)
    return human_readable, outputs, raw_response


def get_packages(client, data_args):
    count = int(data_args.get('limit'))
    raw_response = client.do_request('GET', 'packages')
    packages = []

    # ignoring the last item because its not a package object
    for package in raw_response.get('data', [])[:-1][:count]:
        package = client.get_package_item(package)

        del package['Files']
        del package['Parameters']
        packages.append(package)

    context = createContext(packages, removeNull=True)
    outputs = {'TaniumPackage(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Packages', packages)
    return human_readable, outputs, raw_response


def get_sensor(client, data_args):
    id_ = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id_ and not name:
        raise ValueError('id and name arguments are missing, Please specify one of them.')
    if name:
        endpoint_url = 'sensors/by-name/' + name
    if id_:
        endpoint_url = 'sensors/' + str(id_)

    raw_response = client.do_request('GET', endpoint_url)
    sensor = client.get_sensor_item(raw_response.get('data'))

    context = createContext(sensor, removeNull=True)
    outputs = {'TaniumSensor(val.ID && val.ID === obj.ID)': context}

    params = sensor['Parameters']
    del sensor['Parameters']

    human_readable = tableToMarkdown('Sensor information', sensor)
    human_readable += tableToMarkdown('Parameter information', params)
    return human_readable, outputs, raw_response


def get_sensors(client, data_args):
    count = int(data_args.get('limit'))
    res = client.do_request('GET', 'sensors/')

    sensors = []
    # ignoring the last item because its not a sensor object
    for sensor in res.get('data', [])[:-1][:count]:
        sensor = client.get_sensor_item(sensor)
        del sensor['Parameters']
        sensors.append(sensor)

    context = createContext(sensors, removeNull=True)
    outputs = {'TaniumSensor(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Sensors', sensors)
    return human_readable, outputs, res


def ask_question(client, data_args):
    question_text = data_args.get('question-text')
    parameters = data_args.get('parameters')

    if parameters:
        body = client.parse_question(question_text, parameters)
        id_, res = client.create_question(body)
    else:
        res = client.do_request('POST', 'questions', {'query_text': question_text})
        id_ = res.get('data').get('id')

    context = {'ID': id_}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Question(val.ID && val.ID === obj.ID)': context}
    return f'New question created. ID = {str(id_)}', outputs, res


def get_question_metadata(client, data_args):
    id_ = data_args.get('question-id')
    raw_response = client.do_request('GET', 'questions/' + str(id_))
    question_data = raw_response.get('data')
    question_data = client.get_question_item(question_data)

    context = createContext(question_data, removeNull=True)
    outputs = {'Tanium.Question(val.Tanium.ID && val.Tanium.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Question results', question_data)
    return human_readable, outputs, raw_response


def get_question_result(client, data_args):
    id_ = data_args.get('question-id')
    completion_percentage = int(data_args.get('completion-percentage', DEFAULT_COMPLETION_PERCENTAGE))
    if completion_percentage > 100 or completion_percentage < 1:
        raise ValueError('completion-percentage argument is invalid, Please enter number between 1 to 100')

    res = client.do_request('GET', 'result_data/question/' + str(id_))

    rows = client.parse_question_results(res, completion_percentage)

    if rows is None:
        context = {'QuestionID': id_, 'Status': 'Pending'}
        return f'Question is still executing, Question id: {str(id_)}',\
            {f'Tanium.QuestionResult(val.QuestionID == {id_})': context}, res

    context = {'QuestionID': id_, 'Status': 'Completed', 'Results': rows}
    context = createContext(context, removeNull=True)
    outputs = {f'Tanium.QuestionResult(val.QuestionID == {id_})': context}
    human_readable = tableToMarkdown('Question results', rows)
    return human_readable, outputs, res


def create_saved_question(client, data_args):
    id_ = data_args.get('question-id')
    name = data_args.get('name')
    body = {'name': name, 'question': {'id': id_}}
    raw_response = client.do_request('POST', 'saved_questions', body)

    response = raw_response.get('data')
    response = client.update_id(response)

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID && val.ID === obj.ID)': context}
    saved_question_id = str(response['ID'])
    return f'Question saved. ID = {saved_question_id}', outputs, raw_response


def get_saved_question_metadata(client, data_args):
    id_ = data_args.get('question-id')
    name = data_args.get('question-name')
    endpoint_url = ''
    if not id_ and not name:
        raise ValueError('question id and question name arguments are missing, Please specify one of them.')
    if name:
        endpoint_url = 'saved_questions/by-name/' + name
    if id_:
        endpoint_url = 'saved_questions/' + str(id_)

    raw_response = client.do_request('GET', endpoint_url)
    response = client.get_saved_question_item(raw_response.get('data'))

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved question information', context)
    return human_readable, outputs, raw_response


def get_saved_question_result(client, data_args):
    id_ = data_args.get('question-id')
    completion_percentage = int(data_args.get('completion-percentage', DEFAULT_COMPLETION_PERCENTAGE))
    if completion_percentage > 100 or completion_percentage < 1:
        raise ValueError('completion-percentage argument is invalid, Please enter number between 1 to 100')

    res = client.do_request('GET', 'result_data/saved_question/' + str(id_))

    rows = client.parse_question_results(res, completion_percentage)
    if rows is None:
        context = {'SavedQuestionID': id_, 'Status': 'Pending'}
        return f'Question is still executing, Question id: {str(id_)}',\
            {f'Tanium.SavedQuestionResult(val.SavedQuestionID == {id_})': context}, res

    context = {'SavedQuestionID': id_, 'Status': 'Completed', 'Results': rows}
    context = createContext(context, removeNull=True)
    outputs = {f'Tanium.SavedQuestionResult(val.SavedQuestionID == {id_})': context}
    human_readable = tableToMarkdown('question results:', rows)
    return human_readable, outputs, res


def get_saved_questions(client, data_args):
    count = int(data_args.get('limit'))
    raw_response = client.do_request('GET', 'saved_questions')

    questions = []
    # ignoring the last item because its not a saved question object
    for question in raw_response.get('data', [])[:-1][:count]:
        question = client.get_saved_question_item(question)
        questions.append(question)

    context = createContext(questions, removeNull=True)
    outputs = {'Tanium.SavedQuestion(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved questions', questions)
    return human_readable, outputs, raw_response


def create_action(client, data_args):
    action_name = data_args.get('action-name')
    package_id = data_args.get('package-id')
    package_name = data_args.get('package-name')
    target_group_id = data_args.get('target-group-id')
    target_group_name = data_args.get('target-group-name')
    action_group_id = data_args.get('action-group-id')
    action_group_name = data_args.get('action-group-name')
    parameters = data_args.get('parameters')

    body = client.build_create_action_body(False, action_name, parameters, package_id=package_id,
                                           package_name=package_name, action_group_id=action_group_id,
                                           action_group_name=action_group_name, target_group_id=target_group_id,
                                           target_group_name=target_group_name)

    raw_response = client.do_request('POST', 'actions', body)
    action = client.get_action_item(raw_response.get('data'))

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action created', action)
    return human_readable, outputs, raw_response


def create_action_by_host(client, data_args):
    action_name = data_args.get('action-name')
    package_id = data_args.get('package-id')
    package_name = data_args.get('package-name')
    action_group_id = data_args.get('action-group-id')
    action_group_name = data_args.get('action-group-name')
    parameters = data_args.get('parameters')
    ip_address = data_args.get('ip-address')
    hostname = data_args.get('hostname')

    body = client.build_create_action_body(True, action_name, parameters, package_id=package_id,
                                           package_name=package_name, action_group_id=action_group_id,
                                           action_group_name=action_group_name,
                                           hostname=hostname, ip_address=ip_address)

    raw_response = client.do_request('POST', 'actions', body)
    action = client.get_action_item(raw_response.get('data'))

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action created', action)
    return human_readable, outputs, raw_response


def get_action(client, data_args):
    id_ = data_args.get('id')
    raw_response = client.do_request('GET', 'actions/' + str(id_))
    action = raw_response.get('data')
    action = client.get_action_item(action)

    context = createContext(action, removeNull=True)
    outputs = {'Tanium.Action(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Action information', action)
    return human_readable, outputs, raw_response


def get_actions(client, data_args):
    count = int(data_args.get('limit'))
    raw_response = client.do_request('GET', 'actions')

    actions = []
    # ignoring the last item because its not action object
    for action in raw_response.get('data', [])[:-1][:count]:
        action = client.get_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.Action(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Actions', actions)
    return human_readable, outputs, raw_response


def create_saved_action(client, data_args):
    action_group_id = data_args.get('action-group-id')
    package_id = data_args.get('package-id')
    name = data_args.get('name')

    body = {'name': name, 'action_group': {'id': action_group_id}, 'package_spec': {'id': package_id}}
    raw_response = client.do_request('POST', 'saved_actions', body)
    response = client.get_saved_action_item(raw_response.get('data'))

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved action created', context)
    return human_readable, outputs, raw_response


def get_saved_action(client, data_args):
    id_ = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id_ and not name:
        raise ValueError('id and name arguments are missing, Please specify one of them.')
    if name:
        endpoint_url = 'saved_actions/by-name/' + name
    if id_:
        endpoint_url = 'saved_actions/' + str(id_)

    raw_response = client.do_request('GET', endpoint_url)
    response = client.get_saved_action_item(raw_response.get('data'))

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved action information', context)
    return human_readable, outputs, raw_response


def get_saved_actions(client, data_args):
    count = int(data_args.get('limit'))
    raw_response = client.do_request('GET', 'saved_actions')

    actions = []
    # ignoring the last item because its not a saved action object
    for action in raw_response.get('data', [])[:-1][:count]:
        action = client.get_saved_action_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.SavedAction(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved actions', actions)
    return human_readable, outputs, raw_response


def get_saved_actions_pending(client, data_args):
    count = int(data_args.get('limit'))
    raw_response = client.do_request('GET', 'saved_action_approvals')

    actions = []
    for action in raw_response.get('data', [])[:count]:
        action = client.get_saved_action_pending_item(action)
        actions.append(action)

    context = createContext(actions, removeNull=True)
    outputs = {'Tanium.PendingSavedAction(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved actions pending approval', actions)
    return human_readable, outputs, raw_response


def create_manual_group(client, data_args):
    group_name = data_args.get('group-name')
    hosts = data_args.get('computer-names')
    ip_addresses = data_args.get('ip-addresses')

    if not ip_addresses and not hosts:
        raise ValueError('computer-names and ip-addresses arguments are missing, Please specify one of them.')

    body = {'name': group_name}

    hosts_list = []
    ips_list = []

    if hosts:
        hosts = hosts.split(',')
        for host in hosts:
            hosts_list.append({'computer_name': host})

    if ip_addresses:
        ip_addresses = ip_addresses.split(',')
        for ip in ip_addresses:
            ips_list.append({'ip_address': ip})

    body['computer_specs'] = hosts_list
    body['computer_specs'].extend(ips_list)

    raw_response = client.do_request('POST', 'computer_groups', body)
    group = raw_response.get('data')
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Group created', context)
    return human_readable, outputs, raw_response


def create_filter_based_group(client, data_args):
    group_name = data_args.get('group-name')
    text_filter = data_args.get('text-filter')

    body = {'name': group_name, 'text': text_filter}

    raw_response = client.do_request('POST', 'groups', body)
    group = raw_response.get('data')
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Group created', context)
    return human_readable, outputs, raw_response


def get_group(client, data_args):
    id_ = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id_ and not name:
        raise ValueError('id and name arguments are missing, Please specify one of them.')
    if name:
        endpoint_url = 'groups/by-name/' + name
    if id_:
        endpoint_url = 'groups/' + str(id_)

    raw_response = client.do_request('GET', endpoint_url)
    group = raw_response.get('data')
    group = client.get_group_item(group)

    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Group information', group)
    return human_readable, outputs, raw_response


def get_groups(client, data_args):
    count = int(data_args.get('limit'))
    groups = []

    raw_response = client.do_request('GET', 'groups')
    # ignoring the last item because its not a group object
    for group in raw_response.get('data', [])[:-1][:count]:
        groups.append(client.get_group_item(group))

    context = createContext(groups, removeNull=True)
    outputs = {'Tanium.Group(val.ID && val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Groups', groups)
    return human_readable, outputs, raw_response


def delete_group(client, data_args):
    id_ = data_args.get('id')
    raw_response = client.do_request('DELETE', f'groups/{id_}')
    group = {'ID': int(id_), 'Deleted': True}
    human_readable = f'Group has been deleted. ID = {id_}'
    context = createContext(group, removeNull=True)
    outputs = {'Tanium.Group(val.ID && val.ID === obj.ID)': context}
    return human_readable, outputs, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    domain = params.get('domain')
    # Remove trailing slash to prevent wrong URL path to service
    server = params['url'].strip('/')
    # Service base URL
    base_url = server + '/api/v2/'
    # Should we use SSL
    use_ssl = not params.get('insecure', False)

    # Remove proxy if not set to true in params
    handle_proxy()
    command = demisto.command()
    client = Client(base_url, username, password, domain, verify=use_ssl)
    demisto.info(f'Command being called is {command}')

    commands = {
        'test-module': test_module,
        'tn-get-system-status': get_system_status,
        'tn-get-package': get_package,
        'tn-create-package': create_package,
        'tn-list-packages': get_packages,
        'tn-get-sensor': get_sensor,
        'tn-list-sensors': get_sensors,
        'tn-ask-question': ask_question,
        'tn-get-question-metadata': get_question_metadata,
        'tn-get-question-result': get_question_result,
        'tn-create-saved-question': create_saved_question,
        'tn-get-saved-question-metadata': get_saved_question_metadata,
        'tn-get-saved-question-result': get_saved_question_result,
        'tn-list-saved-questions': get_saved_questions,
        'tn-create-action': create_action,
        'tn-create-action-by-host': create_action_by_host,
        'tn-get-action': get_action,
        'tn-list-actions': get_actions,
        'tn-create-saved-action': create_saved_action,
        'tn-get-saved-action': get_saved_action,
        'tn-list-saved-actions': get_saved_actions,
        'tn-list-saved-actions-pending-approval': get_saved_actions_pending,
        'tn-create-filter-based-group': create_filter_based_group,
        'tn-create-manual-group': create_manual_group,
        'tn-get-group': get_group,
        'tn-list-groups': get_groups,
        'tn-delete-group': delete_group
    }

    try:
        if command in commands:
            human_readable, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)
        # Log exceptions
    except Exception as e:
        err_msg = f'Error in Tanium v2 Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
