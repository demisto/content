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

        columns = []
        for column in results_sets.get('columns'):
            columns.append(column.get('name'))

        rows=[]

        for row in results_sets.get('rows'):
            i=0
            tmp_row = {}
            for item in row.get('data'):
                tmp_row[columns[i]] = item[0].get('text')
                i += 1
            rows.append(tmp_row)
        return rows


''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module(client):
    client.do_request('GET', 'groups')


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
    response = raw_response.get('data')
    response['ID'] = response['id']
    del response['id']

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_packages(client, data_args):
    count = int(data_args.get('count'))

    raw_response = client.do_request('GET', 'packages')

    packages = []

    for package in raw_response.get('data')[:-1][:count]:
        package['ID'] = package['id']
        del package['id']
        packages.append(package)

    context = createContext(packages, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_package(client, data_args):
    name = data_args.get('name')
    command = data_args.get('command')
    body = {'name': name, 'command': command}

    raw_response = client.do_request('POST', 'packages', body)

    package = raw_response.get('data')
    package['ID'] = package['id']
    del package['id']

    context = createContext(package, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

def ask_question(client, data_args):
    question_text = data_args.get('question-text')
    parameters = data_args.get('parameters')

    body = client.parse_question(question_text, parameters)
    id, res = client.create_question(body)
    context = {'ID': id,'text': question_text}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Questions(val.ID === obj.ID)': context}
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
    outputs = {'Tanium.results(val.QuestionID === question_id)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_sensors(client, data_args):
    count = int(data_args.get('count'))
    res = client.do_request('GET', 'sensors/')

    sensors=[]
    for sensor in res.get('data')[:-1][:count]:
        sensor['ID'] = sensor['id']
        del sensor['id']
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
    response = raw_response.get('data')
    response['ID'] = response['id']
    del response['id']

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.Sensor(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Sensor information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=response)


def create_saved_question(client, data_args):
    id = data_args.get('question-id')
    name = data_args.get('name')
    body ={'name':name,'question':{'id':id}}
    raw_response = client.do_request('POST', 'saved_questions',body)

    response = raw_response.get('data')
    response['ID'] = response['id']
    del response['id']

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestions(val.ID === obj.ID)': context}
    return_outputs(readable_output='Question saved. ID = ' + str(response['ID']), outputs=outputs, raw_response=raw_response)


def get_saved_questions(client, data_args):
    count = int(data_args.get('count'))
    raw_response = client.do_request('GET', 'saved_questions')

    questions=[]
    for question in raw_response.get('data')[:-1][:count]:
        question['ID'] = question['id']
        del question['id']
        questions.append(question)

    context = createContext(questions, removeNull=True)
    outputs = {'Tanium.SavedQuestions(val.ID === obj.ID)': context}
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
    outputs = {'Tanium.SavedQuestionsResults(val.SavedQuestionID === id)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_system_status(client):
    raw_response = client.do_request('GET', 'system_status')
    response = raw_response.get('data')

    context =[]
    for item in response:
        if item.get('computer_id'):
            context.append(item)

    context = createContext(context, removeNull=True)
    outputs = {'Tanium.SystemStatus(val.computer_id === obj.computer_id)': context}
    human_readable = tableToMarkdown('System status:', context)
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