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

USERNAME = demisto.params().get('credentials').get('identifier')
PASSWORD = demisto.params().get('credentials').get('password')
Domain = demisto.params().get('domain')
# Remove trailing slash to prevent wrong URL path to service
SERVER = demisto.params()['url'][:-1] \
    if (demisto.params()['url'] and demisto.params()['url'].endswith('/')) else demisto.params()['url']
# Should we use SSL
USE_SSL = not demisto.params().get('insecure', False)

# Service base URL
BASE_URL = SERVER + '/api/v2/'
SESSION = ''

# Remove proxy if not set to true in params
if not demisto.params().get('proxy'):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']


''' HELPER FUNCTIONS '''


def do_request(method, url_suffix, data=None):
    global SESSION
    if not SESSION:
        update_session()

    res = http_request(method, url_suffix, data)

    if res.status_code == 403:
        update_session()
        res = http_request(method, url_suffix, data)
        if res.status_code != 200:
            return_error('Error in API call to '+ BASE_URL + url_suffix + ' response= ' + res.text)
        return res.json()

    return res.json()


def http_request(method, url_suffix, data=None,headers={}):
    global SESSION
    if SESSION:
        headers['session'] = SESSION
    # A wrapper for requests lib to send our requests and handle requests and responses better
    res = requests.request(
        method,
        BASE_URL + url_suffix,
        verify=USE_SSL,
        data=json.dumps(data),
        headers=headers
    )

    if res.status_code ==404:
        return_error(res.json().get('text'))

    # Handle error responses gracefully
    if res.status_code not in {200,403}:
        return_error('Error in API call to Integration [%d] - %s' % (res.status_code, res.reason))

    return res


def update_session():
    body = {
        'username': USERNAME,
        'domain': Domain,
        'password': PASSWORD
    }

    res = http_request('GET', 'session/login', body)
    if res.status_code != 200:
        return_error('')
    global SESSION

    SESSION = res.json().get('data').get('session')


def parse_parameters(parameters):
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


def add_parameters_to_question(question_response, parameters):
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


def parse_question(text, parameters):
    parameters_condition = []

    if parameters:
        try:
            parameters_condition =parse_parameters(parameters)
        except Exception:
            return_error('parameters parsing failed ')

    res = do_request('POST', 'parse_question', {'text': text}).get('data')[0]

    res = add_parameters_to_question(res, parameters_condition)
    return res


def create_question(question_body):
    res = do_request('POST', 'questions', question_body)
    return res.get('data').get('id'),res


def parse_question_results(result):
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


def test_module():
    do_request('GET', 'groups')


def get_package(data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('id and name arguments are missing')
    if id:
        endpoint_url = 'packages/' + str(id)
    if name:
        endpoint_url = 'packages/by-name/' + name


    raw_response = do_request('GET', endpoint_url)
    response = raw_response.get('data')
    response['ID'] = response['id']
    del response['id']

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_packages(data_args):
    count = int(data_args.get('count'))

    raw_response = do_request('GET', 'packages')

    packages = []

    for package in raw_response.get('data')[:-1][:count]:
        package['ID'] = package['id']
        del package['id']
        packages.append(package)

    context = createContext(packages, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def create_package(data_args):
    name = data_args.get('name')
    command = data_args.get('command')
    body = {'name': name, 'command': command}

    raw_response = do_request('POST', 'packages', body)

    package = raw_response.get('data')
    package['ID'] = package['id']
    del package['id']

    context = createContext(package, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)

def ask_question(data_args):
    question_text = data_args.get('question-text')
    parameters = data_args.get('parameters')

    body = parse_question(question_text, parameters)
    id, res = create_question(body)
    context = {'ID': id,'text': question_text}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.Questions(val.ID === obj.ID)': context}
    return_outputs(readable_output='New question created. ID: ' + str(id), outputs=outputs, raw_response=res)


def get_question_results(data_args):
    id = data_args.get('question-id')
    res = do_request('GET', 'result_data/question/' + str(id))

    rows = parse_question_results(res)

    if rows is None:
        return return_outputs(readable_output='Question is still executing, Question id: ' + str(id),
                              outputs={}, raw_response=res)

    context = {'QuestionID': id,'Results':rows}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.results(val.QuestionID === question_id)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_sensors(data_args):
    count = int(data_args.get('count'))
    res = do_request('GET', 'sensors/')

    sensors=[]
    for sensor in res.get('data')[:-1][:count]:
        sensor['ID'] = sensor['id']
        del sensor['id']
        sensors.append(sensor)

    context = createContext(sensors, removeNull=True)
    outputs = {'Tanium.Sensor(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Sensors list:', sensors)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_sensor(data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('id and name arguments are missing')
    if id:
        endpoint_url = 'sensors/' + str(id)
    if name:
        endpoint_url = 'sensors/by-name/' + name

    raw_response = do_request('GET', endpoint_url)
    response = raw_response.get('data')
    response['ID'] = response['id']
    del response['id']

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.Sensor(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Sensor information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=response)


def create_saved_question(data_args):
    id = data_args.get('question-id')
    name = data_args.get('name')
    body ={'name':name,'question':{'id':id}}
    raw_response = do_request('POST', 'saved_questions',body)

    response = raw_response.get('data')
    response['ID'] = response['id']
    del response['id']

    context = createContext(response, removeNull=True)
    outputs = {'Tanium.SavedQuestions(val.ID === obj.ID)': context}
    return_outputs(readable_output='Question saved. ID = ' + str(response['ID']), outputs=outputs, raw_response=raw_response)


def get_saved_questions(data_args):
    count = int(data_args.get('count'))
    raw_response = do_request('GET', 'saved_questions')

    questions=[]
    for question in raw_response.get('data')[:-1][:count]:
        question['ID'] = question['id']
        del question['id']
        questions.append(question)

    context = createContext(questions, removeNull=True)
    outputs = {'Tanium.SavedQuestions(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Saved questions:', questions)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=raw_response)


def get_saved_question_results(data_args):
    id = data_args.get('question-id')

    res = do_request('GET', 'result_data/saved_question/' + str(id))

    rows = parse_question_results(res)
    if rows is None:
        return return_outputs(readable_output='Question is still executing, Question id: ' + str(id),
                              outputs={}, raw_response=res)

    context = {'SavedQuestionID': id, 'Results':rows}
    context = createContext(context, removeNull=True)
    outputs = {'Tanium.SavedQuestionsResults(val.SavedQuestionID === id)': context}
    human_readable = tableToMarkdown('question results:', rows)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=res)


def get_system_status():
    raw_response = do_request('GET', 'system_status')
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
    LOG('Command being called is %s' % (demisto.command()))

    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration test button.
            test_module()
            demisto.results('ok')
        elif demisto.command() == 'tn-get-package':
            get_package(demisto.args())
        elif demisto.command() == 'tn-ask-question':
            ask_question(demisto.args())
        elif demisto.command() == 'tn-get-question-result':
            get_question_results(demisto.args())
        elif demisto.command() == 'tn-list-sensors':
            get_sensors(demisto.args())
        elif demisto.command() == 'tn-get-sensor':
            get_sensor(demisto.args())
        elif demisto.command() == 'tn-create-saved-question':
            create_saved_question(demisto.args())
        elif demisto.command() == 'tn-list-saved-questions':
            get_saved_questions(demisto.args())
        elif demisto.command() == 'tn-get-saved-question-result':
            get_saved_question_results(demisto.args())
        elif demisto.command() == 'tn-get-system-status':
            get_system_status()
        elif demisto.command() == 'tn-create-package':
            create_package(demisto.args())
        elif demisto.command() == 'tn-list-packages':
            get_packages(demisto.args())

    # Log exceptions
    except Exception, e:
        LOG(e.message)
        LOG.print_log()
        return_error('error has occurred: {}'.format(str(e)))
    finally:
        LOG.print_log()

# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
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