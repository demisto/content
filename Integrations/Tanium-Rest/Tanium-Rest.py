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
# if not demisto.params().get('proxy'):
#     del os.environ['HTTP_PROXY']
#     del os.environ['HTTPS_PROXY']
#     del os.environ['http_proxy']
#     del os.environ['https_proxy']


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
            return_error('')
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
    # Handle error responses gracefully
    if res.status_code not in {200,403}:
        return_error('Error in API call to Example Integration [%d] - %s' % (res.status_code, res.reason))

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




''' COMMANDS + REQUESTS FUNCTIONS '''


def test_module():
    do_request('GET', 'groups')


def get_package(data_args):
    id = data_args.get('id')
    name = data_args.get('name')
    endpoint_url = ''
    if not id and not name:
        return_error('')
    if name and not id:
        endpoint_url = 'packages/by-name/' + name
    if id and not name:
        endpoint_url = 'packages/' + str(id)

    response = do_request('GET', endpoint_url).get('data')
    context = createContext(response, removeNull=True)
    outputs = {'Tanium.Package(val.ID === obj.ID)': context}
    human_readable = tableToMarkdown('Package information', context)
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=response)


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

    # Log exceptions
    except Exception, e:
        LOG(e.message)
        LOG.print_log()
        return_error('error has occurred: {}'.format(str(e)))

# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()


#get_package({'id':132})
#get_package({'name':'Detect Intel for Unix Revision 4 Delta'})

