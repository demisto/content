import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''
import urllib3
# disable insecure warnings
urllib3.disable_warnings()

''' GLOBAL VARS '''
SERVER_NAME = demisto.params()['server']
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']

BASE_URL = SERVER_NAME + 'centreon/api/index.php?'
USE_SSL = False if demisto.params().get('insecure') else True
DEFAULT_HEADERS = {
    'Content-Type': 'application/json'
}

''' HELPER FUNCTIONS '''


def httpRequest(method, urlSuffix, data, headers):  # pragma: no cover
    data = {} if data is None else data

    url = BASE_URL + urlSuffix
    LOG('running %s request with url=%s\theaders=%s' % (method, url, headers))

    try:
        res = requests.request(method,
                               url,
                               verify=USE_SSL,
                               params=data,
                               headers=headers
                               )
        res.raise_for_status()
        return res.json()

    except Exception as e:
        LOG(e)
        raise e


def httpPost(urlSuffix, data=None, files=None):  # pragma: no cover
    data = {} if data is None else data
    url = BASE_URL + urlSuffix
    LOG('running request with url=%s\tdata=%s\tfiles=%s' % (url, data, files))
    try:
        res = requests.post(url, data=data, verify=USE_SSL)
        res.raise_for_status()
        return res.json()

    except Exception as e:
        LOG(e)
        raise e


def login():
    # retrieves an authentication token from Centreon
    cmd_url = 'action=authenticate'
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    result = httpPost(cmd_url, data=data)
    return result['authToken']


def transform_host_vals(key, value):
    # "down" and "unreachable" states can be added here after their value would be known
    host_service_status = {
        '0': "Up",
        '4': "Pending"
    }
    if (key == 'State' and value in host_service_status):
        return host_service_status[value]
    return value


def to_upper_camel_case(word):
    return ''.join(x.capitalize() or '_' for x in word.split('_'))


''' COMMANDS FUNCTIONS '''


def get_host_status():
    """ Returns the status of the connected hosts. """

    args = demisto.args()
    token = login()
    DEFAULT_HEADERS['centreon-auth-token'] = token
    cmd_url = 'object=centreon_realtime_hosts&action=list'
    return httpRequest('GET', cmd_url, args, DEFAULT_HEADERS)


def get_host_status_command():
    """ corresponds to 'centreon-get-host-status' command. Brings the status of the connected hosts."""

    response = get_host_status()
    if (len(response) == 0):
        return "No Hosts found"

    # changing the keys from underscore notation to UpperCamelCase notation
    camel_case_response = [dict((to_upper_camel_case(k), v) for k, v in dic.items()) for dic in response]
    # for the human readable - only including keys which has values. Also, transforming values from ints to readable text
    list_for_md = [dict((k, transform_host_vals(k, v)) for k, v in dic.items() if (v == 0 or v))
                   for dic in camel_case_response]

    entry = {
        'Type': entryTypes['note'],
        'Contents': camel_case_response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Centreon Hosts status', list_for_md),
        'EntryContext': {
            'Centreon.Host(val.Id==obj.Id)': camel_case_response
        }
    }

    return entry


def get_service_status():
    """ Returns the status of the connected services. """

    args = demisto.args()
    token = login()
    DEFAULT_HEADERS['centreon-auth-token'] = token
    cmd_url = 'object=centreon_realtime_services&action=list'
    return httpRequest('GET', cmd_url, args, DEFAULT_HEADERS)


def get_service_status_command():
    """ corresponds to 'centreon-get-service-status' command. Brings the status of the connected services. """

    response = get_service_status()
    if (len(response) == 0):
        return "No Services found"

    # changing the keys from underscore notation to UpperCamelCase notation
    camel_case_response = [dict((to_upper_camel_case(k), v) for k, v in dic.items()) for dic in response]
    # for the human readable - only including keys which has values. Also, transforming values from ints to readable text
    list_for_md = [dict((k, transform_host_vals(k, v)) for k, v in dic.items() if (v == 0 or v))
                   for dic in camel_case_response]

    entry = {
        'Type': entryTypes['note'],
        'Contents': camel_case_response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Centreon Services status', list_for_md),
        'EntryContext': {
            'Centreon.Service(val.ServiceId==obj.ServiceId)': camel_case_response
        }
    }

    return entry


''' EXECUTION CODE '''
LOG('command is %s' % (demisto.command(), ))
try:
    handle_proxy()
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        if get_host_status():
            demisto.results('ok')
        else:
            demisto.results('test failed')
    elif demisto.command() == 'centreon-get-host-status':
        demisto.results(get_host_status_command())
    elif demisto.command() == 'centreon-get-service-status':
        demisto.results(get_service_status_command())

except Exception as e:
    LOG(str(e))
    LOG.print_log()
    raise
