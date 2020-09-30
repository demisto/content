import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

urllib3.disable_warnings()

PROXY = demisto.params().get('proxy')
SECURE = demisto.params().get('secure')
BASE_URL = demisto.params().get('url')
API_KEY = demisto.params().get('apikey')
URL_SUFFIX = 'api'
if not demisto.params().get('proxy', False):
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

'''HELPER FUNCTIONS'''


def http_request(method, params):
    r = requests.Response
    if method is 'GET':
        r = requests.get(BASE_URL + "/" + URL_SUFFIX, params=params, verify=SECURE)
    elif method is 'POST':
        if not API_KEY:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        else:
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-FunTranslations-Api-Secret': API_KEY
            }

        r = requests.post(BASE_URL + "/" + URL_SUFFIX, params=params, headers=headers, verify=SECURE)

    if r.status_code is not 200:
        return_error('Error in API call [%d] - %s' % (r.status_code, r.reason))
    json_result = json.loads(xml2json(str(r.text)))

    # handle non success
    if json_result['response']['@status'] != 'success':
        if 'msg' in json_result['response'] and 'line' in json_result['response']['msg']:
            # catch non existing object error and display a meaningful message
            if json_result['response']['msg']['line'] == 'No such node':
                raise Exception(
                    'Object was not found, verify that the name is correct and that the instance was committed.')

            #  catch urlfiltering error and display a meaningful message
            elif str(json_result['response']['msg']['line']).find('test -> url') != -1:
                raise Exception('The URL filtering license is either expired or not active.'
                                ' Please contact your PAN-OS representative.')

            # catch non valid jobID errors and display a meaningful message
            elif isinstance(json_result['response']['msg']['line'], str) and \
                    json_result['response']['msg']['line'].find('job') != -1 and \
                    (json_result['response']['msg']['line'].find('not found') != -1
                     or json_result['response']['msg']['line'].find('No such query job')) != -1:
                raise Exception('Invalid Job ID error: ' + json_result['response']['msg']['line'])

            # catch already at the top/bottom error for rules and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already at the') != -1:
                demisto.results('Rule ' + str(json_result['response']['msg']['line']))
                sys.exit(0)

            # catch already registered ip tags and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('already exists, ignore') != -1:
                if isinstance(json_result['response']['msg']['line']['uid-response']['payload']['register']['entry'],
                              list):
                    ips = [o['@ip'] for o in
                           json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']]
                else:
                    ips = json_result['response']['msg']['line']['uid-response']['payload']['register']['entry']['@ip']
                demisto.results(
                    'IP ' + str(ips) + ' already exist in the tag. All submitted IPs were not registered to the tag.')
                sys.exit(0)

            # catch timed out log queries and return this as an entry.note
            elif str(json_result['response']['msg']['line']).find('Query timed out') != -1:
                demisto.results(str(json_result['response']['msg']['line']) + '. Rerun the query.')
                sys.exit(0)

        if '@code' in json_result['response']:
            raise Exception(
                'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                    json_result['response']['msg']['line']))
        else:
            raise Exception('Request Failed.\n' + str(json_result['response']))

    # handle @code
    if 'response' in json_result and '@code' in json_result['response']:
        if json_result['response']['@code'] not in ['19', '20']:
            # error code non exist in dict and not of success
            if 'msg' in json_result['response']:
                raise Exception(
                    'Request Failed.\nStatus code: ' + str(json_result['response']['@code']) + '\nWith message: ' + str(
                        json_result['response']['msg']))
            else:
                raise Exception('Request Failed.\n' + str(json_result['response']))

    return json_result['response']['result']


""" MAIN FUNCTIONS """


def panos_get_api_key():
    params = {
        'type': 'keygen',
        'user': demisto.params().get('credentials').get('identifier'),
        'password': demisto.params().get('credentials').get('password')
    }
    r = http_request('GET', params)
    return r


def panos_get_current_users():
    params = {
        'type': 'op',
        'cmd': '<show><global-protect-gateway><current-user/></global-protect-gateway></show>',
        'key': demisto.params().get('apiKey')
    }
    r = http_request('GET', params)

    return r


def panos_get_gateways():
    params = {
        'type': 'op',
        'cmd': '<show><global-protect-gateway><gateway/></global-protect-gateway></show>',
        'key': demisto.params().get('apiKey')
    }
    r = http_request('GET', params)

    return r


def panos_disconnect_current_user():
    args = demisto.args()
    command_string = '<request><global-protect-gateway><client-logout><gateway>' + args.get('gateway') + "-N"
    command_string = command_string + '</gateway><user>' + args.get('user')
    command_string = command_string + '</user><reason>' + args.get('reason')
    command_string = command_string + '</reason><computer>' + args.get('computer')
    command_string = command_string + '</computer></client-logout></global-protect-gateway></request>'
    params = {
        'type': 'op',
        'cmd': command_string,
        'key': demisto.params().get('apiKey')
    }
    r = http_request('GET', params)

    return r


def panos_test():
    """
    test module
    """

    params = {
        'type': 'op',
        'cmd': '<show><system><info></info></system></show>',
        'key': demisto.params().get('apiKey')
    }

    http_request('GET', params)

    demisto.results('ok')


''' EXECUTION '''


def main():
    LOG('command is %s' % (demisto.command(),))
    try:
        if demisto.command() == 'panos-get-api-key':
            demisto.results(panos_get_api_key())
        if demisto.command() == 'panos-get-current-users':
            response_from_api = panos_get_current_users()
            raw_response = response_from_api
            command_results = CommandResults(
                outputs_prefix='GlobalProtect.CurrentUsers',
                outputs_key_field='public-ip',
                outputs=response_from_api,
                readable_output=raw_response,
                raw_response=raw_response
            )
            return_results(command_results)
        if demisto.command() == 'panos-get-gateways':
            response_from_api = panos_get_gateways()
            raw_response = response_from_api
            command_results = CommandResults(
                outputs_prefix='GlobalProtect.Gateways',
                outputs_key_field='gateway-name',
                outputs=response_from_api,
                readable_output=raw_response,
                raw_response=raw_response
            )
            return_results(command_results)
        if demisto.command() == 'panos-disconnect-current-user':
            response_from_api = panos_disconnect_current_user()
            raw_response = response_from_api
            command_results = CommandResults(
                outputs_prefix='GlobalProtect.Disconnected',
                outputs_key_field='user',
                outputs=response_from_api,
                readable_output=raw_response,
                raw_response=raw_response
            )
            return_results(command_results)
        elif demisto.command() == 'test-module':
            panos_test()
    except Exception as e:
        logging.exception(e)


if __name__ == 'builtins':
    main()
