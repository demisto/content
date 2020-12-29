''' IMPORTS '''
import requests
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
OK_HTTP_CODES = (200, 401, 422, 500)


class Action():

    TEST_CONN = 'ACTION_TEST_CONN'
    DECEPTION_FILE = 'ACTION_DECEPTION_FILE'
    DECEPTION_HOST = 'ACTION_DECEPTION_HOST'
    DECEPTION_USER = 'ACTION_DECEPTION_USER'
    MUTE_DECEPTION_HOST = 'ACTION_MUTE_DECEPTION_HOST'
    UNMUTE_DECEPTION_HOST = 'ACTION_UNMUTE_DECEPTION_HOST'
    MUTE_DECEPTION_EP = 'ACTION_MUTE_DECEPTION_EP'
    UNMUTE_DECEPTION_EP = 'ACTION_UNMUTE_DECEPTION_EP'

# end of class - Action


class Uri():

    TEST_CONN = '/insights/test-connection'
    DECEPTION_FILE = '/insights/file'
    DECEPTION_HOST = '/insights/host'
    DECEPTION_USER = '/insights/user'
    MUTE_DECEPTION_HOST = '/insights/mute-decoy'
    UNMUTE_DECEPTION_HOST = '/insights/unmute-decoy'
    MUTE_DECEPTION_EP = '/insights/mute-host'
    UNMUTE_DECEPTION_EP = '/insights/unmute-host'

# end of class - Uri


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain
    any Demisto logic.
    Should only do requests and return data.
    """

    def call_acal_api(self, **kwargs):
        """
        http request to Acalvio API server
        """

        _action = kwargs['action'] if 'action' in kwargs else None

        _data = None
        _uri = ''
        _method = 'POST'

        if Action.TEST_CONN == _action:
            _uri = Uri.TEST_CONN

        elif Action.DECEPTION_FILE == _action:
            _uri = Uri.DECEPTION_FILE
            _data = {
                'file': kwargs['filename'] if 'filename' in kwargs
                else None,
                'host': kwargs['endpoint'] if 'endpoint' in kwargs
                else None
            }

        elif Action.DECEPTION_HOST == _action:
            _uri = Uri.DECEPTION_HOST
            _data = {
                'host': kwargs['host'] if 'host' in kwargs else None
            }

        elif Action.DECEPTION_USER == _action:
            _uri = Uri.DECEPTION_USER
            _data = {
                'user': kwargs['username'] if 'username' in kwargs
                else None,
                'domain': kwargs['domain'] if 'domain' in kwargs
                else None,
            }

        elif Action.MUTE_DECEPTION_HOST == _action:
            _uri = Uri.MUTE_DECEPTION_HOST
            _data = {
                'host': kwargs['host'] if 'host' in kwargs else None
            }

        elif Action.UNMUTE_DECEPTION_HOST == _action:
            _uri = Uri.UNMUTE_DECEPTION_HOST
            _data = {
                'host': kwargs['host'] if 'host' in kwargs else None
            }

        elif Action.MUTE_DECEPTION_EP == _action:
            _uri = Uri.MUTE_DECEPTION_EP
            _data = {
                'host': kwargs['ep'] if 'ep' in kwargs else None
            }

        elif Action.UNMUTE_DECEPTION_EP == _action:
            _uri = Uri.UNMUTE_DECEPTION_EP
            _data = {
                'host': kwargs['ep'] if 'ep' in kwargs else None
            }

        res = self._http_request(
            method=_method,
            url_suffix=_uri,
            json_data=_data,
            resp_type='response',
            ok_codes=OK_HTTP_CODES
        )

        if Action.TEST_CONN != _action:
            demisto.log(f'Response from Acalvio API Server: '
                        f'HTTP Status Code - {res.status_code}, '
                        f'HTTP Reason - {res.reason}, HTTP Body - {res.text}')

        return res
    # end of function - call_acal_api

# end of class - Client


class AcalError(object):

    def __init__(self, message='Unknown Error', error='', outputs=None):
        self.message = message  # str
        self.error = error  # str
        self.outputs = outputs if outputs is not None \
            else {'error': True, 'details': None}  # dict

# end of class - AcalError


def get_acal_error(res):

    error = None

    if res is not None:
        error = AcalError(
            message='HTTP Status Code - {}, HTTP Reason - {}, '
                    'Message Body - {}'
            .format(res.status_code, res.reason, res.text),
            error='',
            outputs={'error': True, 'details': res.text}
        )

    return error
# end of function - get_acal_error


def do_test_connection(client):

    results = None
    error = None

    try:
        res = client.call_acal_api(action=Action.TEST_CONN)

        if 200 == res.status_code \
                and 'result' in res.json() \
                and type(res.json()['result']) is bool\
                and res.json()['result']:

            results = 'ok'  # Test Success

        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_test_connection


def do_deception_host_command(client, args):

    results = None
    error = None

    try:
        host = args.get('host')

        res = client.call_acal_api(action=Action.DECEPTION_HOST,
                                   host=host)

        if 200 == res.status_code \
                and 'result' in res.json() \
                and type(res.json()['result']) is bool:

            out_result = {
                'is_deception': res.json()['result'],
                'host': str(host)
            }

            results = CommandResults(
                outputs_prefix='Acalvio.IsDeceptionHost',
                outputs_key_field=['is_deception', 'host'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Deception Host', out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_deception_host_command


def do_deception_file_command(client, args):

    results = None
    error = None

    try:
        filename = args.get('filename')
        endpoint = args.get('endpoint')

        res = client.call_acal_api(action=Action.DECEPTION_FILE,
                                   filename=filename,
                                   endpoint=endpoint)

        if 200 == res.status_code \
                and 'result' in res.json() \
                and type(res.json()['result']) is bool:

            out_result = {
                'is_deception': res.json()['result'],
                'filename': str(filename),
                'endpoint': str(endpoint)
            }

            results = CommandResults(
                outputs_prefix='Acalvio.IsDeceptionFile',
                outputs_key_field=['is_deception', 'filename', 'endpoint'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Deception File', out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_deception_file_command


def do_deception_user_command(client, args):

    results = None
    error = None

    try:
        username = args.get('username')
        domain = args.get('domain')

        res = client.call_acal_api(action=Action.DECEPTION_USER,
                                   username=username,
                                   domain=domain)

        if 200 == res.status_code \
                and 'result' in res.json() \
                and type(res.json()['result']) is bool:

            out_result = {
                'is_deception': res.json()['result'],
                'username': str(username),
                'domain': str(domain) if domain is not None else None
            }

            results = CommandResults(
                outputs_prefix='Acalvio.IsDeceptionUser',
                outputs_key_field=['is_deception', 'username', 'domain'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Deception User', out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_deception_user_command


def do_mute_deception_host_command(client, args):

    results = None
    error = None

    try:
        host = args.get('host')

        res = client.call_acal_api(action=Action.MUTE_DECEPTION_HOST,
                                   host=host)

        if 200 == res.status_code \
                and 'rescode' in res.json():

            out_result = {
                'is_mute': True if 0 == res.json()['rescode'] else False,
                'host': str(host)
            }

            results = CommandResults(
                outputs_prefix='Acalvio.MuteDeceptionHost',
                outputs_key_field=['host', 'is_mute'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Mute Deception Host', out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_mute_deception_host_command


def do_unmute_deception_host_command(client, args):

    results = None
    error = None

    try:
        host = args.get('host')

        res = client.call_acal_api(action=Action.UNMUTE_DECEPTION_HOST,
                                   host=host)

        if 200 == res.status_code \
                and 'rescode' in res.json():

            out_result = {
                'is_unmute': True if 0 == res.json()['rescode'] else False,
                'host': str(host)
            }

            results = CommandResults(
                outputs_prefix='Acalvio.UnmuteDeceptionHost',
                outputs_key_field=['host', 'is_unmute'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Unmute Deception Host', out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_unmute_deception_host_command


def do_mute_deception_ep_command(client, args):

    results = None
    error = None

    try:
        ep = args.get('endpoint')

        res = client.call_acal_api(action=Action.MUTE_DECEPTION_EP,
                                   ep=ep)

        if 200 == res.status_code \
                and 'rescode' in res.json():

            out_result = {
                'is_mute': True if 0 == res.json()['rescode'] else False,
                'endpoint': str(ep)
            }

            results = CommandResults(
                outputs_prefix='Acalvio.MuteDeceptionEndpoint',
                outputs_key_field=['endpoint', 'is_mute'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Mute Deception on Endpoint',
                 out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_mute_deception_ep_command


def do_unmute_deception_ep_command(client, args):

    results = None
    error = None

    try:
        ep = args.get('endpoint')

        res = client.call_acal_api(action=Action.UNMUTE_DECEPTION_EP,
                                   ep=ep)

        if 200 == res.status_code \
                and 'rescode' in res.json():

            out_result = {
                'is_unmute': True if 0 == res.json()['rescode'] else False,
                'endpoint': str(ep)
            }

            results = CommandResults(
                outputs_prefix='Acalvio.UnmuteDeceptionEndpoint',
                outputs_key_field=['endpoint', 'is_unmute'],
                outputs=out_result,
                readable_output=tableToMarkdown
                ('Acalvio ShadowPlex - Unmute Deception on Endpoint',
                 out_result),
                raw_response=res.json()
            )
        else:
            error = get_acal_error(res)

    except DemistoException as de:
        raise Exception(de)

    return (results, error)
# end of function - do_unmute_deception_ep_command


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    # get Acalvio API Server url
    base_url = demisto.params()['url']

    # get Acalvio API Key
    apikey = demisto.params()['apikey']

    # check if SSL is to be verified
    verify_certificate = demisto.params().get('insecure', False)

    proxy = demisto.params().get('proxy', False)

    # set the headers
    headers = {
        'api_key': apikey,
        'content-type': 'application/json'
    }

    demisto.log(f'Command being called is \'{demisto.command()}\'')
    result = None
    acalerror = AcalError()

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button
            result, acalerror = do_test_connection(client)

        elif demisto.command() == 'acalvio-is-deception-host':
            result, acalerror = \
                do_deception_host_command(client, demisto.args())

        elif demisto.command() == 'acalvio-is-deception-file':
            result, acalerror = \
                do_deception_file_command(client, demisto.args())

        elif demisto.command() == 'acalvio-is-deception-user':
            result, acalerror = \
                do_deception_user_command(client, demisto.args())

        elif demisto.command() == 'acalvio-mute-deception-host':
            result, acalerror = \
                do_mute_deception_host_command(client, demisto.args())

        elif demisto.command() == 'acalvio-unmute-deception-host':
            result, acalerror = \
                do_unmute_deception_host_command(client, demisto.args())

        elif demisto.command() == 'acalvio-mute-deception-on-endpoint':
            result, acalerror = \
                do_mute_deception_ep_command(client, demisto.args())

        elif demisto.command() == 'acalvio-unmute-deception-on-endpoint':
            result, acalerror = \
                do_unmute_deception_ep_command(client, demisto.args())

    # Log exceptions
    except Exception as e:
        acalerror = AcalError(message=f'Failed to execute \'{demisto.command()}\' command. Error: {str(e)}')

    finally:
        if result is not None:
            return_results(result)
        else:
            if acalerror is None:
                acalerror = AcalError()
            return_error(message=acalerror.message,
                         error=acalerror.error,
                         outputs=acalerror.outputs)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
