import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
OK_HTTP_CODES = (200, 201)


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

        _action = kwargs.get('action')

        _data = None
        _uri = ''
        _method = 'POST'

        if Action.TEST_CONN == _action:
            _uri = Uri.TEST_CONN

        elif Action.DECEPTION_FILE == _action:
            _uri = Uri.DECEPTION_FILE
            _data = {
                'file': kwargs.get('filename'),
                'host': kwargs.get('endpoint')
            }

        elif Action.DECEPTION_HOST == _action:
            _uri = Uri.DECEPTION_HOST
            _data = {
                'host': kwargs.get('host')
            }

        elif Action.DECEPTION_USER == _action:
            _uri = Uri.DECEPTION_USER
            _data = {
                'user': kwargs.get('username'),
                'domain': kwargs.get('domain'),
            }

        elif Action.MUTE_DECEPTION_HOST == _action:
            _uri = Uri.MUTE_DECEPTION_HOST
            _data = {
                'host': kwargs.get('host')
            }

        elif Action.UNMUTE_DECEPTION_HOST == _action:
            _uri = Uri.UNMUTE_DECEPTION_HOST
            _data = {
                'host': kwargs.get('host')
            }

        elif Action.MUTE_DECEPTION_EP == _action:
            _uri = Uri.MUTE_DECEPTION_EP
            _data = {
                'host': kwargs.get('ep')
            }

        elif Action.UNMUTE_DECEPTION_EP == _action:
            _uri = Uri.UNMUTE_DECEPTION_EP
            _data = {
                'host': kwargs.get('ep')
            }

        res = self._http_request(
            method=_method,
            url_suffix=_uri,
            json_data=_data,
            resp_type='response',
            error_handler=get_api_error,
            ok_codes=OK_HTTP_CODES
        )

        if Action.TEST_CONN != _action:
            demisto.info(f'Response from Acalvio API Server: '
                         f'HTTP Status Code - {res.status_code}, '
                         f'HTTP Reason - {res.reason}, HTTP Body - {res.text}')

        return res.json()
    # end of function - call_acal_api

# end of class - Client


def get_api_error(res):

    message = 'API - HTTP Response Error'
    error = ''
    outputs = None

    if res is not None:
        message = 'HTTP Status Code - {}, HTTP Reason - {}, Message Body - {}' \
            .format(res.status_code, res.reason, res.text)
        outputs = {'error': True, 'details': res.text}

    return_error(message=message, error=error, outputs=outputs)
# end of function - get_api_error


def do_test_connection(client):

    results = None

    res_json = client.call_acal_api(action=Action.TEST_CONN)

    if res_json is not None \
            and 'result' in res_json \
            and type(res_json['result']) is bool\
            and res_json['result']:

        results = 'ok'  # Test Success

    else:
        return_error(message='Error in TestConnection')

    return results
# end of function - do_test_connection


def do_deception_host_command(client, args):

    results = None

    host = args.get('host')

    res_json = client.call_acal_api(action=Action.DECEPTION_HOST,
                                    host=host)

    if res_json is not None \
            and 'result' in res_json \
            and type(res_json['result']) is bool:

        out_result = {
            'IsDeception': res_json['result'],
            'Host': str(host)
        }

        results = CommandResults(
            outputs_prefix='Acalvio.IsDeceptionHost',
            outputs_key_field=['host'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Deception Host', out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in IsDeceptionHost')

    return results
# end of function - do_deception_host_command


def do_deception_file_command(client, args):

    results = None

    filename = args.get('filename')
    endpoint = args.get('endpoint')

    res_json = client.call_acal_api(action=Action.DECEPTION_FILE,
                                    filename=filename,
                                    endpoint=endpoint)

    if res_json is not None \
            and 'result' in res_json \
            and type(res_json['result']) is bool:

        out_result = {
            'IsDeception': res_json['result'],
            'Filename': str(filename),
            'Endpoint': str(endpoint)
        }

        results = CommandResults(
            outputs_prefix='Acalvio.IsDeceptionFile',
            outputs_key_field=['filename', 'endpoint'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Deception File', out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in IsDeceptionFile')

    return results
# end of function - do_deception_file_command


def do_deception_user_command(client, args):

    results = None

    username = args.get('username')
    domain = args.get('domain')

    res_json = client.call_acal_api(action=Action.DECEPTION_USER,
                                    username=username,
                                    domain=domain)

    if res_json is not None \
            and 'result' in res_json \
            and type(res_json['result']) is bool:

        out_result = {
            'IsDeception': res_json['result'],
            'Username': str(username),
            'Domain': str(domain) if domain is not None else None
        }

        results = CommandResults(
            outputs_prefix='Acalvio.IsDeceptionUser',
            outputs_key_field=['username', 'domain'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Deception User', out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in IsDeceptionUser')

    return results
# end of function - do_deception_user_command


def do_mute_deception_host_command(client, args):

    results = None

    host = args.get('host')

    res_json = client.call_acal_api(action=Action.MUTE_DECEPTION_HOST,
                                    host=host)

    if res_json is not None \
            and 'rescode' in res_json:

        out_result = {
            'IsMute': True if 0 == res_json['rescode'] else False,
            'Host': str(host)
        }

        results = CommandResults(
            outputs_prefix='Acalvio.MuteDeceptionHost',
            outputs_key_field=['host'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Mute Deception Host', out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in MuteDeceptionHost')

    return results
# end of function - do_mute_deception_host_command


def do_unmute_deception_host_command(client, args):

    results = None

    host = args.get('host')

    res_json = client.call_acal_api(action=Action.UNMUTE_DECEPTION_HOST,
                                    host=host)

    if res_json is not None \
            and 'rescode' in res_json:

        out_result = {
            'IsUnmute': True if 0 == res_json['rescode'] else False,
            'Host': str(host)
        }

        results = CommandResults(
            outputs_prefix='Acalvio.UnmuteDeceptionHost',
            outputs_key_field=['host'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Unmute Deception Host', out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in UnmuteDeceptionHost')

    return results
# end of function - do_unmute_deception_host_command


def do_mute_deception_ep_command(client, args):

    results = None

    ep = args.get('endpoint')

    res_json = client.call_acal_api(action=Action.MUTE_DECEPTION_EP,
                                    ep=ep)

    if res_json is not None \
            and 'rescode' in res_json:

        out_result = {
            'IsMute': True if 0 == res_json['rescode'] else False,
            'Endpoint': str(ep)
        }

        results = CommandResults(
            outputs_prefix='Acalvio.MuteDeceptionEndpoint',
            outputs_key_field=['endpoint'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Mute Deception on Endpoint',
             out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in MuteDeceptionEndpoint')

    return results
# end of function - do_mute_deception_ep_command


def do_unmute_deception_ep_command(client, args):

    results = None

    ep = args.get('endpoint')

    res_json = client.call_acal_api(action=Action.UNMUTE_DECEPTION_EP,
                                    ep=ep)

    if res_json is not None \
            and 'rescode' in res_json:

        out_result = {
            'IsUnmute': True if 0 == res_json['rescode'] else False,
            'Endpoint': str(ep)
        }

        results = CommandResults(
            outputs_prefix='Acalvio.UnmuteDeceptionEndpoint',
            outputs_key_field=['endpoint'],
            outputs=out_result,
            readable_output=tableToMarkdown
            ('Acalvio ShadowPlex - Unmute Deception on Endpoint',
             out_result),
            raw_response=res_json
        )
    else:
        return_error(message='Error in UnmuteDeceptionEndpoint')

    return results
# end of function - do_unmute_deception_ep_command


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    params = demisto.params()

    # get Acalvio API Server url
    base_url = params['url'].rstrip('/')

    # get Acalvio API Key
    apikey = params['apikey']

    # check if SSL is to be verified
    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)

    # set the headers
    headers = {
        'api_key': apikey,
        'content-type': 'application/json'
    }

    demisto.info(f'Command being called is \'{demisto.command()}\'')
    result = None

    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button
            result = do_test_connection(client)

        elif demisto.command() == 'acalvio-is-deception-host':
            result = \
                do_deception_host_command(client, demisto.args())

        elif demisto.command() == 'acalvio-is-deception-file':
            result = \
                do_deception_file_command(client, demisto.args())

        elif demisto.command() == 'acalvio-is-deception-user':
            result = \
                do_deception_user_command(client, demisto.args())

        elif demisto.command() == 'acalvio-mute-deception-host':
            result = \
                do_mute_deception_host_command(client, demisto.args())

        elif demisto.command() == 'acalvio-unmute-deception-host':
            result = \
                do_unmute_deception_host_command(client, demisto.args())

        elif demisto.command() == 'acalvio-mute-deception-on-endpoint':
            result = \
                do_mute_deception_ep_command(client, demisto.args())

        elif demisto.command() == 'acalvio-unmute-deception-on-endpoint':
            result = \
                do_unmute_deception_ep_command(client, demisto.args())

        return_results(result)

    # Log exceptions
    except DemistoException as de:
        return_error(message=f'Failed to execute \'{demisto.command()}\' command. Error: {str(de)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
