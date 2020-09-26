from CommonServerPython import *

''' IMPORTS '''

from tempfile import NamedTemporaryFile
from ssl import SSLContext, SSLError, PROTOCOL_TLSv1_2
from gevent.pywsgi import WSGIServer
from flask import Flask, Response, request
from multiprocessing import Process
from typing import Any, Dict, cast


''' Classes '''


class Handler:
    @staticmethod
    def write(msg):
        demisto.info(msg)


''' CONSTANTS '''


INTEGRATION_NAME = 'GitHub XSOAR App'
APP: Flask = Flask('Github-LRI')
XSOAR_LOGGER: Handler = Handler()


''' HELPER FUNCTIONS '''


def try_parse_integer(int_to_parse, err_msg):
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def get_params_port(params):
    port_mapping: str = params.get('longRunningPort', '')
    err_msg: str
    port: int
    if port_mapping:
        err_msg = f'Listen Port must be an integer. {port_mapping} is not valid.'
        if ':' in port_mapping:
            port = try_parse_integer(port_mapping.split(':')[1], err_msg)
        else:
            port = try_parse_integer(port_mapping, err_msg)
    else:
        raise ValueError('Please provide a Listen Port.')
    return port


def validate_authentication(headers, app_secret, app_id=None):
    request_app_id = headers.get('X-App-ID', '')
    request_app_secret = headers.get('X-App-Secret', '')

    if not request_app_secret:
        return False
    elif app_id is None and app_secret not in request_app_secret:
        return False
    elif app_secret in request_app_secret and app_id in request_app_id:
        return True
    return False


def create_incident(raw):

    if raw.get('commits'):
        customfields = {
            "CommitDelivery": raw
        }
        incident = demisto.createIncidents([
            {
                "name": f"New Git Commit with ID: {raw.get('after')} ",
                "type": "New Git Commit",
                "customFields": customfields
            }
        ])

    elif raw.get('before') == "0000000000000000000000000000000000000000":
        customfields = {
            "BranchDelivery": raw
        }
        incident = demisto.createIncidents([
            {
                "name": "New Git Branch ",
                "type": "New Git Branch",
                "customFields": customfields
            }
        ])

    elif raw.get('pull_request') and raw.get('action') == "opened":
        customfields = {
            "PRDelivery": raw
        }
        incident = demisto.createIncidents([
            {
                "name": f"New Git PR: {raw.get('number')} ",
                "type": "New Git PR",
                "customFields": customfields
            }
        ])

    elif raw.get('pull_request') and raw.get('action') == "closed":
        customfields = {
            "PRDelivery": raw
        }
        incident = demisto.createIncidents([
            {
                "name": f"Closed Git PR: {raw.get('number')}",
                "type": "Closed Git PR",
                "customFields": customfields
            }
        ])

    elif raw.get('issue') and raw.get('action') == "opened":
        customfields = {
            "IssueDelivery": raw
        }
        incident = demisto.createIncidents([
            {
                "name": f"New Git Issue: {raw.get('issue')['number']}",
                "type": "New Git Issue",
                "customFields": customfields
            }
        ])

    elif raw.get('check_run') and raw.get('action') == "completed":
        customfields = {
            "TaskDelivery": raw
        }
        incident = demisto.createIncidents([
            {
                "name": f"Git App Task: {raw.get('check_run')['app']['name']} ",
                "type": "Git App Task",
                "customFields": customfields
            }
        ])

    else:
        customfields = {
            "GitDelivery": raw
        }

        incident = demisto.createIncidents([
            {
                "name": "New Git Delivery",
                "type": "New Git Delivery",
                "customFields": customfields
            }
        ])
    return incident


def set_context(context):
    context = demisto.setIntegrationContext(context)
    return context


''' ROUTE FUNCTIONS '''


@APP.route('/', methods=['GET'])
def void():
    params = demisto.params()

    app_id = params.get('app_id')
    app_secret = params.get('app_secret')

    if app_secret:
        headers = cast(Dict[Any, Any], request.headers)
        if not validate_authentication(headers, app_secret=app_secret, app_id=app_id):
            err_msg = 'Authentication failed. Make sure you are using the right credentials.'
            demisto.error(err_msg)
            return Response(err_msg, status=401)

    response = {
        "message": "Please use the right API Endpoint"
    }
    return Response(json.dumps(response), status=404, mimetype='application/json')


@APP.route('/github/webhook', methods=['POST'])
def route_incidents():
    """
    Main handler for creating new incidents
    """
    params = demisto.params()

    app_id = params.get('app_id')
    app_secret = params.get('app_secret')

    if app_secret:
        headers = cast(Dict[Any, Any], request.headers)
        if not validate_authentication(headers, app_secret=app_secret, app_id=app_id):
            err_msg = 'Authentication failed. Make sure you are using the right credentials.'
            demisto.error(err_msg)
            return Response(err_msg, status=401)

    response = {
        "message": create_incident(raw=request.json)
    }

    return Response(json.dumps(response), status=200, mimetype='application/json')


@APP.route('/github/context', methods=['GET'])
def route_get_context():
    """
    Main handler for values saved in the integration context
    """
    params = demisto.params()

    app_id = params.get('app_id')
    app_secret = params.get('app_secret')

    if app_secret:
        headers = cast(Dict[Any, Any], request.headers)
        if not validate_authentication(headers, app_secret=app_secret, app_id=app_id):
            err_msg = 'Authentication failed. Make sure you are using the right credentials.'
            demisto.error(err_msg)
            return Response(err_msg, status=401)

    response = json.dumps(demisto.getIntegrationContext())

    return Response(response, status=200, mimetype='application/json')


@APP.route('/github/context', methods=['POST'])
def route_set_context():
    """
    Main handler for values saved in the integration context
    """
    params = demisto.params()

    app_id = params.get('app_id')
    app_secret = params.get('app_secret')

    if app_secret:
        headers = cast(Dict[Any, Any], request.headers)
        if not validate_authentication(headers, app_secret=app_secret, app_id=app_id):
            err_msg = 'Authentication failed. Make sure you are using the right credentials.'
            demisto.error(err_msg)
            return Response(err_msg, status=401)

    try:
        response = {
                "message": set_context(context=request.json)
        }
    except:
        response = {
            "message": "Invalid Context, the context has to be a JSON Dictionary"
        }

    return Response(json.dumps(response), status=200, mimetype='application/json')


'''' Commands '''


def test_module(_, params):
    get_params_port(params)
    run_long_running(params, is_test=True)
    return "ok"


def run_long_running(params, is_test=False):
    certificate: str = params.get('certificate', '')
    private_key: str = params.get('private_key', '')

    certificate_path = str()
    private_key_path = str()

    try:
        port = get_params_port(params)
        ssl_args = dict()

        if (certificate and not private_key) or (private_key and not certificate):
            raise DemistoException('If using HTTPS connection, both certificate and private key should be provided.')

        if certificate and private_key:
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(certificate, 'utf-8'))
            certificate_file.close()

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(private_key, 'utf-8'))
            private_key_file.close()

            context = SSLContext(PROTOCOL_TLSv1_2)
            context.load_cert_chain(certificate_path, private_key_path)
            ssl_args['ssl_context'] = context
            demisto.debug('Starting HTTPS Server')
        else:
            demisto.debug('Starting HTTP Server')

        server = WSGIServer(('0.0.0.0', port), APP, **ssl_args, log=XSOAR_LOGGER)
        if is_test:
            server_process = Process(target=server.serve_forever)
            server_process.start()
            time.sleep(5)
            server_process.terminate()
        else:
            server.serve_forever()
    except SSLError as e:
        ssl_err_message = f'Failed to validate certificate and/or private key: {str(e)}'
        demisto.error(ssl_err_message)
        raise ValueError(ssl_err_message)
    except Exception as e:
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))
    finally:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)


def github_set_context(args):
    demisto.setIntegrationContext(json.loads(args['context']))
    return demisto.getIntegrationContext()


def github_get_context():

    raw = demisto.getIntegrationContext()

    result = CommandResults(
        outputs=raw,
        outputs_prefix="GithubApp.Context",
        outputs_key_field="NA",
        readable_output=tableToMarkdown("Content Output", raw)
    )
    return result


def github_import_delivery(args):
    incident = demisto.createIncidents([
        json.loads(args['delivery'])
    ])
    result = CommandResults(
        outputs={
            "ID": incident[0].get('id')
        },
        outputs_prefix="GitHub.Deliveries",
        readable_output=tableToMarkdown("Deliver ID", incident[0].get('id'), headers="ID"),
        outputs_key_field="NA"
    )
    return result


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()

    credentials = params.get('credentials') if params.get('credentials') else {}
    username: str = credentials.get('identifier', '')
    password: str = credentials.get('password', '')
    if (username and not password) or (password and not username):
        err_msg: str = 'If using credentials, both username and password should be provided.'
        demisto.debug(err_msg)
        raise DemistoException(err_msg)

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        if demisto.command() == 'long-running-execution':
            run_long_running(params)
        elif demisto.command() == 'github-set-context':
            result = github_set_context(demisto.args())
            return_results(result)
        elif demisto.command() == 'github-get-context':
            result = github_get_context()
            return_results(result)
        elif demisto.command() == 'github-import-delivery':
            result = github_import_delivery(demisto.args())
            return_results(result)
        elif demisto.command() == 'test-module':
            result = test_module(demisto.args(), params)
            return_results(result)

    except Exception as e:
        return_error(str(f'Failed to execute {demisto.command()} command. Error: {str(e)}'))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
