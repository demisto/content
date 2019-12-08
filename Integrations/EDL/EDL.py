import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from flask import Flask, Response
from gevent.pywsgi import WSGIServer
from tempfile import NamedTemporaryFile

''' GLOBAL VARIABLES '''
INTEGRATION_NAME: str = 'EDL'
APP: Flask = Flask('demisto-edl')

''' HELPER FUNCTIONS '''


def list_to_str(inp_list: list, delimiter: str = '\n') -> str:
    """
    Transforms a list to an str, with a custom delimiter between each list item
    """
    str_res = ""
    if inp_list:
        str_res = delimiter.join(map(str, inp_list))
    return str_res


def get_params_port(params: dict = demisto.params()) -> int:
    """
    Gets port from the integration parameters
    """
    port_mapping: str = params.get('longRunningPort', '')
    port: int
    try:
        if port_mapping:
            if ':' in port_mapping:
                port = int(port_mapping.split(':')[1])
            else:
                port = int(port_mapping)
    except (ValueError, TypeError):
        return_error(f'EDL port must be an integer. {port_mapping} is not valid.')
    return port


''' COMMAND FUNCTIONS '''


@APP.route('/', methods=['GET'])
def edl_values() -> Response:
    """
    Main handler for values saved in the integration context
    """
    values = list_to_str(list(demisto.getIntegrationContext().values()))
    resp = APP.make_response(values)
    resp.headers['Content-type'] = 'text'
    return Response(values, status=200)


def test_module(args):
    """
    Validates that the port is integer
    """
    params = demisto.params()
    get_params_port(params)
    return 'ok', {}, {}


def run_long_running(params):
    """
    Starts the long running thread.
    """
    certificate: str = params.get('certificate', '')
    private_key: str = params.get('key', '')

    certificate_path = str()
    private_key_path = str()

    try:
        port = get_params_port(params)
        ssl_args = dict()

        if certificate and private_key:
            certificate_file = NamedTemporaryFile(delete=False)
            certificate_path = certificate_file.name
            certificate_file.write(bytes(certificate, 'utf-8'))
            certificate_file.close()
            ssl_args['certfile'] = certificate_path

            private_key_file = NamedTemporaryFile(delete=False)
            private_key_path = private_key_file.name
            private_key_file.write(bytes(private_key, 'utf-8'))
            private_key_file.close()
            ssl_args['keyfile'] = private_key_path

            demisto.info('Starting HTTPS Server')
        else:
            demisto.info('Starting HTTP Server')

        server = WSGIServer(('', port), APP, **ssl_args)
        server.serve_forever()
    except Exception as e:
        if certificate_path:
            os.unlink(certificate_path)
        if private_key_path:
            os.unlink(private_key_path)
        demisto.error(f'An error occurred in long running loop: {str(e)}')
        raise ValueError(str(e))


def add_to_edl(args):
    """
    Adds values to the IntegrationContext (key: value, val: value)
    """
    ctx = demisto.getIntegrationContext()
    values = argToList(args.get('value'))
    for value in values:
        ctx[value] = value
    demisto.setIntegrationContext(ctx)
    hr = f'{values[0] + " was" if len(values) == 1 else ",".join(map(str, values)) + " were"} successfully ' \
         f'added to the EDL.'
    return hr, {}, {}


def del_from_edl(args):
    """
    Deletes a value from the IntegrationContext (key: value)
    """
    ctx = demisto.getIntegrationContext()
    values = argToList(args.get('value'))
    for value in values:
        ctx.pop(value, None)
    demisto.setIntegrationContext(ctx)
    hr = f'{values[0] + " was" if len(values) == 1 else list_to_str(values, ",") + " were"} successfully ' \
         f'removed from the EDL.'
    return hr, {}, {}


def list_edl_values(args):
    """
    Lists all values in the edl
    """
    values = list(demisto.getIntegrationContext().values())
    hr = tableToMarkdown('EDL Values', values, headers='Value')
    return hr, {'EDL(val.Value === obj.Value).Value': values}, values


def replace_edl_values(args):
    """
    Replaces the value in the EDL with the ones provided by the user
    """
    ctx = {}
    values = argToList(args.get('value'))
    for value in values:
        ctx[value] = value
    demisto.setIntegrationContext(ctx)
    hr = f'{values[0] + " was" if len(values) == 1 else list_to_str(values, ",") + " were"} successfully ' \
         f'added to the EDL.'
    return hr, {}, {}


def main():
    """
    Main
    """
    params = demisto.params()
    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))
    commands = {
        'test-module': test_module,
        'add-to-edl': add_to_edl,
        'del-from-edl': del_from_edl,
        'list-edl-values': list_edl_values,
        'replace-edl-values': replace_edl_values
    }

    try:
        if command == 'long-running-execution':
            run_long_running(params)
        else:
            readable_output, outputs, raw_response = commands[command](demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
