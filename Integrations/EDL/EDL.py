import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import signal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # No error!

''' CLASSES '''


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text')
        self.end_headers()

        body = get_values_list_str()

        self.wfile.write(bytes(body, "utf8"))
        return


''' CONSTANTS '''
INTEGRATION_NAME = 'EDL'

''' HELPER FUNCTIONS '''


def get_values_list_str():
    ctx = demisto.getIntegrationContext()
    values = ""
    if ctx:
        values = '\n'.join(map(str, ctx.values()))
    return values


''' COMMAND FUNCTIONS '''


def test_module(args):
    """
    Validates that the port is integer
    """
    port = demisto.getParam('longRunningPort')
    try:
        int(port)
    except (ValueError, TypeError):
        return_error(f'EDL port must be an integer. {port} is not valid.')
    return 'ok', {}, {}


def run_long_running(port):
    """
    Starts the long running thread.
    """
    try:
        httpd = ThreadingHTTPServer(('0.0.0.0', port), RequestHandler)
        signal.signal(signal.SIGTERM, httpd.shutdown)
        signal.signal(signal.SIGINT, httpd.shutdown)
        httpd.serve_forever()
    except Exception:
        httpd.shutdown()
        raise
    return '', {}, {}


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
    hr = f'{values[0] + " was" if len(values) == 1 else ",".join(map(str, values)) + " were"} successfully ' \
         f'removed from the EDL.'
    return hr, {}, {}


def list_edl_values(args):
    """
    Lists all values in the edl
    """
    values = list(demisto.getIntegrationContext().values())
    hr = tableToMarkdown('EDL Values', values, headers='Value')
    return hr, {'EDL(val.Value === obj.Value).Value': values}, values


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
        'list-edl-values': list_edl_values
    }

    try:
        if command == 'long-running-execution':
            run_long_running(int(params.get('longRunningPort')))
        else:
            readable_output, outputs, raw_response = commands[command](demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
