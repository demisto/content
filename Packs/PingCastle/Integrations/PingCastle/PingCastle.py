import random
import string
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa


class PingCastleHTTPServer(BaseHTTPRequestHandler):
    token = ''
    report = ''

    def _set_response(self, code, content_type):
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def do_GET(self):
        """
        Handle GET requests. This server does not accept GET requests.
        """
        self._set_response(400, 'text/html')
        self.wfile.write(b"no GET requests")

    def do_POST(self):
        """
        Handle POST requests - Login and SendReport
        """
        try:
            content_length = int(self.headers.get('Content-Length'))
            post_data = self.rfile.read(content_length)
            try:
                request_json = json.loads(post_data)
                if self.path == '/api/Agent/Login':
                    self._handle_login(request_json)

                elif self.path == '/api/Agent/SendReport':
                    self._handle_send_report(request_json)

                else:
                    self._set_response(404, 'text/html')
                    self.wfile.write(b'no such url')

            except json.JSONDecodeError:
                self._set_response(400, 'text/html')
                self.wfile.write(b'invalid format')
        except Exception:
            demisto.error(traceback.format_exc())

    def _handle_send_report(self, request_json: dict):
        """
        Handle receiving a report from PingCastle making sure the token used is the token issued by this server.
        Args:
            request_json (dict): The JSON sent in the request.
        """
        if self.headers.get('Authorization') is None:
            self._set_response(400, 'text/html')
            self.wfile.write(b'missing token')
            return

        if self.headers.get('Authorization') != self.token:
            self._set_response(401, 'text/html')
            self.wfile.write(b'Invalid Token')
            return

        if request_json.get('xmlReport') is None:
            self._set_response(400, 'text/html')
            self.wfile.write(b'missing xmlReport')
            return

        self._set_report_context(request_json)
        self._create_incident(request_json)
        self._set_response(200, 'text/html')

    def _create_incident(self, request_json: dict):
        """
        Create an Incident from a report sent by PingCastle.
        Args:
            request_json (dict): The JSON sent in the request.
        """
        incident = {
            'name': 'PingCastle-report',
            'occurred': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(request_json)
        }
        demisto.createIncidents([incident])

    def _set_report_context(self, request_json: dict):
        """
        Store the report in the integration context so that it may be retrieved by the get-report command.
        Args:
            request_json (dict): The JSON sent in the request.
        """
        context: dict = demisto.getIntegrationContext()
        context['report'] = request_json.get('xmlReport')
        demisto.setIntegrationContext(context)

    def _handle_login(self, request_json):
        """
        Handle receiving a login request from PingCastle making sure the API Key is the one set in this integration.
        Args:
            request_json (dict): The JSON sent in the request.
        """
        if request_json.get('apikey') is None:
            self._set_response(400, 'text/html')
            self.wfile.write(b'missing api key')
            return

        if request_json.get('apikey') == demisto.params().get('apikey'):
            choices = string.ascii_uppercase + string.digits
            PingCastleHTTPServer.token = ''.join(random.choices(choices, k=10))
            self._set_response(200, 'text/html')
            self.wfile.write(PingCastleHTTPServer.token.encode('utf-8'))


def listen_for_reports(port: str):
    """
    long-running-execution command: Runs a server listening for PingCastle reports
    """
    while True:
        try:
            listener = HTTPServer(('', int(port)), PingCastleHTTPServer)
            listener.serve_forever()
        except Exception:
            demisto.error(traceback.format_exc())
            time.sleep(1)


def get_report_command(args: dict):
    """
    pingcastle-get-report command: Returns the last report sent by PingCastle
    Args:
        args (dict): A dict object containing the arguments for this command
    """
    delete_report = args.get('delete_report') == 'Yes'
    context = demisto.getIntegrationContext()
    report = context.get('report')
    if report is None:
        return 'No report available'

    if delete_report:
        context.pop('report')
        demisto.setIntegrationContext(context)

    return CommandResults(
        outputs_prefix='PingCastle.Report',
        outputs={'report': report},
        raw_response=report
    )


def main() -> None:
    """main function, parses params and runs command functions"""

    port = demisto.params().get('longRunningPort')
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if command == 'long-running-execution':
            listen_for_reports(port)

        elif command == 'pingcastle-get-report':
            return_results(get_report_command(args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
