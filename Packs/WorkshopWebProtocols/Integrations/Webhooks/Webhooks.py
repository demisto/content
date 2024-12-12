import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from fastapi.security.api_key import APIKey, APIKeyHeader
from secrets import compare_digest
import uvicorn
from uvicorn.logging import AccessFormatter
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from fastapi_utils.tasks import repeat_every
from CommonServerUserPython import *  # noqa
from copy import copy
from traceback import format_exc
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')

import urllib3
from typing import Dict, Any
from tempfile import NamedTemporaryFile

app = FastAPI()
# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class UserAgentFormatter(AccessFormatter):
    """This formatter extracts and includes the 'User-Agent' header information
    in the log messages."""

    def get_user_agent(self, scope: Dict) -> str:
        headers = scope.get('headers', [])
        user_agent_header = list(filter(lambda header: header[0].decode().lower() == 'user-agent', headers))
        user_agent = ''
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def format_message(self, record):
        """Include the 'User-Agent' header information in the log message.
        Args:
            record: The log record to be formatted.
        Returns:
            str: The formatted log message."""
        record_copy = copy(record)
        scope = record_copy.__dict__['scope']
        user_agent = self.get_user_agent(scope)
        record_copy.__dict__.update({'user_agent': user_agent})
        return super().formatMessage(record_copy)


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    def baseintegration_dummy(self, dummy: str) -> Dict[str, str]:
        """Returns a simple python dict with the information provided
        in the input (dummy).

        :type dummy: ``str``
        :param dummy: string to add in the dummy dict that is returned

        :return: dict as {"dummy": dummy}
        :rtype: ``str``
        """

        return {"dummy": dummy}

async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.

    Args:
        error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)

''' HELPER FUNCTIONS '''
@app.get('/')
async def handle_get_response(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth),
                               token: APIKey = Depends(token_auth)):
    """handle any response that came from Zoom app
    Args:
        request : zoom request
    Returns:
        JSONResponse:response to zoom
    """
    # request = await request.json()
    # demisto.debug(f"WH: Got request; {request}")
    # credentials_param = demisto.params().get('credentials')
    # auth_failed = False
    # v_token = demisto.params().get('verification_token', {}).get('password')
    # if not str(token).startswith('Basic') and v_token:
    #     if token != v_token:
    #         auth_failed = True

    # elif credentials and credentials_param and (username := credentials_param.get('identifier')):
    #     password = credentials_param.get('password', '')
    #     if not compare_digest(credentials.username, username) or not compare_digest(credentials.password, password):
    #         auth_failed = True
    # if auth_failed:
    #     demisto.debug('Authorization failed')
    #     return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed. Try another route')
    
    return Response(status_code=status.HTTP_200_OK, content='Great that you conected, ')

@app.post('/')
async def handle_post_response(request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth),
                               token: APIKey = Depends(token_auth)):
    """handle any response that came from Zoom app
    Args:
        request : zoom request
    Returns:
        JSONResponse:response to zoom
    """
    request = await request.json()
    demisto.debug(f"WH: Got request; {request}")
    # credentials_param = demisto.params().get('credentials')
    # auth_failed = False
    # v_token = demisto.params().get('verification_token', {}).get('password')
    # if not str(token).startswith('Basic') and v_token:
    #     if token != v_token:
    #         auth_failed = True

    # elif credentials and credentials_param and (username := credentials_param.get('identifier')):
    #     password = credentials_param.get('password', '')
    #     if not compare_digest(credentials.username, username) or not compare_digest(credentials.password, password):
    #         auth_failed = True
    # if auth_failed:
    #     demisto.debug('Authorization failed')
    #     return Response(status_code=status.HTTP_401_UNAUTHORIZED, content='Authorization failed.')

    event_type = request['event']
    payload = request['payload']
    
    try:
        if payload:
            return Response(status_code=status.HTTP_200_OK, content=f'Yayy, got {event_type=} and {payload=}')
        else:
            return Response(status_code=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        await handle_listen_error(f'An error occurred while handling a response: {e}')

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message



def run_long_running(port: int, is_test: bool = False):
    while True:
        certificate = demisto.params().get('certificate', '')
        private_key = demisto.params().get('key', '')

        certificate_path = ''
        private_key_path = ''
        try:
            ssl_args = {}

            if certificate and private_key:
                certificate_file = NamedTemporaryFile(delete=False)
                certificate_path = certificate_file.name
                certificate_file.write(bytes(certificate, 'utf-8'))
                certificate_file.close()
                ssl_args['ssl_certfile'] = certificate_path

                private_key_file = NamedTemporaryFile(delete=False)
                private_key_path = private_key_file.name
                private_key_file.write(bytes(private_key, 'utf-8'))
                private_key_file.close()
                ssl_args['ssl_keyfile'] = private_key_path

                demisto.debug('Starting HTTPS Server')
            else:
                demisto.debug('Starting HTTP Server')

            integration_logger = IntegrationLogger()
            integration_logger.buffering = False
            log_config = dict(uvicorn.config.LOGGING_CONFIG)
            log_config['handlers']['default']['stream'] = integration_logger
            log_config['handlers']['access']['stream'] = integration_logger
            log_config['formatters']['access'] = {
                '()': UserAgentFormatter,
                'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
            }
            uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
        except Exception as e:
            demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            if certificate_path:
                os.unlink(certificate_path)
            if private_key_path:
                os.unlink(private_key_path)
            time.sleep(5)


def run_log_running(port: int, is_test: bool = False):
    while True:
        try:
            demisto.debug('Starting Server')
            integration_logger = IntegrationLogger()
            integration_logger.buffering = False
            log_config = dict(uvicorn.config.LOGGING_CONFIG)
            log_config['handlers']['default']['stream'] = integration_logger
            log_config['handlers']['access']['stream'] = integration_logger
            log_config['formatters']['access'] = {
                '()': UserAgentFormatter,
                'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
            }
            uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config)
            if is_test:
                time.sleep(5)
                return 'ok'
        except Exception as e:
            demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            time.sleep(5)

''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    base_url = urljoin(demisto.params()['url'], '/api/v1')

    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    LONG_RUNNING = demisto.params().get('longRunning', False)
    if LONG_RUNNING:
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        if demisto.command() == 'long-running-execution':
            run_long_running(port)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
