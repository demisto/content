import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from copy import copy
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc

import uvicorn
from fastapi import Depends, FastAPI, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from uvicorn.logging import AccessFormatter

''' Globals '''
# Get Target API Parameters
API_CRED_TYPE = demisto.params().get('api_credential_type')
API_PATH = demisto.params().get('api_path')
API_CREDENTIALS = demisto.params().get('api_credentials')
API_CUSTOM_HEADER = demisto.params().get('custom_auth_header')
API_CUSTOM_HEADER_VALUE = demisto.params().get('custom_auth_header_value')
API_PERMISSIONS = json.loads(demisto.params().get('api_permissions'))

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')


def is_json(jstr):
    try:
        json.loads(jstr)
    except ValueError:
        return False
    return True


class SimpleAPIProxyAccessFormatter(AccessFormatter):
    def get_user_agent(self, scope: dict) -> str:
        headers = scope.get('headers', [])
        user_agent_header = list(filter(lambda header: header[0].decode() == 'user-agent', headers))
        user_agent = ''
        if len(user_agent_header) == 1:
            user_agent = user_agent_header[0][1].decode()
        return user_agent

    def formatMessage(self, record):
        recordcopy = copy(record)
        scope = recordcopy.__dict__['scope']
        user_agent = self.get_user_agent(scope)
        recordcopy.__dict__.update({'user_agent': user_agent})
        return super().formatMessage(recordcopy)


def make_api_request(
        url: str, method: str, data: dict | None = None, parameters: dict | None = None
) -> Union[requests.Response, Response]:
    '''
        Make request to api endpoint

    Args:

        url (str): endpoint to make request
        method (str): GET, POST action to perform
        data (Optional[Dict]): Body to be sent to service
        parameters (Optional[Dict]): Query parameters to be sent to service

    Returns:
        requests.Response object (For returning raw API response object) or Response object
        (For handling errors in integration configuration)
    '''

    http_basic_creds_to_pass = None
    headers_to_pass = None

    if API_CRED_TYPE:
        if API_CRED_TYPE == 'Basic':
            http_basic_creds_to_pass = (API_CREDENTIALS.get('identifier'), API_CREDENTIALS.get('password'))

        elif API_CRED_TYPE == 'Bearer Token':
            headers_to_pass = {
                "Authorization": f"Bearer {API_CREDENTIALS.get('password')}"
            }

        elif API_CRED_TYPE == 'Custom Header':
            if not API_CUSTOM_HEADER:
                return Response(status_code=200, content="Custom Header is not set in integration configuration "
                                                         "and Credential Type is selected as 'Custom Header'")

            elif not API_CUSTOM_HEADER_VALUE:
                return Response(status_code=200, content="Custom Header value is not set in integration configuration "
                                                         "and Credential Type is selected as 'Custom Header'")

            headers_to_pass = {
                API_CUSTOM_HEADER: API_CUSTOM_HEADER_VALUE
            }

    # json stringify if dict
    isjson = False
    if isinstance(data, dict):
        isjson = True

    if isjson:
        response = requests.request(method.upper(), url, json=data, params=parameters, auth=http_basic_creds_to_pass,
                                    headers=headers_to_pass, verify=False)
    else:
        response = requests.request(method.upper(), url, data=data, params=parameters, auth=http_basic_creds_to_pass,
                                    headers=headers_to_pass, verify=False)

    demisto.debug(f'Requests Request Headers: {response.request.headers}')
    demisto.debug(f'Requests Response: {response.text}')
    return response

# Set to / as we will take ALL authenticated POST against the instance and evaluated
# if the request is allowed via the api_permissions definition


@app.post('/')
async def handle_post(
        request: Request,
        credentials: HTTPBasicCredentials = Depends(basic_auth),
        token: APIKey = Depends(token_auth),
) -> Response:
    '''
        Handles the requests to '/' endpoint of the exposed service

    Args:
        request (Request): Actual Request object from client's request
        credentials (HTTPBasicCredentials): Credentials for the API
        token (APIKey): Token to be used for API request

    '''
    credentials_param = demisto.params().get('credentials')
    if credentials_param and (username := credentials_param.get('identifier')):
        password = credentials_param.get('password', '')
        auth_failed = False
        header_name = None
        if username.startswith('_header'):
            header_name = username.split(':')[1]
            token_auth.model.name = header_name
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (not (compare_digest(credentials.username, username)
                                        and compare_digest(credentials.password, password))):
            auth_failed = True
        if auth_failed:
            request_headers = dict(request.headers)
            secret_header = (header_name or 'Authorization').lower()
            if secret_header in request_headers:
                request_headers[secret_header] = '***'
            demisto.debug(f'Authorization failed - request headers {request_headers}')
            return Response(status_code=401, content='Authorization failed.')

    # Check if METHOD and TARGET from the POST body are allowed per the api_permissions defined as an integration input

    body_from_request = await request.json()
    target_found = False
    allowed_methods = []

    for item in API_PERMISSIONS.get('Permissions'):
        # Matches from beginning of the string, same as ^[Endpoint]*
        if re.match(item.get('target'), body_from_request.get('target')):
            target_found = True
            allowed_methods = item.get('allowed_methods')
            break

    if target_found:
        # added to get the method from the client posted body
        method = body_from_request.get('method')

        if method in allowed_methods:
            data_for_post = body_from_request.get('body')
            parameters_for_get = body_from_request.get('parameters')

            # Parsing string type parameters to dict: "?var1=val1&var2=val2" -> {'var1': 'val1', 'var2': 'val2'}
            if parameters_for_get:
                parameters_for_get = dict(subString.split('=') for subString in parameters_for_get[1:].split('&'))

            url = API_PATH + body_from_request.get('target')

            demisto.debug(f'Target URL: {url}')

            result = make_api_request(url, method, data_for_post, parameters_for_get)

            if isinstance(result, Response):
                return Response(status_code=400, content=str(result.body))

            elif isinstance(result, requests.Response):
                if is_json(result.text):
                    return Response(status_code=result.status_code, content=json.dumps(result.json()),
                                    media_type="application/json")
                else:
                    return Response(status_code=result.status_code, content=result.text)
        else:
            return Response(status_code=400, content="Method not allowed.")

    return Response(status_code=400, content="Target not found.")


def run_log_running(port: int, is_test: bool = False):
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
                '()': SimpleAPIProxyAccessFormatter,
                'fmt': '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s "%(user_agent)s"'
            }
            uvicorn.run(app, host='0.0.0.0', port=port, log_config=log_config, **ssl_args)  # type: ignore[arg-type]
            if is_test:
                time.sleep(5)
                return 'ok'
        except Exception as e:
            demisto.error(f'An error occurred in the long running loop: {str(e)} - {format_exc()}')
            demisto.updateModuleHealth(f'An error occurred: {str(e)}')
        finally:
            if certificate_path:
                os.unlink(certificate_path)
            if private_key_path:
                os.unlink(private_key_path)
            time.sleep(5)


def main() -> None:
    try:
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return_results(run_log_running(port=port, is_test=True))
        elif demisto.command() == 'long-running-execution':
            run_log_running(port=port)
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
