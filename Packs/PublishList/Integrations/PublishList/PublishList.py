import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import csv
import json
from copy import copy
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc

import uvicorn
from fastapi import Depends, FastAPI, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKey, APIKeyHeader
from uvicorn.logging import AccessFormatter

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name='Authorization')

listsToPublish = [x.strip() for x in demisto.params().get('listsToPublish').split(',')]
commaToLineBreak = demisto.params().get('commaToLineBreak')
commentIfEmpty = demisto.params().get('add_comment_if_empty')


def is_json(jstr):
    try:
        json.loads(jstr)
    except ValueError:
        return False
    return True


class PublishListAccessFormatter(AccessFormatter):
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


@app.get('/{xsoar_list}')
async def handle_get(
        xsoar_list: str,
        request: Request,
        credentials: HTTPBasicCredentials = Depends(basic_auth),
        token: APIKey = Depends(token_auth)
):
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

    if xsoar_list not in listsToPublish:
        # Return list not found instead of permission denied to prevent brute force list name discovery
        return Response(status_code=404, content='List not found')

    try:
        list_response = demisto.internalHttpRequest("GET", f"/lists/download/{xsoar_list}")
        if len(list_response.get("body")) == 0 and commentIfEmpty:
            return Response(content="# Empty list")

        # For normal lists (not json) that are essentially just a long comma separated list
        # this puts each entry on a new line
        if commaToLineBreak and not is_json(list_response.get("body")):
            tmparr = []
            reader = csv.reader([list_response.get("body")], quoting=csv.QUOTE_MINIMAL)
            for row in reader:
                if type(row) is str:
                    r = str(row)  # new variable needed for mypy validation
                    tmparr.append(r)
                else:
                    for cell in row:
                        c = str(cell)  # new variable needed for mypy validation
                        tmparr.append(c)
            list_body = "\n".join(tmparr)
            return Response(content=list_body)

        return Response(content=list_response.get("body"))
    except Exception as e:
        return e


def main() -> None:
    try:
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
        if demisto.command() == 'test-module':
            return_results('ok')
        elif demisto.command() == 'long-running-execution':
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
                        '()': PublishListAccessFormatter,
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
    except Exception as e:
        demisto.error(format_exc())
        return_error(f'Failed to execute {demisto.command()} command. Error: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
