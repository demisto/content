from fastapi.security import HTTPBasic
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from fastapi.security.api_key import APIKey, APIKeyHeader
import uvicorn
from uvicorn.logging import AccessFormatter
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.security.api_key import APIKey, APIKeyHeader
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
JSON_STRUCTURE = {
    "event": "answer",
    "payload": {
        "answer": "your answer"
    }
}
EVENTS = {}
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


async def handle_listen_error(error: str):
    """
    Logs an error and updates the module health accordingly.

    Args:
        error: The error string.
    """
    demisto.error(error)
    demisto.updateModuleHealth(error)

''' HELPER FUNCTIONS '''


def generate_events():
    original_dict = {
  "attackData": {
    "clientIP": "192.0.2.82",
    "configId": "14227",
    "policyId": "qik1_26545",
    "ruleActions": "YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d",
    "ruleData": "dGVsbmV0LmV4ZQ%3d%3d%3bdGVsbmV0LmV4ZQ%3d%3d%3bVmVjdG9yIFNjb3JlOiAxMCwgREVOWSB0aHJlc2hvbGQ6IDksIEFsZXJ0IFJ1bGVzOiA5NTAwMDI6OTUwMDA2LCBEZW55IFJ1bGU6ICwgTGFzdCBNYXRjaGVkIE1lc3NhZ2U6IFN5c3RlbSBDb21tYW5kIEluamVjdGlvbg%3d%3d",
    "ruleMessages": "U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d",
    "ruleSelectors": "QVJHUzpvcHRpb24%3d%3bQVJHUzpvcHRpb24%3d%3b",
    "ruleTags": "T1dBU1BfQ1JTL1dFQl9BVFRBQ0svRklMRV9JTkpFQ1RJT04%3d%3bT1dBU1BfQ1JTL1dFQl9BVFRBQ0svQ09NTUFORF9JTkpFQ1RJT04%3d%3bQUtBTUFJL1BPTElDWS9DTURfSU5KRUNUSU9OX0FOT01BTFk%3d",
    "ruleVersions": "NA%3d%3d%3bNA%3d%3d%3bMQ%3d%3d",
    "rules": "OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ"
  },
  "botData": {
    "botScore": "100",
    "responseSegment": "3"
  },
  "clientData": {
    "appBundleId": "com.mydomain.myapp",
    "appVersion": "1.23",
    "sdkVersion": "4.7.1",
    "telemetryType": "2"
  },
  "format": "json",
  "geo": {
    "asn": "14618",
    "city": "ASHBURN",
    "continent": "288",
    "country": "US",
    "regionCode": "VA"
  },
  "httpMessage": {
    "bytes": "266",
    "host": "www.hmapi.com",
    "method": "GET",
    "path": "/",
    "port": "80",
    "protocol": "HTTP/1.1",
    "query": "option=com_jce%20telnet.exe",
    "requestHeaders": "User-Agent%3a%20BOT%2f0.1%20(BOT%20for%20JCE)%0d%0aAccept%3a%20text%2fhtml,application%2fxhtml+xml,application%2fxml%3bq%3d0.9,*%2f*%3bq%3d0.8%0d%0auniqueID%3a%20CR_H8%0d%0aAccept-Language%3a%20en-US,en%3bq%3d0.5%0d%0aAccept-Encoding%3a%20gzip,%20deflate%0d%0aConnection%3a%20keep-alive%0d%0aHost%3a%20www.hmapi.com%0d%0aContent-Length%3a%200%0d%0a",
    "requestId": "1158db1758e37bfe67b7c09",
    "responseHeaders": "Server%3a%20AkamaiGHost%0d%0aMime-Version%3a%201.0%0d%0aContent-Type%3a%20text%2fhtml%0d%0aContent-Length%3a%20266%0d%0aExpires%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aDate%3a%20Tue,%2004%20Apr%202017%2010%3a57%3a02%20GMT%0d%0aConnection%3a%20close%0d%0aSet-Cookie%3a%20ak_bmsc%3dAFE4B6D8CEEDBD286FB10F37AC7B256617DB580D417F0000FE7BE3580429E23D%7epluPrgNmaBdJqOLZFwxqQLSkGGMy4zGMNXrpRIc1Md4qtsDfgjLCojg1hs2HC8JqaaB97QwQRR3YS1ulk+6e9Dbto0YASJAM909Ujbo6Qfyh1XpG0MniBzVbPMUV8oKhBLLPVSNCp0xXMnH8iXGZUHlUsHqWONt3+EGSbWUU320h4GKiGCJkig5r+hc6V1pi3tt7u3LglG3DloEilchdo8D7iu4lrvvAEzyYQI8Hao8M0%3d%3b%20expires%3dTue,%2004%20Apr%202017%2012%3a57%3a02%20GMT%3b%20max-age%3d7200%3b%20path%3d%2f%3b%20domain%3d.hmapi.com%3b%20HttpOnly%0d%0a",
    "start": "1491303422",
    "status": "200"
  },
  "type": "akamai_siem",
  "userRiskData": {
    "allow": "0",
    "general": "duc_1h:10|duc_1d:30",
    "originUserId": "jsmith007",
    "risk": "udfp:1325gdg4g4343g/M|unp:74256/H",
    "score": "75",
    "status": "0",
    "trust": "ugp:US",
    "username": "jsmith@example.com",
    "uuid": "964d54b7-0821-413a-a4d6-8131770ec8d5"
  },
  "version": "1.0"
}
    padding_string = "LARGER_DATA_" * 100
    duplicated_dicts = []
    target_size = 10
    import random
    import copy
    import urllib.parse
    for i in range(target_size):
        duplicated_dict = copy.deepcopy(original_dict)
        
        # Modify attackData
        for attack_data_key in ['rules', 'ruleMessages', 'ruleTags', 'ruleData', 'ruleSelectors', 'ruleActions', 'ruleVersions']:
            timestamp = str(time.time())
            encoded_timestamp = base64.b64encode(timestamp.encode()).decode()
            duplicated_dict['attackData'][attack_data_key] += f"{encoded_timestamp}"
        
        random_value = str(random.randint(1, 1000))
        encoded_random_value = urllib.parse.quote(random_value)
        duplicated_dict["httpMessage"]["requestHeaders"] += f"%3brandom_value%3A{encoded_random_value}{duplicated_dict['httpMessage']['requestHeaders']}{duplicated_dict['httpMessage']['requestHeaders']}{duplicated_dict['httpMessage']['requestHeaders']}{duplicated_dict['httpMessage']['requestHeaders']}"
        
        # Modify responseHeaders with the current index (URL-encode if needed)
        encoded_index = urllib.parse.quote(str(i))
        duplicated_dict["httpMessage"]["responseHeaders"] += f"%3bindex%3A{encoded_index}{duplicated_dict['httpMessage']['responseHeaders']}{duplicated_dict['httpMessage']['responseHeaders']}{duplicated_dict['httpMessage']['responseHeaders']}{duplicated_dict['httpMessage']['responseHeaders']}{duplicated_dict['httpMessage']['responseHeaders']}{duplicated_dict['httpMessage']['responseHeaders']}"
        
        for key in duplicated_dict.keys():
            if key not in ["httpMessage", "attackData", "version", "format", "type"] and  isinstance(duplicated_dict[key], dict):
                for key2 in duplicated_dict[key].keys():
                    duplicated_dict[key][key2] += padding_string
                
        duplicated_dicts.append(duplicated_dict)
    return duplicated_dicts


@app.get('/')
async def handle_get_request():
    """handle a regular get response.
    Args:
    Returns:
        Response:response object.
    """
    global EVENTS
    if not EVENTS:
        EVENTS = generate_events()
    return Response(status_code=status.HTTP_200_OK, content=json.dumps(EVENTS), media_type="application/json")


''' COMMAND FUNCTIONS '''


def test_module() -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

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
    LONG_RUNNING = demisto.params().get('longRunning', False)
    if LONG_RUNNING:
        try:
            port = int(demisto.params().get('longRunningPort'))
        except ValueError as e:
            raise ValueError(f'Invalid listen port - {e}')
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            return_results(result)
        if demisto.command() == 'long-running-execution':
            run_long_running(port)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()