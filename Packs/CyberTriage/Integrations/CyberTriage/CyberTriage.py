import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any, Tuple

import requests
import urllib3

# Disable warning for insecure requests when cert validation is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def IS_2XX(x: int) -> bool:
    return int(x / 100) == 2  # Returns true if status code (int) is 2xx


class CyberTriageClient(BaseClient):
    SCAN_OPTIONS = ['pr', 'nw', 'nc', 'st', 'sc', 'ru', 'co', 'lo', 'ns', 'wb', 'fs']

    def __init__(self, server: str, rest_port: str, api_key: str, user: str,
                 password: str, verify_server_cert: bool, ok_codes: Tuple[int, ...]):
        base_url = f'https://{server}:{rest_port}/api/' if not (
            server.startswith('https://') or server.startswith('http://')
        ) else f'{server}:{rest_port}/api/'
        req_headers = {'restApiKey': api_key}
        self._user = user
        self._password = password
        super().__init__(base_url=base_url, verify=verify_server_cert, headers=req_headers, ok_codes=ok_codes)

    def test_connection(self):
        response = self._http_request('GET', url_suffix='correlation/checkcredentials', resp_type='response')
        return response

    def triage_endpoint(self, is_hash_upload_on: bool, is_file_upload_on: bool,
                        endpoint: str, scan_options: str, incident_name: str):
        # Validate scan options
        invalid_options = []
        if scan_options:
            invalid_options = [opt for opt in scan_options.split(',') if opt not in self.SCAN_OPTIONS]
        if invalid_options:
            raise DemistoException('The following are not valid scan options: {}'.format(','.join(invalid_options)))

        # Make data dict for rest call
        api_data = {
            'incidentName': incident_name,
            'hostName': endpoint,
            'userId': self._user,
            'password': self._password,
            'scanOptions': scan_options,
            'malwareScanRequested': is_hash_upload_on,
            'sendContent': is_file_upload_on,
            'sendIpAddress': False
        }
        response = self._http_request('POST', url_suffix='livesessions', data=api_data, resp_type='response')
        return response


def test_connection_command(client: CyberTriageClient) -> str:
    response = client.test_connection()
    response.raise_for_status()
    return 'ok'


def triage_endpoint_command(client: CyberTriageClient, args: dict[str, Any]) -> CommandResults:
    def is_true(x: str) -> bool:
        return x == 'yes'
    is_hash_upload_on = is_true(args.get('malware_hash_upload', ''))  # arg value = 'yes' or 'no'
    is_file_upload_on = is_true(args.get('malware_file_upload', ''))  # arg value = 'yes' or 'no'
    endpoint = args.get('endpoint', '')
    scan_options = args.get('scan_options', '')
    incident_name = args.get('incident_name', '')
    response = client.triage_endpoint(is_hash_upload_on, is_file_upload_on, endpoint, scan_options, incident_name)

    response.raise_for_status()

    if is_ip_valid(endpoint):
        endpoint_context = {'IPAddress': endpoint}
    else:
        endpoint_context = {'Hostname': endpoint}

    data = response.json()

    ec = {
        'CyberTriage': data,
        'Endpoint': endpoint_context
    }

    return CommandResults(
        readable_output=f'A collection has been scheduled for {endpoint}',
        outputs=ec,
        raw_response=data
    )


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    server = params.get('server', '')
    rest_port = params.get('rest_port', '')
    api_key = params.get('api_key', {}).get('password', '')
    user = params.get('credentials', {}).get('identifier', '')
    password = params.get('credentials', {}).get('password', '')
    verify_server_cert = False
    handle_proxy(proxy_param_name='use_proxy')

    demisto.debug(f"Command being called is {command}")
    try:
        acceptable_status_codes: Tuple[int, ...] = tuple(
            int(code) for code in requests.status_codes.codes if IS_2XX(code)
        )
        client = CyberTriageClient(server, rest_port, api_key, user, password,
                                   verify_server_cert, acceptable_status_codes)
        # This is the call made when running the ct-triage-endpoint command.
        if command == 'ct-triage-endpoint':
            return_results(triage_endpoint_command(client, args))

        # This is the call made when pressing the integration test button.
        elif command == 'test-module':
            return_results(test_connection_command(client))
        else:
            raise NotImplementedError(f'command={command} not implemented in this integration')
    except Exception as e:
        return_error(
            f"Failed to execute {command} command.\nError: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
