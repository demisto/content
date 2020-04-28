from typing import Dict, Callable, Tuple, Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
      Client to use in the FalconX integration. Overrides BaseClient
      """

    def __init__(self, server_url: str, username: str, password: str):
        self._base_url = server_url
        self._username = username
        self._password = password
        self.token = self._generate_token()

    def http_request(self, method, url_suffix, data, headers=None, params=None, response_type: str = 'json'):
        """
        Generic request to FalconX
        """
        full_url = urljoin(self._base_url, url_suffix)

        try:
            result = requests.request(
                method,
                full_url,
                verify=False,
                params=params,
                data=data,
                headers=headers,
            )
            if not result.ok:
                raise ValueError(f'Error in API call to FalconX {result.status_code}. Reason: {result.text}')

            if response_type != 'json':
                return result.text
            return result.json()

        except Exception as exception:
            raise Exception(str(exception))

    def _generate_token(self) -> str:
        """Generate an Access token

        Returns:
            valid token
        """

        body = {
            'client_id': self._username,
            'client_secret': self._password
        }

        BYTE_CREDS = f'{self._name}:{self._password}'.encode('utf-8')

        HEADERS = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Basic {base64.b64encode(BYTE_CREDS).decode()}'
        }

        headers = {
            'Authorization': HEADERS['Authorization']
        }
        token_res = self.http_request('POST', '/oauth2/token', data=body, headers=headers)
        # print(token_res.text)
        return token_res.get('access_token')


def test_module():
    """
    If a client was made then an accesses token was successfully reached,
    therefor the username and password are valid and a connection was made
    """
    return 'ok'

# Idea - move the part that needs the token to an inner function in Client
def upload_file(client, args):
    file_name = args.get('file_name')
    is_confidential = args.get('is_confidential')
    comment = args.get('comment')
    url = f"/samples/entities/samples/v2?file_name={file_name}&is_confidential={is_confidential}&comment={comment}"

    payload = "<file contents here>"
    headers = {
        'Authorization': client.token,
        'Content-Type': 'application/octet-stream',
        'Content-Type': 'application/x-msdos-program'
    }

    response = client.http_request("POST", url, headers=headers, data=payload)
    return response.text.encode('utf8'), [], {}


def send_uploaded_file_to_sendbox_analysis(client, args):
    url = "/falconx/entities/submissions/v1"

    payload = "{\n    \"sandbox\": [\n        {\n            \"sha256\": \"266239878dfca823d2ab82446a0cc7b19a416fd70a09df25db2365419745d9fe\",\n            \"environment_id\": 160,\n            \"action_script\": \"\",\n            \"command_line\": \"\",\n            \"document_password\": \"\",\n            \"enable_tor\": false,\n            \"submit_name\": \"\",\n            \"system_date\": \"\",\n            \"system_time\": \"\"\n        }\n    ]\n}"
    headers = {
        'Authorization': client.token,
        'Content-Type': 'application/json',
        'Content-Type': 'text/plain'
    }

    response = client.http_request("POST", url, headers=headers, data=payload)
    return response.text.encode('utf8'), [], {}


def send_url_to_sandbox_analysis(client, args):
    url = "/falconx/entities/submissions/v1"

    payload = "{\n    \"sandbox\": [\n        {\n            \"url\": \"https://www.google.com\",\n            \"environment_id\": 160,\n            \"action_script\": \"\",\n            \"command_line\": \"\",\n            \"document_password\": \"\",\n            \"enable_tor\": false,\n            \"submit_name\": \"\",\n            \"system_date\": \"\",\n            \"system_time\": \"\"\n        }\n    ]\n}"
    headers = {
        'Authorization': client.token,
        'Content-Type': 'application/json',
        'Content-Type': 'text/plain'
    }

    response = client.http_request("POST", url, headers=headers, data=payload)
    return response.text.encode('utf8'), [], {}


def get_full_report(client, args):
    id = args.get("id")
    url = f"/falconx/entities/reports/v1?ids={id}"
    payload = {}
    headers = {
        'Authorization': client.token
    }

    response = client.http_request("POST", url, headers=headers, data=payload)
    return response.text.encode('utf8'), [], {}


def get_report_summary(client, args):
    id = args.get("id")
    url = f"/falconx/entities/report-summaries/v1?ids={id}"

    payload = {}
    headers = {
        'Authorization': client.token
    }

    response = requests.request("GET", url, headers=headers, data=payload)

    print(response.text.encode('utf8'))

    return 'ok'


def get_analysis_status(client, args):
    return 'ok'

def download_ioc(client, args):
    return 'ok'

def check_quota_status(client, args):
    return 'ok'

def find_sandbox_reports(client, args):
    return 'ok'

def find_submission_id(client, args):
    return 'ok'


def main():
    # print("start")
    url = "https://api.crowdstrike.com/" # CONST?
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    try:
        command = demisto.command()
        LOG(f'Command being called in SQL is: {command}')
        client = Client(server_url=url, username=username, password=password)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'cs-fx-upload-file': upload_file,
            'cs-fx-detonate-uploaded-file': send_uploaded_file_to_sendbox_analysis,
            'cs-fx-detonate-url': send_url_to_sandbox_analysis,
            'cs-fx-get-full-report': get_full_report,
            'cs-fx-get-report-summary': get_report_summary,
            'cs-fx-get-analysis-status': get_analysis_status,
            'cs-fx-download-ioc': download_ioc,
            'cs-fx-check-quota': check_quota_status,
            'cs-fx-find-reports': find_sandbox_reports,
            'cs-fx-find-submission-id': find_submission_id
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        if command in commands:
            return_outputs(*commands[command](client, demisto.args(), command))
        else:
            raise NotImplementedError(f'{command} is not an existing FalconX command')
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
