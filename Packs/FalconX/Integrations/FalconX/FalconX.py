from typing import Dict, Callable, Tuple, Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InB1YmxpYzphNDdiNTc2MS0zYzk3LTQwMmItOTgzNi0wNmNhODI0NTViOTMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiMTU3YjMyZjRmNWE5NDQ1Yjg1ODRiODM3ZWY4MDQ0NzciXSwiY2xpZW50X2lkIjoiMTU3YjMyZjRmNWE5NDQ1Yjg1ODRiODM3ZWY4MDQ0NzciLCJleHAiOjE1ODg2OTAzMzIsImlhdCI6MTU4ODY4ODUzMiwiaXNzIjoiaHR0cHM6Ly9hcGkuY3Jvd2RzdHJpa2UuY29tLyIsImp0aSI6Ijc1ZmM4MzFmLTBmY2QtNDI1Mi05YTE2LTc3ZDM1MzVkZWZkNyIsIm5iZiI6MTU4ODY4ODUzMiwic3ViIjoiMTU3YjMyZjRmNWE5NDQ1Yjg1ODRiODM3ZWY4MDQ0NzcifQ.cymJfswMYtFlqV25EAmQ5MEuCQ_OKnmtFPZsYp5D8Q-x-aGgFSaAEn9XB_b0iPiCVEpHwepxsa_Puo0wXaTY17pmDALWQjrTA6tDeN1eQ4EYs-sCUoZyuu9hDv4_ENIB5u7Y1jpXQfBudeemPSKBoWuuuASUJ1czooDR0VBJIrTRa0IjEG_VP6cJgkv22oQxHhUj7am0PeckE0Pfdzg8jPG7E7iTB8XIPj-40bDYUeOBnUg94pVmwmUqeWd_BTKBqL60fx3L8RrFls2mkUJ42bwhEOXzJ1h3OhYzBAmrTJw6oIje1J7qCjZz-YFuFmrQhueNK9ybPf-BgA0qH4YjtD6sLFhXuJ9RhTXH3uFVPcX3f75RVrmld1eZdGabenvmilZgiKFXN8vT92Hqpa28P17ALlag2gjQbfqMvGa33KLvmgvoYeBD1oU41FnGYpl1f1kp-4Nm3oakKlKaAOZZMyut_9R9li7AS51zYTGUAyIzGcogXRn2FiCCPEH7KUDTdlesPzkqZDw_ePUz4aCcj2CY-PGA1c1C1TZN-7e1XEqBkb2cMQbbCSCALdu1QWT6JqUUk2LyKXdIPSCOsglcRsF5WtTE3L0MzMhLmYvnhzPdQ47vzoDMOrQAXs3gl0JuUARYGj3kvp1tilfC3mKNsUbbL_fz2W-C0cS-JuqfjgY"

URL = "https://api.crowdstrike.com/"


class Client(BaseClient):
    """
    Client to use in the FalconX integration. Overrides BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str):
        self._base_url = server_url
        self._username = username
        self._password = password
        #self.token = self._generate_token()
        self.token = access_token

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
                demisto.log(result.text)
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

        BYTE_CREDS = f'{self._username}:{self._password}'.encode('utf-8')

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


def test_module(client):
    """
    If a client was made then an accesses token was successfully reached,
    therefor the username and password are valid and a connection was made
    """
    demisto.log("OK!!!!")
    return 'ok'


# is failing
def upload_file_command(
        client: Client,
        file, # orel.fix file type??????
        file_name: str,
        comment: str,
        is_confidential: str
) -> Tuple[str, dict, dict]:

    url_suffix = f"/samples/entities/samples/v2?file_name={file_name}&is_confidential={is_confidential}&comment={comment}"

    headers = {
        'Authorization': 'Bearer '+access_token,
        'Content-Type': 'application/octet-stream',
    }

    data = open(file, 'rb').read()

    response = client.http_request("POST", url_suffix, data=data, headers=headers)
    # demisto.log(response.text)
    return response


def send_uploaded_file_to_sendbox_analysis_command(
        client: Client,
        sha256: str,
        environment_id: int, #orel.debug - make sure there are final number of options
        action_script: str,
        command_line: str,
        document_password: str,
        enable_tor: str,
        submit_name: str,
        system_date: str,
        system_time: str
) -> Tuple[str, dict, dict]:

    url_suffix = "/falconx/entities/submissions/v1"
    body = {
        "sandbox": [
            {
                "sha256": sha256,
                "environment_id": environment_id,
                "action_script": action_script,
                "command_line": command_line,
                "document_password": document_password,
                "enable_tor": enable_tor,
                "submit_name": submit_name,
                "system_date": system_date,
                "system_time": system_time
            }
        ]
    }
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json',
    }
    response = client.http_request("POST", url_suffix, data=body, headers=headers)
    # demisto.log(response.text)
    return response


def send_url_to_sandbox_analysis_command(
        client: Client,
        url: str,
        environment_id: int, #orel.debug - make sure there are final number of options
        action_script: str,
        command_line: str,
        document_password: str,
        enable_tor: str,
        submit_name: str,
        system_date: str,
        system_time: str
) -> Tuple[str, dict, dict]:

    url_suffix = "/falconx/entities/submissions/v1"

    body = {
        "sandbox": [
            {
                "url": url,
                "environment_id": environment_id,
                "action_script": action_script,
                "command_line": command_line,
                "document_password": document_password,
                "enable_tor": enable_tor,
                "submit_name": submit_name,
                "system_date": system_date,
                "system_time": system_time
            }
        ]
    }

    payload = "{    \"sandbox\": [\n        {\n            \"url\": \"https://www.google.com\",\n            \"environment_id\": 160,\n            \"action_script\": \"\",\n            \"command_line\": \"\",\n            \"document_password\": \"\",\n            \"enable_tor\": false,\n            \"submit_name\": \"\",\n            \"system_date\": \"\",\n            \"system_time\": \"\"\n        }\n    ]\n}"
    headers = {
        'Authorization': 'bearer ' + client.token,
        'Content-Type': 'application/json',
    }
    response = client.http_request("POST", url_suffix, headers=headers, json=body)
    demisto.log(response)
    return response


def get_full_report_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/reports/v1?ids={id}"
    params = {
        "ids": ids
    }
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None, params=params)
    # demisto.log(response.text)
    return response


def get_report_summary_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/report-summaries/v1?ids={id}"
    params = {
        "ids": ids
    }
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None, params=params)
    # demisto.log(response.text)
    return response


def get_analysis_status_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/submissions/v1?ids={ids}"

    params = {
        "ids": ids
    }
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None, params=params)
    # demisto.log(response.text)
    return response


def download_ioc_command( #orel.fix - name??? where is it?
        client: Client,
        id: str,
        name: str,
        accept_encoding: str
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/artifacts/v1?id={id}" \
                 f"&name=&Accept-Encoding={accept_encoding}"

    params = {
        "id": id,
        "Accept-Encoding": accept_encoding,
    }
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None, params=params)
    # demisto.log(response.text)
    return response


def check_quota_status_command(
        client: Client
) -> Tuple[str, dict, dict]:
    url_suffix = f"/falconx/entities/submissions/v1?ids="

    headers = {
        'Authorization': 'bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None)
    demisto.log(response)
    return response


def find_sandbox_reports_command(
        client: Client,
        filter: str,
        offset: str,
        limit: int,
        sort: str
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/queries/reports/v1?filter={filter}&offset={offset}&limit{limit}=&sort={sort}"

    params = {
        "filter": filter,
        "offset": offset,
        "limit": limit,
        "sort": sort,
    }
    headers = {
        'Authorization': 'bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None, params=params)
    demisto.log(response)
    return response


def find_submission_id_command(
        client: Client,
        filter: str,
        offset: str,
        limit: int,
        sort: str
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/queries/submissions/v1?filter={filter}&offset={offset}&limit{limit}=&sort={sort}"

    params = {
        "filter": filter,
        "offset": offset,
        "limit": limit,
        "sort": sort,
    }
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    response = client.http_request("GET", url_suffix, headers=headers, data=None, params=params)
    # demisto.log(response.text)
    return response


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    try:
        command = demisto.command()
        LOG(f'Command being called in FalconX Sandbox is: {command}')
        client = Client(server_url=URL, username=username, password=password)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'cs-fx-upload-file': upload_file_command,
            'cs-fx-detonate-uploaded-file': send_uploaded_file_to_sendbox_analysis_command,
            'cs-fx-detonate-url': send_url_to_sandbox_analysis_command,
            'cs-fx-get-full-report': get_full_report_command,
            'cs-fx-get-report-summary': get_report_summary_command,
            'cs-fx-get-analysis-status': get_analysis_status_command,
            'cs-fx-download-ioc': download_ioc_command,
            'cs-fx-check-quota': check_quota_status_command,
            'cs-fx-find-reports': find_sandbox_reports_command,
            'cs-fx-find-submission-id': find_submission_id_command
        }
        if command in commands:
            return_outputs(*commands[command](client, **demisto.args()))
        else:
            raise NotImplementedError(f'{command} is not an existing FalconX command')
    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
