from typing import Dict, Callable, Tuple, Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

URL = "https://api.crowdstrike.com/"


class Client(BaseClient):
    """
    Client to use in the FalconX integration. Overrides BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str):
        self._base_url = server_url
        self._username = username
        self._password = password
        self.token = self._generate_token()

    def http_request(self, method, url_suffix, data=None, headers=None, params=None, json=None, response_type: str = 'json'):
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
                json=json
            )
            if not result.ok:
                demisto.log(result.text)
                raise ValueError(f'Error in API call to FalconX {result.status_code}. Reason: {result.text}')

            if response_type != 'json':
                return result.text
            return result.json()

        except Exception as exception:
            raise Exception(str(exception))

    def post_http_req_falconx_json(self, url_suffix, data):
        headers = {
            'Authorization': 'bearer ' + self.token,
            'Content-Type': 'application/json',
        }

        return self.http_request("POST", url_suffix, headers=headers, json=data)

    def post_http_req_falconx_octet_stream(self, url_suffix, data):
        headers = {
            'Authorization': 'bearer ' + self.token,
            'Content-Type': 'application/octet-stream',
        }

        return self.http_request("POST", url_suffix, headers=headers, data=data)

    def get_http_req_falconx(self, url_suffix, params=None):
        headers = {
            'Authorization': 'bearer ' + self.token,
        }

        return self.http_request("Get", url_suffix, headers=headers, params=params)

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


def _create_short_context_falconx(resources: dict):
    sandbox = resources.get("sandbox")[0]
    resource_output = {
        'id': resources.get("id"),
        'state': resources.get("state"),
        'created_timestamp': resources.get("created_timestamp"),
        'sha256': sandbox.get("sha256"),
        'environment_id': sandbox.get("environment_id")
    }
    return {f'csfalconx.resource(val.resource === obj.resource)': resource_output}


def _create_full_context_falconx(resources: dict):
    sandbox = resources.get("sandbox")[0]
    resource_output = {
        'id': resources.get("id"),
        'verdict': resources.get("verdict"),
        'created_timestamp': resources.get("created_timestamp"),
        'environment_id': sandbox.get("environment_id"),
        'environment_description': sandbox.get("environment_description"),
        'sandbox_threat_score': sandbox.get("threat_score"),
        'sandbox_submit_url': sandbox.get("submit_url"),
        'submission_type': sandbox.get("submission_type"),
        'sandbox_filetyp': sandbox.get("filetyp"),  # find
        'sandbox_filesize': sandbox.get("filesize"),  # find
        'sandbox_sha256': sandbox.get("sha256"),
        'ioc_strict_csv': resources.get("ioc_report_strict_csv_artifact_id"),
        'ioc_broad_csv': resources.get("ioc_report_broad_csv_artifact_id"),
        'ioc_strict_jason': resources.get("ioc_report_strict_json_artifact_id"),
        'ioc_broad_jason': resources.get("ioc_report_broad_json_artifact_id"),
        'ioc_strict_stix': resources.get("ioc_report_strict_stix_artifact_id"),
        'ioc_broad_stix': resources.get("ioc_report_broad_stix_artifact_id"),
        'ioc_strict_maec': resources.get("ioc_report_strict_maec_artifact_id"),
        'ioc_broad_maec': resources.get("ioc_report_broad_maec_artifact_id"),
    }
    return {f'csfalconx.resource(val.resource === obj.resource)': resource_output}


def test_module(client):
    """
    If a client was made then an accesses token was successfully reached,
    therefor the username and password are valid and a connection was made
    """
    demisto.log("OK!!!!")
    return 'ok'


def upload_file_command(
        client: Client,
        file: str,# orel.fix file path?
        file_name: str,
        comment: str,
        is_confidential: str
) -> Tuple[str, dict, dict]:

    url_suffix = f"/samples/entities/samples/v2?file_name={file_name}&is_confidential={is_confidential}&comment={comment}"
    data = open(file, 'rb').read()
    response = client.post_http_req_falconx_octet_stream(url_suffix, data)

    resource_output = {
        'sha256': response.get("resources")[0].get("sha256"),
        'file_name': file_name,
    }
    entry_context = {f'csfalconx.resource(val.resource === obj.resource)': resource_output}

    return response, entry_context, response


def send_uploaded_file_to_sendbox_analysis_command(
        client: Client,
        sha256: str,
        environment_id: int,
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
                "enable_tor": enable_tor == "true",
                "submit_name": submit_name,
                "system_date": system_date,
                "system_time": system_time
            }
        ]
    }

    response = client.post_http_req_falconx_json(url_suffix, body)
    resources = response.get("resources")[0]
    resource_output = {
        'id': resources.get("id"),
        'state': resources.get("state"),
        'created_timestamp': resources.get("created_timestamp"),
        'sha256': sha256,
        'environment_id': environment_id
    }
    entry_context = {f'csfalconx.resource(val.resource === obj.resource)': resource_output}

    return response, entry_context, response


def send_url_to_sandbox_analysis_command(
        client: Client,
        url: str,
        environment_id: int,
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
                "enable_tor": enable_tor == "true",
                "submit_name": submit_name,
                "system_date": system_date,
                "system_time": system_time
            }
        ]
    }
    response = client.post_http_req_falconx_json(url_suffix, body)
    resources = response.get("resources")[0]
    entry_context = _create_short_context_falconx(resources)

    return response, entry_context, response


def get_full_report_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/reports/v1?ids={id}"
    params = {
        "ids": ids
    }
    response = client.get_http_req_falconx(url_suffix, params)
    resources = response.get("resources")[0]

    entry_context = _create_full_context_falconx(resources)

    return response, entry_context, response


def get_report_summary_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/report-summaries/v1?ids={id}"
    params = {
        "ids": ids
    }
    response = client.get_http_req_falconx(url_suffix, params)
    resources = response.get("resources")[0]

    entry_context = _create_full_context_falconx(resources)

    return response, entry_context, response


def get_analysis_status_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/submissions/v1?ids={ids}"
    params = {
        "ids": ids
    }
    response = client.get_http_req_falconx(url_suffix, params)
    resources = response.get("resources")[0]
    entry_context = _create_short_context_falconx(resources)

    return response, entry_context, response


def download_ioc_command(
        client: Client,
        id: str,
        name: str,
        accept_encoding: str
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/artifacts/v1?id={id}&name={name}&Accept-Encoding={accept_encoding}"
    params = {
        "id": id,
        "name": name,
        "Accept-Encoding": accept_encoding,
    }
    response = client.get_http_req_falconx(url_suffix, params)
    # entry_context not final
    return response


def check_quota_status_command(
        client: Client
) -> Tuple[str, dict, dict]:
    url_suffix = f"/falconx/entities/submissions/v1?ids="

    response = client.get_http_req_falconx(url_suffix)
    quota = response.get("meta").get("quota")
    resource_output = {
        'quota_total': quota.get("total"),
        'quota_used': quota.get("used"),
        'quota_in_progress': quota.get("in_progress"),
    }
    entry_context = {f'csfalconx.resource(val.resource === obj.resource)': resource_output}

    return response, entry_context, response


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

    response = client.get_http_req_falconx(url_suffix, params)
    resource_output = {
        'id': response.get("resources")[0],
    }
    entry_context = {f'csfalconx.resource(val.resource === obj.resource)': resource_output}
    return response, entry_context, response


def find_submission_id_command(
        client: Client,
        offset: str,
        filter: str,
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
    response = client.get_http_req_falconx(url_suffix, params)
    resource_output = {
        'id': response.get("resources")[0],
    }
    entry_context = {f'csfalconx.resource(val.resource === obj.resource)': resource_output}
    return response, entry_context, response


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
