from typing import Dict, Callable, Tuple, Any

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import requests
import traceback

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):
    """
    Client to use in the CrowdStrikeFalconX integration. Overrides BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str):
        super().__init__(base_url=server_url, verify=False)
        self._base_url = server_url
        self._username = username
        self._password = password
        self.token = self._generate_token()

    def cs_falconx_http_req(self, method, url_suffix, content_type=None, data=None, json_data=None, param=None):
        headers = {
            'Authorization': 'bearer ' + self.token,
        }
        if content_type:
            headers['Content-Type'] = content_type
        return self._http_request(method, url_suffix, headers=headers, data=data, json_data=json_data, params=param)

    def _generate_token(self) -> str:
        """Generate an Access token

        Returns:
            valid token
        """

        body = {
            'client_id': self._username,
            'client_secret': self._password
        }

        byte_creds = f'{self._username}:{self._password}'.encode('utf-8')

        headers = {
            'Authorization': f'Basic {base64.b64encode(byte_creds).decode()}'
        }
        token_res = self._http_request('POST', '/oauth2/token', data=body, headers=headers)
        return token_res.get('access_token')


def add_outputs_from_dict(
        api_current_dict: dict,
        fields_to_keep: list
) -> dict:
    if not api_current_dict or not fields_to_keep:
        return {}

    group_outputs = {}

    for field_to_keep in fields_to_keep:
        if field_to_keep in api_current_dict.keys():
            group_outputs[field_to_keep] = api_current_dict.get(field_to_keep)

    return group_outputs


def parse_outputs(
        api_res: Dict,
        meta_fields: list = [],
        quota_fields: list = [],
        resources_fields: list = [],
        sandbox_filds: list = []
) -> Dict[str, dict]:
    """Parse group data as received from CrowdStrike FalconX API into Demisto's conventions
    the output from the API is a dict that contains the keys: meta, resources and errors
    the meta contains a "quota" dict
    the "resources" is an array that contains the sandbox dict
    if the error isn't empty......
    """
    if api_res.get("errors"):
        return api_res.get("errors")

    api_res_meta, api_res_quota, api_res_resources, api_res_sandbox = {}, {}, {}, {}
    resources_group_outputs, sandbox_group_outputs = {}, {}

    api_res_meta = api_res.get("meta")
    if api_res_meta:
        api_res_quota = api_res_meta.get("quota")

    meta_group_outputs = add_outputs_from_dict(api_res_meta, meta_fields)
    quota_group_outputs = add_outputs_from_dict(api_res_quota, quota_fields)

    if api_res.get("resources"):
        if type(api_res.get("resources")[0]) == dict:
            api_res_resources = api_res.get("resources")[0]
            resources_group_outputs = add_outputs_from_dict(api_res_resources, resources_fields)

            if api_res_resources and api_res_resources.get("sandbox"):
                api_res_sandbox = api_res_resources.get("sandbox")[0]
                sandbox_group_outputs = add_outputs_from_dict(api_res_sandbox, sandbox_filds)
        else:
            resources_group_outputs={"resources":api_res.get("resources")}

    merged_dicts = {**meta_group_outputs, **quota_group_outputs, **resources_group_outputs, **sandbox_group_outputs}

    return {f'csfalconx.resource(val.resource === obj.resource)': merged_dicts}


def test_module(client):
    """
    If a client was made then an accesses token was successfully reached,
    therefor the username and password are valid and a connection was made
    """
    return 'ok', {}, []


def upload_file_command(
        client: Client,
        file: str,
        file_name: str,
        is_confidential: str,
        comment: str = ""
) -> Tuple[str, dict, dict]:

    url_suffix = f"/samples/entities/samples/v2?file_name={file_name}&is_confidential={is_confidential}&comment={comment}"
    data = open(file, 'rb').read()

    response = client.cs_falconx_http_req("POST", url_suffix, content_type='application/octet-stream', data=data)

    resources_fields = ["file_name", "sha256"]
    entry_context = parse_outputs(response, resources_fields=resources_fields)

    return response, entry_context, response


def send_uploaded_file_to_sendbox_analysis_command(
        client: Client,
        sha256: str,
        environment_id: int,
        action_script: str = "",
        command_line: str = "",
        document_password: str = "",
        enable_tor: str = "false",
        submit_name: str = "",
        system_date: str = "",
        system_time: str = ""
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

    response = client.cs_falconx_http_req("POST", url_suffix, content_type='application/json', json_data=body)

    sandbox_filds = ["environment_id", "sha256"]
    resource_fields = ['id', 'state', 'created_timestamp', 'created_timestamp']
    entry_context = parse_outputs(response, sandbox_filds=sandbox_filds, resources_fields=resource_fields)

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
    response = client.cs_falconx_http_req("POST", url_suffix, content_type='application/json', json_data=body)

    resources_fields = ['id', 'state', 'created_timestamp']
    sandbox_filds = ["environment_id", "sha256"]
    entry_context = parse_outputs(response, resources_fields=resources_fields, sandbox_filds=sandbox_filds)

    return response, entry_context, response


def get_full_report_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/reports/v1?ids={id}"
    params = {
        "ids": ids
    }
    response = client.cs_falconx_http_req("Get", url_suffix, param=params)

    resources_fields = ['id', 'verdict', 'created_timestamp', "ioc_report_strict_csv_artifact_id",
                        "ioc_report_broad_csv_artifact_id", "ioc_report_strict_json_artifact_id",
                        "ioc_report_broad_json_artifact_id", "ioc_report_strict_stix_artifact_id",
                        "ioc_report_broad_stix_artifact_id", "ioc_report_strict_maec_artifact_id",
                        "ioc_report_broad_maec_artifact_id"]

    sandbox_filds = ["environment_id", "environment_description", "threat_score", "submit_url", "submission_type",
                     "filetyp", "filesize", "sha256"]
    entry_context = parse_outputs(response, resources_fields=resources_fields, sandbox_filds=sandbox_filds)

    return response, entry_context, response


def get_report_summary_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/report-summaries/v1?ids={id}"
    params = {
        "ids": ids
    }
    response = client.cs_falconx_http_req("Get", url_suffix, param=params)

    resources_fields = ['id', 'verdict', 'created_timestamp', "ioc_report_strict_csv_artifact_id",
                        "ioc_report_broad_csv_artifact_id", "ioc_report_strict_json_artifact_id",
                        "ioc_report_broad_json_artifact_id", "ioc_report_strict_stix_artifact_id",
                        "ioc_report_broad_stix_artifact_id", "ioc_report_strict_maec_artifact_id",
                        "ioc_report_broad_maec_artifact_id"]

    sandbox_filds = ["environment_id", "environment_description", "threat_score", "submit_url", "submission_type",
                     "filetyp", "filesize", "sha256"]
    entry_context = parse_outputs(response, resources_fields=resources_fields, sandbox_filds=sandbox_filds)

    return response, entry_context, response


def get_analysis_status_command(
        client: Client,
        ids: list
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/submissions/v1?ids={ids}"
    params = {
        "ids": ids
    }
    response = client.cs_falconx_http_req("Get", url_suffix, param=params)

    resources_fields = ['id', 'state', 'created_timestamp']
    sandbox_filds = ["environment_id", "sha256"]
    entry_context = parse_outputs(response, resources_fields=resources_fields, sandbox_filds=sandbox_filds)

    return response, entry_context, response


def download_ioc_command(
        client: Client,
        id: str,
        name: str = "",
        accept_encoding: str = ""
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/entities/artifacts/v1?id={id}&name={name}&Accept-Encoding={accept_encoding}"
    params = {
        "ids": id,
        "name": name,
        "Accept-Encoding": accept_encoding,
    }
    response = client.cs_falconx_http_req("Get", url_suffix, param=params)
    return response, {}, response # there is an issue with the entry context here


def check_quota_status_command(
        client: Client
) -> Tuple[str, dict, dict]:
    url_suffix = f"/falconx/entities/submissions/v1?ids="

    response = client.cs_falconx_http_req("Get", url_suffix)

    quota_fields = ['total', 'used', 'in_progress']
    entry_context = parse_outputs(response, quota_fields=quota_fields)

    return response, entry_context, response


def find_sandbox_reports_command(
        client: Client,
        limit: int,
        filter: str = "",
        offset: str = "",
        sort: str = "",
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/queries/reports/v1?filter={filter}&offset={offset}&limit{limit}=&sort={sort}"
    params = {
        "filter": filter,
        "offset": offset,
        "limit": limit,
        "sort": sort,
    }

    response = client.cs_falconx_http_req("Get", url_suffix, param=params)

    resources_fields = ['id']
    entry_context = parse_outputs(response, resources_fields=resources_fields)

    return response, entry_context, response


def find_submission_id_command(
        client: Client,
        limit: int,
        offset: str="",
        filter: str="",
        sort: str = "",
) -> Tuple[str, dict, dict]:

    url_suffix = f"/falconx/queries/submissions/v1?filter={filter}&offset={offset}&limit{limit}=&sort={sort}"

    params = {
        "filter": filter,
        "offset": offset,
        "limit": limit,
        "sort": sort,
    }
    response = client.cs_falconx_http_req("Get", url_suffix, param=params)

    resources_fields = ['id']
    entry_context = parse_outputs(response, resources_fields=resources_fields)

    return response, entry_context, response


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    url = "https://api.crowdstrike.com/"

    try:
        command = demisto.command()
        LOG(f'Command being called in CrowdStrikeFalconX Sandbox is: {command}')
        client = Client(server_url=url, username=username, password=password)
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
            raise NotImplementedError(f'{command} is not an existing CrowdStrikeFalconX command')
    except Exception as err:
        return_error(f'Unexpected error: {str(err)}', error=traceback.format_exc())


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
