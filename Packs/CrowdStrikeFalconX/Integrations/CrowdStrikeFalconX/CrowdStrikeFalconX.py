from typing import Dict, Tuple, List

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
import shutil

# Disable insecure warnings
urllib3.disable_warnings()


def convert_environment_id_string_to_int(
        environment_id: str
) -> int:
    """
    Converting the string that describes the environment id into an int which needed for the http request
    :param environment_id: one of the environment_id options
    :return: environment_id represented by an int
    """
    try:
        environment_id_options = {
            "300: Linux Ubuntu 16.04": 300,
            "200: Android (static analysis)": 200,
            "160: Windows 10": 160,
            "110: Windows 7": 110,
            "100: Windows 7": 100,
            "64-bit": 64,
            "32-bit": 32,
        }
        return environment_id_options[environment_id]
    except Exception:
        raise Exception('Invalid environment id option')


class Client(BaseClient):
    """
    Client to use in the CrowdStrikeFalconX integration. Uses BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str, use_ssl: bool, proxy: bool):
        super().__init__(base_url=server_url, verify=use_ssl, proxy=proxy)
        self._username = username
        self._password = password
        self._token = self._generate_token()
        self._headers = {'Authorization': 'bearer ' + self._token}

    def _generate_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
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

    def upload_file(
            self,
            file: str,
            file_name: str,
            is_confidential: str = "true",
            comment: str = ""
    ) -> dict:
        """Creating the needed arguments for the http request
        :param file: content of the uploaded sample in binary format
        :param file_name: name of the file
        :param is_confidential: defines visibility of this file in Falcon MalQuery, either via the API or the Falcon console
        :param comment: a descriptive comment to identify the file for other users
        :return: http response
        """
        name = demisto.getFilePath(file)['name']
        try:
            shutil.copy(demisto.getFilePath(file)['path'], name)
            with open(name, 'rb') as f:
                url_suffix = f"/samples/entities/samples/v2?file_name={file_name}&is_confidential={is_confidential}" \
                             f"&comment={comment}"
                self._headers['Content-Type'] = 'application/octet-stream'
                shutil.rmtree(file_name, ignore_errors=True)
                return self._http_request("POST", url_suffix, files={'file': f})
        except OSError:
            raise Exception('Failed to prepare file for upload.')
        finally:
            shutil.rmtree(file_name, ignore_errors=True)

    def send_uploaded_file_to_sandbox_analysis(
            self,
            sha256: str,
            environment_id: str,
            action_script: str,
            command_line: str,
            document_password: str,
            enable_tor: str,
            submit_name: str,
            system_date: str,
            system_time: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param sha256: SHA256 ID of the sample, which is a SHA256 hash value
        :param environment_id: specifies the sandbox environment used for analysis
        :param action_script: runtime script for sandbox analysis
        :param command_line: command line script passed to the submitted file at runtime
        :param document_password: auto-filled for Adobe or Office files that prompt for a password
        :param enable_tor: if true, sandbox analysis routes network traffic via TOR
        :param submit_name: name of the malware sample that’s used for file type detection and analysis
        :param system_date: set a custom date in the format yyyy-MM-dd for the sandbox environment
        :param system_time: set a custom time in the format HH:mm for the sandbox environment.
        :return: http response
        """
        url_suffix = "/falconx/entities/submissions/v1"
        body = {
            "sandbox": [
                {
                    "sha256": sha256,
                    "environment_id": convert_environment_id_string_to_int(environment_id),
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
        self._headers['Content-Type'] = 'application/json'
        return self._http_request("POST", url_suffix, json_data=body)

    def send_url_to_sandbox_analysis(
            self,
            url: str,
            environment_id: str,
            action_script: str,
            command_line: str,
            document_password: str,
            enable_tor: str,
            submit_name: str,
            system_date: str,
            system_time: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param url: a web page or file URL. It can be HTTP(S) or FTP.
        :param environment_id: specifies the sandbox environment used for analysis
        :param action_script: runtime script for sandbox analysis
        :param command_line: command line script passed to the submitted file at runtime
        :param document_password: auto-filled for Adobe or Office files that prompt for a password
        :param enable_tor: if true, sandbox analysis routes network traffic via TOR
        :param submit_name: name of the malware sample that’s used for file type detection and analysis
        :param system_date: set a custom date in the format yyyy-MM-dd for the sandbox environment
        :param system_time: set a custom time in the format HH:mm for the sandbox environment.
        :return: http response
        """
        url_suffix = "/falconx/entities/submissions/v1"
        body = {
            "sandbox": [
                {
                    "url": url,
                    "environment_id": convert_environment_id_string_to_int(environment_id),
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
        self._headers['Content-Type'] = 'application/json'
        return self._http_request("POST", url_suffix, json_data=body)

    def get_full_report(
            self,
            id: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param id: id of a submitted malware samples.
        :return: http response
        """
        url_suffix = f"/falconx/entities/reports/v1?ids={id}"
        params = {
            "ids": id
        }
        return self._http_request("Get", url_suffix, params=params)

    def get_report_summary(
            self,
            id: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param id: id of a submitted malware samples.
        :return: http response
        """
        url_suffix = f"/falconx/entities/report-summaries/v1?ids={id}"
        params = {
            "ids": id
        }
        return self._http_request("Get", url_suffix, params=params)

    def get_analysis_status(
            self,
            ids: list
    ) -> dict:
        """Creating the needed arguments for the http request
        :param ids: ids of a submitted malware samples.
        :return: http response
        """
        url_suffix = f"/falconx/entities/submissions/v1?ids={ids}"
        params = {
            "ids": ids
        }
        return self._http_request("Get", url_suffix, params=params)

    def download_ioc(
            self,
            id: str,
            name: str,
            accept_encoding: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param id: id of an artifact, such as an IOC pack, PCAP file, or actor image
        :param name: the name given to your downloaded file
        :param accept_encoding: format used to compress your downloaded file
        :return: http response
        """
        url_suffix = f"/falconx/entities/artifacts/v1?id={id}&name={name}&Accept-Encoding={accept_encoding}"
        params = {
            "ids": id,
            "name": name,
            "Accept-Encoding": accept_encoding,
        }
        return self._http_request("Get", url_suffix, params=params)

    def check_quota_status(
            self
    ) -> dict:
        """Creating the needed arguments for the http request
        :return: http response
        """
        url_suffix = f"/falconx/entities/submissions/v1?ids="
        return self._http_request("Get", url_suffix)

    def find_sandbox_reports(
            self,
            limit: int,
            filter: str,
            offset: str,
            sort: str,
    ) -> dict:
        """Creating the needed arguments for the http request
        :param limit: maximum number of report IDs to return
        :param filter: optional filter and sort criteria in the form of an FQL query
        :param offset: the offset to start retrieving reports from.
        :param sort: sort order: asc or desc
        :return: http response
        """
        url_suffix = f"/falconx/queries/reports/v1?filter={filter}&offset={offset}&limit{limit}=&sort={sort}"
        params = {
            "filter": filter,
            "offset": offset,
            "limit": limit,
            "sort": sort,
        }
        return self._http_request("Get", url_suffix, params=params)

    def find_submission_id(
            self,
            limit: int,
            filter: str,
            offset: str,
            sort: str,
    ) -> dict:
        """Creating the needed arguments for the http request
        :param limit: maximum number of report IDs to return
        :param filter: optional filter and sort criteria in the form of an FQL query
        :param offset: the offset to start retrieving reports from.
        :param sort: sort order: asc or desc
        :return: http response
        """
        url_suffix = f"/falconx/queries/submissions/v1?filter={filter}&offset={offset}&limit{limit}=&sort={sort}"

        params = {
            "filter": filter,
            "offset": offset,
            "limit": limit,
            "sort": sort,
        }
        return self._http_request("Get", url_suffix, params=params)


def add_outputs_from_dict(
        api_current_dict: dict,
        fields_to_keep: list
) -> dict:
    """
    Filters a dict and keeps only the keys that appears in the given list
    :param api_current_dict: the origin dict
    :param fields_to_keep: the list which contains the wanted keys
    :return: a dict based on api_current_dict without the keys that doesn't appear in fields_to_keep
    """
    if not api_current_dict or not fields_to_keep:
        return {}

    group_outputs = {}

    for field_to_keep in fields_to_keep:
        if field_to_keep in api_current_dict.keys():
            group_outputs[field_to_keep] = api_current_dict.get(field_to_keep)

    return group_outputs


def parse_outputs(
        api_res: dict,
        meta_fields: list = [],
        quota_fields: list = [],
        resources_fields: list = [],
        sandbox_fields: list = []
) -> Dict[str, dict]:
    """Parse group data as received from CrowdStrike FalconX API into Demisto's conventions
    the output from the API is a dict that contains the keys: meta, resources and errors
    the meta contains a "quota" dict
    the "resources" is an array that contains the sandbox dict
    the function filters the wanted params from the api result
    :param api_res: the api result from the http request
    :param meta_fields: the wanted params that appear in the mate section
    :param quota_fields: the wanted params that appear in the quota section
    :param resources_fields: the wanted params that appear in the resources section
    :param sandbox_fields: the wanted params that appear in the sandbox section
    :return: a dict based on api_res with the wanted params only
    """
    error = api_res.get("errors")
    if error:
        # if there is an error in the api result, return only the error
        return error[0]

    api_res_quota, api_res_resources, api_res_sandbox = {}, {}, {}
    resources_group_outputs, sandbox_group_outputs = {}, {}

    api_res_meta = api_res.get("meta")
    if api_res_meta:
        api_res_quota = api_res_meta.get("quota")

    meta_group_outputs = add_outputs_from_dict(api_res_meta, meta_fields)
    quota_group_outputs = add_outputs_from_dict(api_res_quota, quota_fields)

    resources = api_res.get("resources")
    if resources:
        # depended on the command, the resources section can be a str list or a list that contains
        # only one argument which is a dict
        if type(resources[0]) == dict:
            api_res_resources = resources[0]
            resources_group_outputs = add_outputs_from_dict(api_res_resources, resources_fields)

            sandbox = api_res_resources.get("sandbox")
            if api_res_resources and sandbox:
                api_res_sandbox = sandbox[0]
                sandbox_group_outputs = add_outputs_from_dict(api_res_sandbox, sandbox_fields)
        else:
            # the resources section is a list of strings
            resources_group_outputs = {"resources": api_res.get("resources")}

    merged_dicts = {**meta_group_outputs, **quota_group_outputs, **resources_group_outputs, **sandbox_group_outputs}

    return merged_dicts


def test_module(
        client: Client,
) -> Tuple[str, dict, list]:
    """
    If a client was made then an accesses token was successfully reached,
    therefor the username and password are valid and a connection was made
    additionally, checks if not using all the optional quota
    :param client: the client object with an access token
    :return: ok if got a valid accesses token and not all the quota is used at the moment
    """
    output = client.check_quota_status()

    error = output.get("errors")
    if error:
        return error[0]

    meta = output.get("meta")
    if meta is not None:
        quota = meta.get("quota")
        if quota is not None:
            total = quota.get("total")
            used = quota.get("used")
            if total <= used:
                raise Exception(f"Quota limitation has been reached: {used}")
            else:
                return 'ok', {}, []
    raise Exception("Quota limitation is unreachable")


def upload_file_command(
        client: Client,
        file: str,
        file_name: str,
        is_confidential: str = "true",
        comment: str = "",
        submit_file: str = "no"
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Upload a file for sandbox analysis.
    :param client: the client object with an access token
    :param file: content of the uploaded sample in binary format
    :param file_name: name of the file
    :param is_confidential: defines visibility of this file in Falcon MalQuery, either via the API or the Falcon console
    :param comment: a descriptive comment to identify the file for other users
    :param submit_file: if "yes" run cs-fx-submit-uploaded-file for the uploaded file
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.upload_file(file, file_name, is_confidential, comment)

    resources_fields = ["file_name", "sha256"]
    filtered_outputs = parse_outputs(response, resources_fields=resources_fields)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    if submit_file == "no":
        return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs), entry_context, [response]

    else:
        sha256 = str(filtered_outputs.get("sha256"))
        return send_uploaded_file_to_sandbox_analysis_command(client, sha256, "160: Windows 10")


def send_uploaded_file_to_sandbox_analysis_command(
        client: Client,
        sha256: str,
        environment_id: str,
        action_script: str = "",
        command_line: str = "",
        document_password: str = "",
        enable_tor: str = "false",
        submit_name: str = "",
        system_date: str = "",
        system_time: str = ""
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Submit a sample SHA256 for sandbox analysis.
    :param client: the client object with an access token
    :param sha256: SHA256 ID of the sample, which is a SHA256 hash value
    :param environment_id: specifies the sandbox environment used for analysis
    :param action_script: runtime script for sandbox analysis
    :param command_line: command line script passed to the submitted file at runtime
    :param document_password: auto-filled for Adobe or Office files that prompt for a password
    :param enable_tor: if true, sandbox analysis routes network traffic via TOR
    :param submit_name: name of the malware sample that’s used for file type detection and analysis
    :param system_date: set a custom date in the format yyyy-MM-dd for the sandbox environment
    :param system_time: set a custom time in the format HH:mm for the sandbox environment.
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.send_uploaded_file_to_sandbox_analysis(sha256, environment_id, action_script, command_line,
                                                             document_password, enable_tor, submit_name, system_date,
                                                             system_time)

    sandbox_fields = ["environment_id", "sha256"]
    resource_fields = ['id', 'state', 'created_timestamp', 'created_timestamp']
    filtered_outputs = parse_outputs(response, sandbox_fields=sandbox_fields, resources_fields=resource_fields)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs), entry_context, [response]


def send_url_to_sandbox_analysis_command(
        client: Client,
        url: str,
        environment_id: str,
        action_script: str = "",
        command_line: str = "",
        document_password: str = "",
        enable_tor: str = "false",
        submit_name: str = "",
        system_date: str = "",
        system_time: str = ""
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Submit a URL or FTP for sandbox analysis.
    :param client: the client object with an access token
    :param url: a web page or file URL. It can be HTTP(S) or FTP.
    :param environment_id: specifies the sandbox environment used for analysis
    :param action_script: runtime script for sandbox analysis
    :param command_line: command line script passed to the submitted file at runtime
    :param document_password: auto-filled for Adobe or Office files that prompt for a password
    :param enable_tor: if true, sandbox analysis routes network traffic via TOR
    :param submit_name: name of the malware sample that’s used for file type detection and analysis
    :param system_date: set a custom date in the format yyyy-MM-dd for the sandbox environment
    :param system_time: set a custom time in the format HH:mm for the sandbox environment.
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.send_url_to_sandbox_analysis(url, environment_id, action_script, command_line, document_password,
                                                   enable_tor, submit_name, system_date, system_time)

    resources_fields = ['id', 'state', 'created_timestamp']
    sandbox_fields = ["environment_id", "sha256"]
    filtered_outputs = parse_outputs(response, resources_fields=resources_fields, sandbox_fields=sandbox_fields)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs), entry_context, [response]


def get_full_report_command(
        client: Client,
        ids: list
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Get a full version of a sandbox report.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """
    ids_list = argToList(ids)
    filtered_outputs_list = []
    response_list = []

    for single_id in ids_list:
        response = client. get_full_report(single_id)
        response_list.append(response)

        resources_fields = ['id', 'verdict', 'created_timestamp', "ioc_report_strict_csv_artifact_id",
                            "ioc_report_broad_csv_artifact_id", "ioc_report_strict_json_artifact_id",
                            "ioc_report_broad_json_artifact_id", "ioc_report_strict_stix_artifact_id",
                            "ioc_report_broad_stix_artifact_id", "ioc_report_strict_maec_artifact_id",
                            "ioc_report_broad_maec_artifact_id"]

        sandbox_fields = ["environment_id", "environment_description", "threat_score", "submit_url", "submission_type",
                          "filetyp", "filesize", "sha256"]
        filtered_outputs_list.append(parse_outputs(response, resources_fields=resources_fields,
                                                   sandbox_fields=sandbox_fields))

    entry_context = {f'csfalconx.resource(val.id === obj.id)': filtered_outputs_list}
    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs_list), entry_context, response_list


def get_report_summary_command(
        client: Client,
        ids: list
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Get a short summary version of a sandbox report.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """
    filtered_outputs_list = []
    response_list = []
    ids_list = argToList(ids)

    for single_id in ids_list:
        response = client.get_report_summary(single_id)
        response_list.append(response)

        resources_fields = [
            'id', 'verdict', 'created_timestamp', "ioc_report_strict_csv_artifact_id",
            "ioc_report_broad_csv_artifact_id", "ioc_report_strict_json_artifact_id",
            "ioc_report_broad_json_artifact_id", "ioc_report_strict_stix_artifact_id",
            "ioc_report_broad_stix_artifact_id", "ioc_report_strict_maec_artifact_id",
            "ioc_report_broad_maec_artifact_id"
        ]

        sandbox_fields = ["environment_id", "environment_description", "threat_score", "submit_url", "submission_type",
                          "filetyp", "filesize", "sha256"]
        filtered_outputs_list.append(parse_outputs(response, resources_fields=resources_fields,
                                                   sandbox_fields=sandbox_fields))

    entry_context = {f'csfalconx.resource(val.id === obj.id)': filtered_outputs_list}
    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs_list), entry_context, response_list


def get_analysis_status_command(
        client: Client,
        ids: list
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Check the status of a sandbox analysis.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """
    filtered_outputs_list = []
    response_list = []
    ids_list = argToList(ids)

    for single_id in ids_list:
        response = client.get_analysis_status(single_id)
        response_list.append(response)

        resources_fields = ['id', 'state', 'created_timestamp']
        sandbox_fields = ["environment_id", "sha256"]
        filtered_outputs_list.append(parse_outputs(response, resources_fields=resources_fields,
                                                   sandbox_fields=sandbox_fields))

    entry_context = {f'csfalconx.resource(val.id === obj.id)': filtered_outputs_list}
    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs_list), entry_context, response_list


def download_ioc_command(
        client: Client,
        id: str,
        name: str = "",
        accept_encoding: str = ""
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Download IOC packs, PCAP files, and other analysis artifacts.
    :param client: the client object with an access token
    :param id: id of an artifact, such as an IOC pack, PCAP file, or actor image
    :param name: the name given to your downloaded file
    :param accept_encoding: format used to compress your downloaded file
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.download_ioc(id, name, accept_encoding)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [response]}

    return tableToMarkdown("CrowdStrike Falcon X response:", response), entry_context, [response]


def check_quota_status_command(
        client: Client
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Search endpoint contains File Hash.
    :param client: the client object with an access token
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.check_quota_status()
    quota_fields = ['total', 'used', 'in_progress']

    filtered_outputs = parse_outputs(response, quota_fields=quota_fields)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs), entry_context, [response]


def find_sandbox_reports_command(
        client: Client,
        limit: int = 50,
        filter: str = "",
        offset: str = "",
        sort: str = "",
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Find sandbox reports by providing an FQL filter and paging details.
    :param client: the client object with an access token
    :param limit: maximum number of report IDs to return
    :param filter: optional filter and sort criteria in the form of an FQL query
    :param offset: the offset to start retrieving reports from.
    :param sort: sort order: asc or desc
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.find_sandbox_reports(limit, filter, offset, sort)
    resources_fields = ['id']

    filtered_outputs = parse_outputs(response, resources_fields=resources_fields)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs), entry_context, [response]


def find_submission_id_command(
        client: Client,
        limit: int = 50,
        filter: str = "",
        offset: str = "",
        sort: str = "",
) -> Tuple[str, Dict[str, List[Dict[str, dict]]], List[dict]]:
    """Find submission IDs for uploaded files by providing an FQL filter and paging details.
    :param client: the client object with an access token
    :param limit: maximum number of report IDs to return
    :param filter: optional filter and sort criteria in the form of an FQL query
    :param offset: the offset to start retrieving reports from.
    :param sort: sort order: asc or desc
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.find_submission_id(limit, filter, offset, sort)

    resources_fields = ['id']
    filtered_outputs = parse_outputs(response, resources_fields=resources_fields)
    entry_context = {f'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    return tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs), entry_context, [response]


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    url = "https://api.crowdstrike.com/"
    try:
        command = demisto.command()
        LOG(f'Command being called in CrowdStrikeFalconX Sandbox is: {command}')
        client = Client(server_url=url, username=username, password=password, use_ssl=use_ssl, proxy=proxy)
        commands = {
            'test-module': test_module,
            'cs-fx-upload-file': upload_file_command,
            'cs-fx-submit-uploaded-file': send_uploaded_file_to_sandbox_analysis_command,
            'cs-fx-submit-url': send_url_to_sandbox_analysis_command,
            'cs-fx-get-full-report': get_full_report_command,
            'cs-fx-get-report-summary': get_report_summary_command,
            'cs-fx-get-analysis-status': get_analysis_status_command,
            'cs-fx-download-ioc': download_ioc_command,
            'cs-fx-check-quota': check_quota_status_command,
            'cs-fx-find-reports': find_sandbox_reports_command,
            'cs-fx-find-submission-id': find_submission_id_command
        }
        if command in commands:
            return_outputs(*commands[command](client, **demisto.args()))  # type: ignore[operator]
        else:
            raise NotImplementedError(f'{command} is not an existing CrowdStrike Falcon X command')
    except Exception as err:
        return_error(f'Unexpected error: {str(err)}', error=traceback.format_exc())


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
