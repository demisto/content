from typing import Callable

import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

DBOT_SCORE_DICT = {'malicious': Common.DBotScore.BAD,
                   'suspicious': Common.DBotScore.SUSPICIOUS,
                   'no specific threat': Common.DBotScore.GOOD}


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


class Client:
    """
    Client to use in the CrowdStrikeFalconX integration. Uses BaseClient
    """

    def __init__(self, server_url: str, username: str, password: str, use_ssl: bool, proxy: bool, reliability: str):
        self._base_url = server_url
        self._verify = use_ssl
        self._ok_codes = tuple()  # type: ignore[var-annotated]
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._token = self._generate_token()
        self._headers = {'Authorization': 'bearer ' + self._token}
        self.reliability = reliability
        if not proxy:
            self._session.trust_env = False

    @staticmethod
    def _handle_errors(errors: list) -> str:
        """
        Converting the errors of the API to a string, in case there are no error, return an empty string
        :param errors: each error is a dict with the keys code and message
        :return: errors converted to single str
        """
        return '\n'.join(f"{error['code']}: {error['message']}" for error in errors)

    def _is_status_code_valid(self, response, ok_codes=None):
        """If the status code is OK, return 'True'.

        :type response: ``requests.Response``
        :param response: Response from API after the request for which to check the status.

        :type ok_codes: ``tuple`` or ``list``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204). If you specify
            "None", will use response.ok.

        :return: Whether the status of the response is valid.
        :rtype: ``bool``
        """
        # Get wanted ok codes
        status_codes = ok_codes if ok_codes else self._ok_codes
        if status_codes:
            return response.status_code in status_codes
        return response.ok

    def _http_request(self, method, url_suffix, full_url=None, headers=None,
                      json_data=None, params=None, data=None, files=None,
                      timeout=10, ok_codes=None, return_empty_response=False):
        """A wrapper for requests lib to send our requests and handle requests and responses better.

        :type method: ``str``
        :param method: The HTTP method, for example: GET, POST, and so on.

        :type url_suffix: ``str``
        :param url_suffix: The API endpoint.

        :type full_url: ``str``
        :param full_url:
            Bypasses the use of self._base_url + url_suffix. This is useful if you need to
            make a request to an address outside of the scope of the integration
            API.

        :type headers: ``dict``
        :param headers: Headers to send in the request. If None, will use self._headers.

        :type params: ``dict``
        :param params: URL parameters to specify the query.

        :type data: ``dict``
        :param data: The data to send in a 'POST' request.

        :type json_data: ``dict``
        :param json_data: The dictionary to send in a 'POST' request.

        :type files: ``dict``
        :param files: The file data to send in a 'POST' request.

        :type timeout: ``float`` or ``tuple``
        :param timeout:
            The amount of time (in seconds) that a request will wait for a client to
            establish a connection to a remote machine before a timeout occurs.
            can be only float (Connection Timeout) or a tuple (Connection Timeout, Read Timeout).

        :type ok_codes: ``tuple``
        :param ok_codes:
            The request codes to accept as OK, for example: (200, 201, 204). If you specify
            "None", will use self._ok_codes.

        :return: Depends on the resp_type parameter
        :rtype: ``dict`` or ``str`` or ``requests.Response``
        """
        try:
            # Replace params if supplied
            address = full_url if full_url else urljoin(self._base_url, url_suffix)
            headers = headers if headers else self._headers
            # Execute
            res = self._session.request(
                method,
                address,
                verify=self._verify,
                params=params,
                data=data,
                json=json_data,
                files=files,
                headers=headers,
                timeout=timeout,
            )
            # Handle error responses gracefully
            if not self._is_status_code_valid(res, ok_codes):
                err_msg = ""
                try:
                    # Try to parse json error response
                    error_entry = res.json()
                    err_msg += self._handle_errors(error_entry.get("errors"))
                    raise DemistoException(err_msg)
                except ValueError:
                    raise DemistoException(f'{err_msg}\n{res.text}' if err_msg else res.text)

            is_response_empty_and_successful = (res.status_code == 204)
            if is_response_empty_and_successful and return_empty_response:
                return res

            try:
                return res.json()
            except ValueError as exception:
                raise DemistoException("Failed to parse json object from response:" + str(res.content), exception)
        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.SSLError as exception:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise DemistoException(err_msg, exception)
        except requests.exceptions.ConnectionError as exception:
            # Get originating Exception in Exception chain
            error_class = str(exception.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = '\nError Type: {}\nError Number: [{}]\nMessage: {}\n' \
                      'Verify that the server URL parameter' \
                      ' is correct and that you have access to the server from your host.' \
                .format(err_type, exception.errno, exception.strerror)
            raise DemistoException(err_msg, exception)

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
        get_file_path_res = demisto.getFilePath(file)
        file_path = get_file_path_res["path"]
        file_name = get_file_path_res["name"]

        url_suffix = f"/samples/entities/samples/v2?file_name={file_name}&is_confidential={is_confidential}" \
                     f"&comment={comment}"
        self._headers['Content-Type'] = 'application/octet-stream'
        file_data = open(file_path, 'rb')
        res = self._http_request("POST", url_suffix, data=file_data)
        file_data.close()
        return res

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
        url_suffix = "/falconx/entities/submissions/v1?ids="
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


def keep_dict_keys(
        dictionary: dict,
        fields_to_keep: Optional[list]
) -> dict:
    """
    Filters a dict and keeps only the keys that appears in the given list
    :param dictionary: the origin dict
    :param fields_to_keep: the list which contains the wanted keys
    :return: a dict based on api_current_dict without the keys that doesn't appear in fields_to_keep
    """
    return {k: v for k, v in dictionary.items() if k in (fields_to_keep or [])}


def parse_outputs(
        response: dict,
        reliability: str,
        meta_fields: Optional[list] = None,
        quota_fields: Optional[list] = None,
        resources_fields: Optional[list] = None,
        sandbox_fields: Optional[list] = None,
        extra_sandbox_fields: Optional[list] = None,
) -> tuple[dict[str, dict], Optional[Common.Indicator]]:
    """Parse group data as received from CrowdStrike FalconX API matching Demisto conventions
    the output from the API is a dict that contains the keys: meta, resources_list and errors
    the meta contains a "quota" dict
    the "resources_list" is an array that contains the sandbox dict
    the function filters the wanted params from the api result
    :param response: the api result from the http request
    :param meta_fields: the wanted params that appear in the mate section
    :param reliability: a string representing the assumed reliability of this integration instance
    :param quota_fields: the wanted params that appear in the quota section
    :param resources_fields: the wanted params that appear in the resources_list section
    :param sandbox_fields: the wanted params that appear in the sandbox section
    :param extra_sandbox_fields: the wanted params that appear in the extra sandbox section
    :return: a dict based on api_res with the wanted params only
    """
    result, indicator = {}, None

    if api_res_meta := response.get("meta", dict()):
        result |= keep_dict_keys(api_res_meta, meta_fields)
        result |= keep_dict_keys(api_res_meta.get("quota", {}), quota_fields)

    if resources_list := response.get("resources"):
        # depends on the command, the resources_list section can be a list[str] or list of only one dict
        if isinstance(resources_list[0], dict):
            resources = resources_list[0]
            resources_group_outputs = keep_dict_keys(resources, resources_fields)

            if sandbox := resources.get("sandbox", [{}])[0]:
                result |= keep_dict_keys(sandbox, sandbox_fields)

                extra_sandbox_group_outputs = keep_dict_keys(sandbox, extra_sandbox_fields)
                for process in extra_sandbox_group_outputs.get('processes', []):
                    if process.get('registry'):
                        process.pop('registry')
                if extra_sandbox_group_outputs:
                    resources_group_outputs['sandbox'] = extra_sandbox_group_outputs
                indicator = parse_indicator(resources, reliability)

        else:
            # the resources_list section is a list of strings
            resources_group_outputs = {"resources_list": response.get("resources")}

        result |= resources_group_outputs

    return result, indicator  # todo populate with indicators


def parse_indicator(sandbox: dict, reliability: str) -> Optional[Common.File]:
    if sha256 := sandbox.get('sha256'):  # does the `if` make sense here?
        score_field = DBOT_SCORE_DICT.get(sandbox.get('verdict'),
                                          Common.DBotScore.NONE)

        dbot = Common.DBotScore(indicator=sha256,  # todo sha256 or name?
                                indicator_type=DBotScoreType.FILE,
                                score=score_field,
                                reliability=DBotScoreReliability.get_dbot_score_reliability_from_str(reliability))

        info = {item['id']: item['value'] for item in sandbox.get('version_info', [])}

        return Common.File(dbot_score=dbot,
                           name=sandbox.get('submit_name'),
                           size=sandbox.get('file_size'),
                           file_type=sandbox.get('file_type'),
                           company=info.get('CompanyName'),
                           product_name=info.get('ProductName'),
                           signature=Common.FileSignature(authentihash='',  # todo
                                                          copyright='',  # todo
                                                          description=info.get('FileDescription', ''),
                                                          file_version=info.get('FileVersion', ''),
                                                          internal_name=info.get('InternalName', ''),
                                                          original_name=info.get('OriginalFilename', '')))


def test_module(
        client: Client,
) -> tuple[str, dict, list]:
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
        submit_file: str = "no",
):
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
    filtered_outputs, indicator = parse_outputs(response, client.reliability, resources_fields=resources_fields)
    if submit_file == 'no':
        return CommandResults(
            outputs_key_field='sha256',
            outputs_prefix='csfalconx.resource',
            outputs=[filtered_outputs],
            readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs),
            raw_response=[response],
            indicators=[indicator])

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
):
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
    filtered_outputs, indicator = parse_outputs(response, reliability=client.reliability,
                                                sandbox_fields=sandbox_fields, resources_fields=resource_fields)
    # in order identify the id source, upload or submit command, the id name changed
    filtered_outputs["submitted_id"] = filtered_outputs.pop("id")

    return CommandResults(
        outputs_key_field='submitted_id',
        outputs_prefix='csfalconx.resource',
        outputs=filtered_outputs,
        readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs),
        raw_response=[response],
        indicators=[indicator]
    )


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
):
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
    filtered_outputs, indicator = parse_outputs(response, client.reliability,
                                                resources_fields=resources_fields, sandbox_fields=sandbox_fields)
    # in order identify the id source, upload or submit command, the id name changed
    filtered_outputs["submitted_id"] = filtered_outputs.pop("id")

    return CommandResults(
        outputs_key_field='submitted_id',
        outputs_prefix='csfalconx.resource',
        outputs=[filtered_outputs],
        readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs),
        raw_response=[response],
        indicators=[indicator])


def arrange_output_for_hr(filtered_outputs_list):
    res_hr_list: list = []
    hr_fields = ['sha256', 'environment_description', 'environment_id', 'created_timestamp', 'id', 'submission_type',
                 'threat_score', 'verdict']
    for output in filtered_outputs_list:
        output_for_hr: dict = {}
        for field in hr_fields:
            output_for_hr[field] = output.get(field)
        res_hr_list.append(output_for_hr)
    return res_hr_list, hr_fields


def get_full_report_command(client: Client, ids: list, extended_data: str):
    """Get a full version of a sandbox report.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :param extended_data: Whether to return extended data which includes mitre attacks and signature information.
    :param polling: Whether is polling call this function.
    :return: Demisto outputs when entry_context and responses are lists
    """
    ids_list = argToList(ids)
    filtered_outputs_list = []
    response_list = []
    is_command_finished: bool = False

    for single_id in ids_list:
        response = client.get_full_report(single_id)
        if response.get('resources'):
            is_command_finished = True
        response_list.append(response)

        resources_fields = ['id', 'verdict', 'created_timestamp', "ioc_report_strict_csv_artifact_id",
                            "ioc_report_broad_csv_artifact_id", "ioc_report_strict_json_artifact_id",
                            "ioc_report_broad_json_artifact_id", "ioc_report_strict_stix_artifact_id",
                            "ioc_report_broad_stix_artifact_id", "ioc_report_strict_maec_artifact_id",
                            "ioc_report_broad_maec_artifact_id", 'tags', "intel"]

        sandbox_fields = [
            "environment_id", "environment_description", "threat_score", "submit_url", "submission_type", "filetype",
            "filesize", "sha256"
        ]
        extra_sandbox_fields = [
            "processes", "architecture", "classification", "classification_tags", "http_requests",
            "extracted_files", "file_metadata", "file_size", "file_type", "file_type_short", "packer", "incidents",
            "submit_name", "screenshots_artifact_ids", "dns_requests", "contacted_hosts", "contacted_hosts"
        ]

        if extended_data == 'true':
            extra_sandbox_fields.extend(["mitre_attacks", "signatures"])

        output, indicator = parse_outputs(response, reliability=client.reliability,
                                          resources_fields=resources_fields, sandbox_fields=sandbox_fields,
                                          extra_sandbox_fields=extra_sandbox_fields)
        filtered_outputs_list.append(output)

    filtered_outputs_list_for_hr, hr_fields = arrange_output_for_hr(filtered_outputs_list)

    if filtered_outputs_list:
        readable_output = tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs_list_for_hr, hr_fields)
    else:
        readable_output = 'There are no results yet, the sample might still being analyzed.' \
                          ' Please wait to download the report.\n' \
                          'You can use cs-fx-get-analysis-status to check the status of a sandbox analysis.'

    command_result = CommandResults(
        outputs_key_field='id',
        outputs_prefix='csfalconx.resource',
        outputs=filtered_outputs_list,
        readable_output=readable_output,
        raw_response=[response_list]
    )
    return command_result, is_command_finished


def get_report_summary_command(
        client: Client,
        ids: list
) -> CommandResults:
    """Get a short summary version of a sandbox report.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """
    filtered_outputs_list = []
    indicators = []
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
                          "filetype", "filesize", "sha256"]
        outputs, indicator = parse_outputs(response, reliability=client.reliability,
                                           resources_fields=resources_fields, sandbox_fields=sandbox_fields)
        filtered_outputs_list.append(outputs)
        indicators.append(indicator)

    no_outputs_msg = 'There are no results yet, the sample might still be going through analysis.' \
                     ' Please wait to download the report.\n' \
                     'You can use cs-fx-get-analysis-status to check the status of a sandbox analysis.'

    filtered_outputs_list = list(filter(None, filtered_outputs_list))
    indicators = list(filter(None, indicators))

    return CommandResults(outputs_key_field='sha256',  # todo is this still correct?
                          outputs_prefix='csfalconx.resource',
                          outputs=filtered_outputs_list,
                          readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs_list)
                          if filtered_outputs_list else no_outputs_msg,
                          raw_response=response_list,
                          indicators=indicators)


def get_analysis_status_command(
        client: Client,
        ids: list
) -> CommandResults:
    """Check the status of a sandbox analysis.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """
    filtered_outputs_list = []
    response_list = []
    indicators = []
    ids_list = argToList(ids)

    for single_id in ids_list:
        response = client.get_analysis_status(single_id)
        response_list.append(response)

        resources_fields = ['id', 'state', 'created_timestamp']
        sandbox_fields = ["environment_id", "sha256"]
        outputs, indicator = parse_outputs(response, reliability=client.reliability,
                                           resources_fields=resources_fields, sandbox_fields=sandbox_fields)
        filtered_outputs_list.append(outputs)
        indicators.append(indicator)

    filtered_outputs_list = list(filter(None, filtered_outputs_list))
    indicators = list(filter(None, indicators))

    return CommandResults(outputs_key_field='sha256',  # todo is this still correct?
                          outputs_prefix='csfalconx.resource',
                          outputs=filtered_outputs_list,
                          readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs_list),
                          raw_response=response_list,
                          indicators=indicators)


def download_ioc_command(
        client: Client,
        id: str,
        name: str = "",
        accept_encoding: str = ""
) -> tuple[str, dict[str, list[dict[str, dict]]], list[dict]]:
    """Download IOC packs, PCAP files, and other analysis artifacts.
    :param client: the client object with an access token
    :param id: id of an artifact, such as an IOC pack, PCAP file, or actor image
    :param name: the name given to your downloaded file
    :param accept_encoding: format used to compress your downloaded file
    :return: Demisto outputs when entry_context and responses are lists
    """
    response: dict = {}
    try:
        response = client.download_ioc(id, name, accept_encoding)
    except Exception as a:
        demisto.debug(f'Download ioc exception {a}')

    entry_context = {'csfalconx.resource(val.id === obj.id)': [response]}

    return tableToMarkdown("CrowdStrike Falcon X response:", response), entry_context, [response]


def check_quota_status_command(
        client: Client
) -> CommandResults:
    """Search endpoint contains File Hash.
    :param client: the client object with an access token
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.check_quota_status()
    quota_fields = ['total', 'used', 'in_progress']

    filtered_outputs, indicator = parse_outputs(response, client.reliability, quota_fields=quota_fields)

    return CommandResults(outputs_prefix='csfalconx.resource',
                          # todo key field?
                          indicators=[indicator] if indicator else [],
                          readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs),
                          raw_response=response,
                          outputs=[filtered_outputs] if filtered_outputs else [])


def find_sandbox_reports_command(
        client: Client,
        limit: int = 50,
        filter: str = "",
        offset: str = "",
        sort: str = "",
) -> CommandResults:
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

    filtered_outputs, indicator = parse_outputs(response, reliability=client.reliability,
                                                resources_fields=resources_fields)  # todo use indicator
    entry_context = {'csfalconx.resource(val.id === obj.id)': [filtered_outputs]}

    return CommandResults(outputs_key_field='sha256',  # todo is this still correct?
                          outputs_prefix='csfalconx.resource',
                          outputs=[filtered_outputs],
                          readable_output=tableToMarkdown("CrowdStrike Falcon X response:", [filtered_outputs]),
                          raw_response=response,
                          indicators=[indicator])


def find_submission_id_command(
        client: Client,
        limit: int = 50,
        filter: str = "",
        offset: str = "",
        sort: str = "",
) -> CommandResults:
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
    filtered_outputs, indicator = parse_outputs(response, reliability=client.reliability,
                                                resources_fields=resources_fields)

    return CommandResults(outputs_key_field='sha256',  # todo is this still correct?
                          outputs_prefix='csfalconx.resource',
                          outputs=filtered_outputs,
                          readable_output=tableToMarkdown("CrowdStrike Falcon X response:", filtered_outputs),
                          raw_response=[response],
                          indicators=[indicator] if indicator else [])


def get_results_function_args(outputs, extended_data, item_type, interval_in_secs):
    if isinstance(outputs, list):
        outputs = outputs[0]

    results_function_args: dict = {
        'ids': outputs.get('submitted_id'),
        'extended_data': extended_data,
        'interval_in_seconds': interval_in_secs,
        'polling': True,
    }
    if item_type == 'FILE':
        results_function_args['submit_file'] = 'yes'

    return results_function_args


def pop_polling_related_args(args):
    for key in ('submit_file', 'enable_tor', 'interval_in_seconds', 'polling'):
        args.pop(key, None)


def is_new_polling_search(args):
    """
    Check if the polling func is a new search or in the polling flow.
    if there ids argument in the args dict its mean that the first search is finished and we should run the polling flow
    """
    return not args.get('ids')


def arrange_args_for_upload_func(args):
    args.pop('polling')
    args.pop('interval_in_seconds')
    extended_data = args.pop('extended_data')
    return extended_data


def run_polling_command(client, args: dict, cmd: str, upload_function: Callable, results_function: Callable, item_type):
    """
    This function is generically handling the polling flow. In the polling flow, there is always an initial call that
    starts the uploading to the API (referred here as the 'upload' function) and another call that retrieves the status
    of that upload (referred here as the 'results' function).
    The run_polling_command function runs the 'upload' function and returns a ScheduledCommand object that schedules
    the next 'results' function, until the polling is complete.
    Args:
        item_type: the item type to handle the args according.
        client: the CS FX client.
        args: the arguments required to the command being called, under cmd
        cmd: the command to schedule by after the current command
        upload_function: the function that initiates the uploading to the API
        results_function: the function that retrieves the status of the previously initiated upload process

    Returns:

    """
    ScheduledCommand.raise_error_if_not_supported()
    interval_in_secs = int(args.get('interval_in_seconds', 600))
    # distinguish between the initial run, which is the upload run, and the results run
    if is_new_polling_search(args):
        # create new search
        extended_data = arrange_args_for_upload_func(args)
        command_results = upload_function(client, **args)
        outputs = command_results.outputs
        results_function_args = get_results_function_args(outputs, extended_data, item_type, interval_in_secs)
        # schedule next poll
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=results_function_args,
            timeout_in_seconds=6000)
        command_results.scheduled_command = scheduled_command
        return command_results

    # not a new search, get search status
    pop_polling_related_args(args)
    command_result, status = results_function(client, **args)
    if not status:
        # schedule next poll
        polling_args = {
            'interval_in_seconds': interval_in_secs,
            'polling': True,
            **args
        }
        scheduled_command = ScheduledCommand(
            command=cmd,
            next_run_in_seconds=interval_in_secs,
            args=polling_args,
            timeout_in_seconds=6000)

        command_result = CommandResults(scheduled_command=scheduled_command)
    return command_result


def upload_file_with_polling_command(client, args):
    return run_polling_command(client, args, 'cs-fx-upload-file', upload_file_command, get_full_report_command, 'FILE')


def submit_uploaded_file_polling_command(client, args):
    return run_polling_command(client, args, 'cs-fx-submit-uploaded-file',
                               send_uploaded_file_to_sandbox_analysis_command, get_full_report_command, 'FILE')


def submit_uploaded_url_polling_command(client, args):
    return run_polling_command(client, args, 'cs-fx-submit-url', send_url_to_sandbox_analysis_command,
                               get_full_report_command, 'URL')


def validate_command_args(command, args):
    if 'ids' in args:  # for the polling result command
        return
    if command == 'cs-fx-upload-file':
        if 'file' not in args:
            raise Exception("file argument is a mandatory for cs-fx-upload-file command")
        if 'file_name' not in args:
            raise Exception("file_name argument is a mandatory for cs-fx-upload-file command")
        if 'polling' in args and args.get('submit_file') != 'yes':
            raise Exception("The command cs-fx-upload-file support the polling option "
                            "just when the submit_file argument is yes.")

    elif command == 'cs-fx-submit-uploaded-file':
        if 'environment_id' not in args:
            raise Exception("environment_id argument is a mandatory for cs-fx-submit-uploaded-file command")
        if 'sha256' not in args:
            raise Exception("sha256 argument is a mandatory for cs-fx-submit-uploaded-file command")

    elif command == 'cs-fx-submit-url':
        if 'environment_id' not in args:
            raise Exception("environment_id argument is a mandatory for cs-fx-submit-url command")
        if 'url' not in args:
            raise Exception("sha256 argument is a mandatory for cs-fx-submit-url command")


def remove_polling_related_args(args):
    if 'interval_in_seconds' in args:
        args.pop('interval_in_seconds')
    if 'extended_data' in args:
        args.pop('extended_data')


def main():
    params = demisto.params()
    args = demisto.args()
    url = params.get('base_url', 'https://api.crowdstrike.com/')
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('reliability', DBotScoreReliability.B)

    try:
        command = demisto.command()
        LOG(f'Command being called in CrowdStrikeFalconX Sandbox is: {command}')
        client = Client(server_url=url, username=username, password=password, use_ssl=use_ssl, proxy=proxy,
                        reliability=reliability)
        polling_commands = {
            'cs-fx-upload-file': upload_file_with_polling_command,
            'cs-fx-submit-uploaded-file': submit_uploaded_file_polling_command,
            'cs-fx-submit-url': submit_uploaded_url_polling_command
        }
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
        if command in polling_commands:
            validate_command_args(command, args)
            if args.get('polling', '') == 'true':
                return_results(polling_commands[command](client, args))  # type: ignore[operator]
            else:
                remove_polling_related_args(args)
                return_results(commands[command](client, **args))  # type: ignore[operator]
        elif command == 'cs-fx-get-full-report':
            return_results(get_full_report_command(client, **args)[0])  # type: ignore[operator]
        elif command in commands:
            return_outputs(*commands[command](client, **args))  # type: ignore[operator]
        else:
            raise NotImplementedError(f'{command} is not an existing CrowdStrike Falcon X command')
    except Exception as err:
        return_error(f'Unexpected error:\n{str(err)}', error=traceback.format_exc())


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
