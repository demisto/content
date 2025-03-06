import uuid
from dataclasses import dataclass
from collections.abc import Callable
from urllib.parse import quote
from more_itertools import always_iterable
import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


class FileReportWarning(Exception):
    """
    This class is in charge of catching errors raised from having an error object in the
    file's sandbox analysis report
    """


@dataclass
class RawCommandResults:
    response: dict
    output: Optional[dict]
    indicator: Optional[Common.File]


DBOT_SCORE_DICT: Dict[str, int] = {'malicious': Common.DBotScore.BAD,
                                   'suspicious': Common.DBotScore.SUSPICIOUS,
                                   'no specific threat': Common.DBotScore.GOOD}
OUTPUTS_PREFIX = 'csfalconx.resource'
ONE_MINUTE = 60


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
            "310: Linux Ubuntu 20": 310,
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
        self._ok_codes = ()  # type: ignore[var-annotated]
        self._username = username
        self._password = password
        self._session = requests.Session()
        self._token = self._get_access_token()
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
                if 'image' in res.headers.get('Content-Type', '') or 'text' in res.headers.get('Content-Type', ''):
                    filename_from_headers = res.headers.get('Content-Disposition', '')
                    if 'filename=' in filename_from_headers:
                        filename = filename_from_headers.split('filename=')[-1]
                    else:
                        filename = str(uuid.uuid4())
                    stored_file = fileResult(filename, res.content)
                    file_type = 'image' if 'image' in res.headers.get('Content-Type', '') else 'file'
                    file_entry = {
                        'Type': entryTypes[file_type],
                        'ContentsFormat': formats['text'],
                        'File': stored_file['File'],
                        'FileID': stored_file['FileID'],
                        'Contents': ''
                    }
                    return file_entry
                else:  # handle the response as json
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

    def _get_access_token(self) -> str:
        """Generate an Access token using the user name and password
        :return: valid token
        """
        integration_context = get_integration_context()
        access_token = integration_context.get('access_token')
        token_initiate_time = integration_context.get('token_initiate_time')
        token_expiration_seconds = integration_context.get('token_expiration_seconds')

        if access_token and not is_token_expired(
            token_initiate_time=float(token_initiate_time),
            token_expiration_seconds=float(token_expiration_seconds)
        ):
            demisto.info('access token from integration context is still valid')
            return access_token

        # there's no token or it is expired
        access_token, token_expiration_seconds = self._get_token_request()
        integration_context = {
            'access_token': access_token,
            'token_expiration_seconds': token_expiration_seconds,
            'token_initiate_time': time.time()
        }
        demisto.info('Updating new access token to the integration context...')
        set_integration_context(context=integration_context)

        return access_token

    def _get_token_request(self):
        body = {
            'client_id': self._username,
            'client_secret': self._password
        }

        byte_creds = f'{self._username}:{self._password}'.encode()

        headers = {
            'Authorization': f'Basic {base64.b64encode(byte_creds).decode()}'
        }
        token_response = self._http_request('POST', '/oauth2/token', data=body, headers=headers)
        return token_response.get('access_token'), token_response.get('expires_in')

    def upload_file(
            self,
            file: str,
            file_name: Optional[str] = None,
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
        file_name = quote(file_name or get_file_path_res.get('name', ''))

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
        body = {
            "sandbox": [
                {
                    "url": quote(url, safe=":/"),
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
        return self._http_request("POST", "/falconx/entities/submissions/v1", json_data=body)

    def get_full_report(
            self,
            id: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param id: id of a submitted malware samples.
        :return: http response
        """
        return self._http_request("Get", "/falconx/entities/reports/v1", params={"ids": id})

    def get_report_summary(
            self,
            id: str
    ) -> dict:
        """Creating the needed arguments for the http request
        :param id: id of a submitted malware samples.
        :return: http response
        """
        url_suffix = "/falconx/entities/report-summaries/v1"
        return self._http_request("Get", url_suffix, params={"ids": id})

    def get_analysis_status(
            self,
            ids: list
    ) -> dict:
        """Creating the needed arguments for the http request
        :param ids: ids of a submitted malware samples.
        :return: http response
        """
        return self._http_request("Get", "/falconx/entities/submissions/v1", params={"ids": ids})

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
        url_suffix = "/falconx/entities/artifacts/v1"
        params = {
            "id": id,
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
            limit: int = 50,
            filter: str = "",
            offset: str = "",
            sort: str = "",
            hashes: Optional[List[str]] = None,
    ) -> dict:
        """Creating the needed arguments for the http request
        :param limit: maximum number of report IDs to return
        :param filter: optional filter and sort criteria in the form of an FQL query, takes precedence over `hash`.
        :param offset: the offset to start retrieving reports from.
        :param sort: sort order: asc or desc
        :param hashes: sha256 hashes of the files. ignored if `filter` is provided.
        :return: http response
        """

        params = {
            "filter": filter,
            "offset": offset,
            "limit": limit,
            "sort": sort,
        }
        if hashes and not filter:
            params['filter'] = ",".join(f'sandbox.sha256:"{sha256}"' for sha256 in argToList(hashes))
            # argToList is called on purpose, as this method is also used in find-reports

        return self._http_request("Get", "/falconx/queries/reports/v1", params=params)

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
        params = {
            "filter": filter,
            "offset": offset,
            "limit": limit,
            "sort": sort,
        }
        return self._http_request('Get', '/falconx/queries/submissions/v1', params=params)


def is_token_expired(token_initiate_time: float, token_expiration_seconds: float) -> bool:
    """
    Check whether a token has expired. a token considered expired if it has been reached to its expiration date in
    seconds minus a minute to be on the safe side.

    for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120
    300.0001 - 240 < 120 - 60

    Args:
        token_initiate_time (float): the time in which the token was initiated in seconds.
        token_expiration_seconds (float): the time in which the token should be expired in seconds.

    Returns:
        bool: True if token has expired, False if not.
    """
    return time.time() - token_initiate_time >= token_expiration_seconds - ONE_MINUTE


def filter_dictionary(dictionary: dict, fields_to_keep: Optional[tuple], sort_by_field_list: bool = False) -> dict:
    """
    Filters a dictionary and keeps only the keys that appears in the given list
    :param dictionary: the origin dict
    :param fields_to_keep: the list which contains the wanted keys
    :param sort_by_field_list: whether to sort the dictionary keys according to the field list
    :return: the dictionary, with only fields that appeared in fields_to_keep.
    >>> filter_dictionary({1:2,3:4}, (3,))
    {3: 4}
    >>> filter_dictionary({1:2,3:4}, (3,1))
    {1: 2, 3: 4}
    >>> filter_dictionary({1:2,3:4}, (3,1), True)
    {3: 4, 1: 2}
    >>> filter_dictionary({1:2,3:4}, (,), True)
    {}
    >>> filter_dictionary({1:2,3:4}, None)
    {}
    """
    filtered = {k: v for k, v in dictionary.items() if k in (fields_to_keep or [])}

    if sort_by_field_list:
        key_order = {v: i for i, v in enumerate(fields_to_keep or [])}
        filtered = dict(sorted(filtered.items(), key=lambda pair: key_order[pair[0]]))

    return filtered


def file_command(client: Client, **args: dict) -> List[CommandResults]:
    file_hashes = argToList(args.get('file', ''))
    report_ids = client.find_sandbox_reports(hashes=file_hashes, limit=250).get('resources', [])

    resources_fields = ('verdict',)
    sandbox_fields = ('filetype', 'file_size', 'sha256', 'threat_score')

    report_to_results: Dict[str, RawCommandResults] = {}
    for report_id in report_ids:
        response = client.get_full_report(report_id)
        report_to_results[report_id] = parse_outputs(response, reliability=client.reliability,
                                                     resources_fields=resources_fields, sandbox_fields=sandbox_fields)

    command_results = parse_file_results(report_to_results)

    if not command_results:
        command_results = [
            CommandResults(
                readable_output=f'There are no results yet for the any of the {file_hashes=}, '
                                'analysis might not have been completed. '
                                'Please wait to download the report.\n'
                                'You can use cs-fx-get-analysis-status to check the status '
                                'of a sandbox analysis.'
            )
        ]
    return command_results


def parse_file_results(report_to_results: Dict[str, RawCommandResults]) -> List[CommandResults]:
    """
    File results may be returned from multiple reports and include various data.
    1. The output used uses the highest verdict and threat score.
    2. The indicator used is the one with the highest DBotScore.

    :param report_to_results: a dictionary of each
    :return: a list of CommandResults, with only one value per SHA256, using the most suitable data available.
    """
    command_results = []
    # Only one output per SHA256
    results = tuple(report_to_results.values())

    max_indicators: Dict[str, Common.File] = find_suitable_hash_indicator(results)  # type:ignore[arg-type]
    max_outputs: Dict[str, dict] = find_suitable_hash_output(results)  # type:ignore[arg-type]

    added_hashes = set()

    for report_id, result in report_to_results.items():
        if result.output:
            if not (sha256 := result.output.get('sha256')):
                demisto.debug(f'unexpected result for {report_id=}: '
                              f'output is not empty but SHA256 could not be found.\n\n'
                              f'{result.output=}\n'
                              f'{result.response=}\n'
                              f'{result.indicator=}\n\n')
                continue
            if sha256 in added_hashes:  # most suitable result has already been added
                continue
            if result.output != max_outputs[sha256]:  # only use the max output
                continue

            result.indicator = max_indicators.get(sha256)
            readable_output = tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output)
            added_hashes.add(sha256)

        else:  # no output for this report_id
            readable_output = f'There are no results yet for {report_id=}, ' \
                              f'its analysis might not have been completed. ' \
                              'Please wait to download the report.\n' \
                              'You can use cs-fx-get-analysis-status to check the status of a sandbox analysis.',

        command_results.append(
            CommandResults(
                outputs_key_field='sha256',
                outputs_prefix=OUTPUTS_PREFIX,
                outputs=result.output,
                readable_output=readable_output,
                raw_response=result.response,
                indicator=result.indicator,
            )
        )
    return command_results


def find_suitable_hash_output(raw_results: tuple[RawCommandResults]) -> Dict[str, dict]:
    """
    Aggregates data fields from various outputs, to create a single output per SHA256.
    :param raw_results: result that may include multiple outputs for the same SHA256 value.
    :return: mapping of SHA256 -> output
    """
    max_outputs: Dict[str, dict] = {}

    for result in filter(None, raw_results):  # filters out None results
        if not (output := result.output):
            continue  # no output to compare
        if not (sha256 := output.get('sha256')):
            continue  # must have SHA256 to compare

        if not (temp_max := max_outputs.get(sha256)):
            # current result is first one with this SHA256
            max_outputs[sha256] = output
            continue

        if temp_max == output:
            # nothing to update, a dupe value
            continue

        new_max = {
            'sha256': sha256,
            'file_size': temp_max.get('file_size') or output.get('file_size')  # one may be missing
        }
        # take the one that's more severe. If both are missing, threat_score is omitted from the result.
        threat_score = max(temp_max.get('threat_score', -1),
                           output.get('threat_score', -1))
        if threat_score != -1:
            new_max['threat_score'] = threat_score

        if 'verdict' in temp_max or 'verdict' in output:
            # take the one whose DBotScore equivalent of the verdict is more severe.
            new_max['verdict'] = max(temp_max.get('verdict'), output.get('verdict'),
                                     key=lambda value: DBOT_SCORE_DICT.get(value, Common.DBotScore.NONE))

        # done building new_max
        max_outputs[sha256] = new_max

    return max_outputs


def parse_outputs(
        response: dict,
        reliability: str,
        meta_fields: Optional[tuple] = None,
        quota_fields: Optional[tuple] = None,
        resources_fields: Optional[tuple] = None,
        sandbox_fields: Optional[tuple] = None,
        extra_sandbox_fields: Optional[tuple] = None,
) -> RawCommandResults:
    """Parse group data as received from CrowdStrike FalconX API matching Demisto conventions
    the output from the API is a dict that contains the keys: meta, resources and errors
    the meta contains a "quota" dict
    the "resources" is an array that contains the sandbox dict
    the function filters the wanted params from the api result
    :param response: the api result from the http request
    :param meta_fields: the wanted params that appear in the mate section
    :param reliability: a string representing the assumed reliability of this integration instance
    :param quota_fields: the wanted params that appear in the quota section
    :param resources_fields: the wanted params that appear in the resources section
    :param sandbox_fields: the wanted params that appear in the sandbox section
    :param extra_sandbox_fields: the wanted params that appear in the extra sandbox section
    """
    output: Dict[str, Any] = {}
    indicator: Optional[Common.File] = None

    if api_res_meta := response.get("meta", {}):
        output.update(filter_dictionary(api_res_meta, meta_fields))
        output.update(filter_dictionary(api_res_meta.get("quota", {}), quota_fields))

    if resources_list := response.get("resources"):
        # depends on the command, the resources_list section can be a List[str] or list with a single dictionary
        if isinstance(resources_list[0], dict):
            resources = resources_list[0]
            resources_group_outputs = filter_dictionary(resources, resources_fields)

            if sandbox := resources.get("sandbox", [{}])[0]:  # list of single dict
                output.update(filter_dictionary(sandbox, sandbox_fields))
                indicator = parse_indicator(sandbox, reliability)

                if extra_sandbox_group_outputs := filter_dictionary(sandbox, extra_sandbox_fields):
                    for process in extra_sandbox_group_outputs.get('processes', []):
                        process.pop('registry', None)

                    resources_group_outputs['sandbox'] = extra_sandbox_group_outputs
                    output.update(extra_sandbox_group_outputs)
        else:  # the resources section is a list of strings
            resources_group_outputs = {"resources": resources_list}
        output.update(resources_group_outputs)
    return RawCommandResults(response, output, indicator)


def parse_indicator(sandbox: dict, reliability_str: str) -> Optional[Common.File]:  # type: ignore[return]
    if sha256 := sandbox.get('sha256'):
        score_field: int = DBOT_SCORE_DICT.get(sandbox.get('verdict', ''), Common.DBotScore.NONE)
        reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(reliability_str)
        dbot = Common.DBotScore(indicator=sha256,
                                indicator_type=DBotScoreType.FILE,
                                score=score_field,
                                reliability=reliability)

        info = {item['id']: item.get('value') for item in sandbox.get('version_info', [])}
        relationships: Optional[List[EntityRelationship]] = None
        if sandbox.get('submission_type', '') in ('file_url', 'file'):
            relationships = parse_indicator_relationships(sandbox, indicator_value=sha256, reliability=reliability)
        signature: Optional[Common.FileSignature] = Common.FileSignature(authentihash='',  # N/A in data
                                                                         copyright=info.get('LegalCopyright', ''),
                                                                         description=info.get('FileDescription', ''),
                                                                         file_version=info.get('FileVersion', ''),
                                                                         internal_name=info.get('InternalName', ''),
                                                                         original_name=info.get('OriginalFilename', ''))
        if signature and not any(signature.to_context().values()):  # if all values are empty
            signature = None

        return Common.File(
            dbot_score=dbot,
            name=sandbox.get('submit_name'),
            sha256=sha256,
            size=sandbox.get('file_size'),
            file_type=sandbox.get('file_type'),
            company=info.get('CompanyName'),
            product_name=info.get('ProductName'),
            signature=signature,
            relationships=relationships or None,
        )
    return None


def parse_indicator_relationships(sandbox: dict, indicator_value: str, reliability: str) -> List[EntityRelationship]:
    relationships = []

    def _create_relationship(relationship_name: str, entity_b: str, entity_b_type: str) -> EntityRelationship:
        return EntityRelationship(
            name=relationship_name,
            entity_a=indicator_value,
            entity_a_type=FeedIndicatorType.File,
            entity_b=entity_b,
            entity_b_type=entity_b_type,
            source_reliability=reliability
        )

    for request in sandbox.get('dns_requests', []):
        if request_address := request.get('address'):
            relationships.append(_create_relationship(
                relationship_name=EntityRelationship.Relationships.COMMUNICATES_WITH,
                entity_b=request_address,
                entity_b_type=FeedIndicatorType.IP)
            )

        if request_domain := request.get('domain'):
            relationships.append(_create_relationship(
                relationship_name=EntityRelationship.Relationships.COMMUNICATES_WITH,
                entity_b=request_domain,
                entity_b_type=FeedIndicatorType.Domain)
            )

    for host in sandbox.get('contacted_hosts', []):
        if host_address := host.get('address'):
            relationships.append(_create_relationship(
                relationship_name=EntityRelationship.Relationships.COMMUNICATES_WITH,
                entity_b=host_address,
                entity_b_type=FeedIndicatorType.IP)
            )
    return relationships


def test_module(client: Client) -> str:
    """
    If a client was made then an accesses token was successfully reached,
    therefore the username and password are valid and a connection was made
    additionally, checks if not using all the optional quota
    :param client: the client object with an access token
    :return: ok if got a valid accesses token and not all the quota is used at the moment
    """
    output = client.check_quota_status()

    if error := output.get("errors"):
        return error[0]

    if quota := output.get('meta', {}).get('quota'):
        quota_amount = quota.get('total')
        used_amount = quota.get('used')
        if used_amount < quota_amount:
            return 'ok'
        else:
            raise DemistoException(f'Quota limit has been reached: {used_amount}')
    raise DemistoException('Quota limit is unknown')


def upload_file_command(  # type: ignore[return]
        client: Client,
        file: str,
        environment_id: str = "160: Windows 10",
        file_name: Optional[str] = None,
        is_confidential: str = "true",
        comment: str = "",
        submit_file: str = "no",
        action_script: str = "",
        command_line: str = "",
        document_password: str = "",
        enable_tor: str = "false",
        submit_name: str = "",
        system_date: str = "",
        system_time: str = "",
) -> CommandResults:
    """Upload a file for sandbox analysis.
    :param client: the client object with an access token
    :param file: content of the uploaded sample in binary format
    :param file_name: name of the file
    :param is_confidential: defines visibility of this file in Falcon MalQuery, either via the API or the Falcon console
    :param comment: a descriptive comment to identify the file for other users
    :param submit_file: if "yes" run cs-fx-submit-uploaded-file for the uploaded file
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
    response = client.upload_file(file, file_name, is_confidential, comment)

    resources_fields = ("file_name", "sha256")
    result = parse_outputs(response, client.reliability, resources_fields=resources_fields)
    if submit_file == 'no':
        return CommandResults(
            outputs_key_field='sha256',
            outputs_prefix=OUTPUTS_PREFIX,
            outputs=result.output,
            readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
            raw_response=response,
        )

    else:
        sha256 = str(result.output.get("sha256"))  # type: ignore[union-attr]
        return send_uploaded_file_to_sandbox_analysis_command(client, sha256, environment_id, action_script,
                                                              command_line, document_password, enable_tor,
                                                              submit_name, system_date, system_time)


def get_uploaded_file_name(hash_file: str) -> str | None:
    """Returns a file name from the context based on his sha256.

    Args:
        hash_file (str): The sha256 that represents the file.

    Returns:
        str: The file name.
    """
    if context := demisto.get(demisto.context(), OUTPUTS_PREFIX, []):
        if isinstance(context, dict):
            context = [context]
        if filtered_context := list(filter(lambda x: x.get('sha256') == hash_file, context)):
            return filtered_context[0].get('file_name')
    return None


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
        system_time: str = "") -> CommandResults:
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
    sandbox_fields = ("environment_id", "sha256")
    resource_fields = ('id', 'state', 'created_timestamp', 'created_timestamp')
    result = parse_outputs(response, reliability=client.reliability,
                           sandbox_fields=sandbox_fields, resources_fields=resource_fields)
    if result.output:  # the "if" is here to calm mypy down
        # in order identify the id source, upload or submit command, the id name changed
        result.output["submitted_id"] = result.output.pop("id")
        # We should get the file name from the context since the API does not return it.
        result.output["file_name"] = get_uploaded_file_name(sha256)

    return CommandResults(
        outputs_key_field='submitted_id',
        outputs_prefix=OUTPUTS_PREFIX,
        outputs=result.output,
        readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
        raw_response=result.response,
        indicator=result.indicator
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
        system_time: str = "") -> CommandResults:
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

    resources_fields = ('id', 'state', 'created_timestamp')
    sandbox_fields = ("environment_id", "sha256")
    result = parse_outputs(response, client.reliability, resources_fields=resources_fields,
                           sandbox_fields=sandbox_fields)
    if result.output:  # the "if" is here to calm mypy down
        # in order identify the id source, upload or submit command, the id name changed
        result.output["submitted_id"] = result.output.pop("id")
        result.output['url_name'] = url

    return CommandResults(
        outputs_key_field='submitted_id',
        outputs_prefix=OUTPUTS_PREFIX,
        outputs=result.output,
        readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
        raw_response=response,
        indicator=result.indicator)


def get_full_report_command(
        client: Client,
        ids: str,  # argToList is called inside
        extended_data: str = '',
) -> tuple[List[CommandResults], bool]:
    """Get a full version of a sandbox report.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :param extended_data: Whether to return extended data which includes mitre attacks and signature information.
    :return: list of CommandResults, and a boolean marking at least one of them has `resources` (used for polling)
    """
    results: List[RawCommandResults] = []
    is_command_finished: bool = False

    resources_fields = ('id', 'verdict', 'created_timestamp', "ioc_report_strict_csv_artifact_id",
                        "ioc_report_broad_csv_artifact_id", "ioc_report_strict_json_artifact_id",
                        "ioc_report_broad_json_artifact_id", "ioc_report_strict_stix_artifact_id",
                        "ioc_report_broad_stix_artifact_id", "ioc_report_strict_maec_artifact_id",
                        "ioc_report_broad_maec_artifact_id", 'tags', "intel")

    sandbox_fields = (
        "environment_id", "environment_description", "threat_score", "submit_url", "submission_type", "filetype",
        "filesize", "sha256"
    )
    extra_sandbox_fields = (
        "processes", "architecture", "classification", "classification_tags", "http_requests",
        "extracted_files", "file_metadata", "file_size", "file_type", "file_type_short", "packer", "incidents",
        "submit_name", "screenshots_artifact_ids", "dns_requests", "contacted_hosts", "contacted_hosts"
    )

    hr_fields = (
        'sha256', 'environment_description', 'environment_id', 'created_timestamp', 'id', 'submission_type',
        'threat_score', 'verdict'
    )

    for id_ in argToList(ids):
        response = client.get_full_report(id_)
        if response.get('resources'):
            is_command_finished = True  # flag used when commands
            # We can extract the error from the response object under resources section, as it looks like the error section is
            # always empty
            try:
                validate_sandbox_report(response.get('resources', []))
            except FileReportWarning as e:
                return_warning(str(e))

        if extended_data == 'true':
            extra_sandbox_fields = extra_sandbox_fields + ("mitre_attacks", "signatures")  # type:ignore[assignment]

        result = parse_outputs(response, reliability=client.reliability,
                               resources_fields=resources_fields, sandbox_fields=sandbox_fields,
                               extra_sandbox_fields=extra_sandbox_fields)
        results.append(result)

    command_results = []
    for result in results:
        if result.output:
            if human_readable_values := filter_dictionary(result.output, hr_fields, sort_by_field_list=True):
                readable_output = tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:",
                                                  t=human_readable_values, headers=hr_fields)
            else:
                readable_output = tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output)
        else:
            readable_output = 'There are no results yet for this sample, its analysis might not have been completed. ' \
                              'Please wait to download the report.\n' \
                              'You can use cs-fx-get-analysis-status to check the status of a sandbox analysis.',

        command_results.append(
            CommandResults(
                outputs_key_field='id',
                outputs_prefix=OUTPUTS_PREFIX,
                outputs=result.output,
                readable_output=readable_output,
                raw_response=result.response,
                indicator=result.indicator
            )
        )
    if not command_results:
        command_results = [
            CommandResults(readable_output=f'There are no results yet for the any of the queried samples ({ids}), '
                                           'analysis might not have been completed. '
                                           'Please wait to download the report.\n'
                                           'You can use cs-fx-get-analysis-status to check the status '
                                           'of a sandbox analysis.')
        ]
    return command_results, is_command_finished


def validate_sandbox_report(report_resources: list[dict[str, Any]]) -> None:
    """This function checks for any error messages in the sandbox report.
    The report resource can hold the following data:
    "resources": [
        {
            "id": "resource_id",
            "cid": "cid",
            "created_timestamp": "2024-01-10T16:17:37Z",
            "index_timestamp": "2024-01-10T16:20:54Z",
            "origin": "apigateway",
            "verdict": "no verdict",
            "sandbox": [
                {
                    "sha256": "dummy_sha256",
                    "environment_id": "dummy_environment_id",
                    "environment_description": "Windows 10 64 bit",
                    "file_type": "PNG image data, 1951 x 954, 8-bit/color RGBA, non-interlaced",
                    "file_type_short": [
                        "img"
                    ],
                    "submit_name": "dummy_sha256",
                    "submission_type": "file",
                    "error_message": 'File "dummy_sha256" was detected as "image", this format is not supported on WINDOWS',
                    "error_type": "FILE_TYPE_BAD_ERROR",
                    "error_origin": "CLIENT",
                    "is_certificates_valid": False
                }
            ]
        }
    ]
    Args:
        report_resources (list[dict[str, Any]]): Report resources of the report. They hold the data about
        any error messages returned from the report.

    Raises:
        FileReportWarning: If an error message is found in the sandbox report
    """
    for resource in report_resources:
        resource_id = resource['id']
        for sandbox_entity in resource.get('sandbox', []):
            if error_message := sandbox_entity.get('error_message'):
                error_type = sandbox_entity.get('error_type', '<UNKNOWN>')
                raise FileReportWarning(f'Sandbox report for resource id {resource_id} returned an error of'
                                        f' type {error_type} with content: {error_message}')


def find_suitable_hash_indicator(results: tuple[RawCommandResults]) -> Dict[str, Common.File]:
    """
    Returns the indicator with the highest dbot_score for every hash.
    :param results: raw results from a command
    :return: dict mapping a SHA256 to the indicator with the highest DBotScore
    """
    max_indicators: Dict[str, Common.File] = {}  # SHA256 to indicator with maximal DBotScore

    for indicator in filter(None, (result.indicator for result in results)):
        if sha256 := indicator.sha256:
            if existing := max_indicators.get(sha256):
                if indicator.dbot_score.score > existing.dbot_score.score:
                    max_indicators[sha256] = indicator
            else:
                max_indicators[sha256] = indicator
    return max_indicators


def get_report_summary_command(
        client: Client,
        ids: str,  # argToList is called inside
) -> List[CommandResults]:
    """Get a short summary version of a sandbox report.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """

    resources_fields = (
        'id', 'verdict', 'created_timestamp', 'ioc_report_strict_csv_artifact_id',
        'ioc_report_broad_csv_artifact_id', 'ioc_report_strict_json_artifact_id',
        'ioc_report_broad_json_artifact_id', 'ioc_report_strict_stix_artifact_id',
        'ioc_report_broad_stix_artifact_id', 'ioc_report_strict_maec_artifact_id',
        'ioc_report_broad_maec_artifact_id'
    )

    sandbox_fields = (
        'environment_id', 'environment_description', 'threat_score', 'submit_url', 'submission_type', 'filetype',
        'filesize', 'sha256'
    )

    no_outputs_msg = 'There are no results yet, the sample might still be going through analysis.' \
                     ' Please wait to download the report.\n' \
                     'You can use cs-fx-get-analysis-status to check the status of a sandbox analysis.'
    results = []

    for single_id in argToList(ids):
        response = client.get_report_summary(single_id)
        if response.get('resources'):
            # We can extract the error from the response object under resources section, as it looks like the error section is
            # always empty
            try:
                validate_sandbox_report(response.get('resources', []))
            except FileReportWarning as e:
                return_warning(str(e))

        result = parse_outputs(response, reliability=client.reliability,
                               resources_fields=resources_fields, sandbox_fields=sandbox_fields)
        results.append(
            CommandResults(
                outputs_key_field='id',
                outputs_prefix=OUTPUTS_PREFIX,
                outputs=result.output,
                readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output)
                if result.output else no_outputs_msg,
                raw_response=result.response,
                indicator=result.indicator
            )
        )
    return results


def get_analysis_status_command(
        client: Client,
        ids: str,  # argsToList called inside
) -> List[CommandResults]:
    """Check the status of a sandbox analysis.
    :param client: the client object with an access token
    :param ids: ids of a submitted malware samples.
    :return: Demisto outputs when entry_context and responses are lists
    """
    resources_fields = ('id', 'state', 'created_timestamp')
    sandbox_fields = ('environment_id', 'sha256')

    results = []

    for single_id in argToList(ids):
        response = client.get_analysis_status([single_id])
        result = parse_outputs(response, reliability=client.reliability, resources_fields=resources_fields,
                               sandbox_fields=sandbox_fields)
        results.append(
            CommandResults(outputs_key_field='id',
                           outputs_prefix=OUTPUTS_PREFIX,
                           outputs=result.output,
                           readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
                           raw_response=result.response,
                           # not returning indicator
                           )
        )
    return results


def download_ioc_command(
        client: Client,
        id: str,
        name: str = "",
        accept_encoding: str = ""
) -> Union[CommandResults, dict]:
    """Download IOC packs, PCAP files, and other analysis artifacts.
    :param client: the client object with an access token
    :param id: id of an artifact, such as an IOC pack, PCAP file, or actor image
    :param name: the name given to your downloaded file
    :param accept_encoding: format used to compress your downloaded file
    :return: Demisto outputs when entry_context and responses are lists
    """
    response: Optional[dict] = None
    try:
        response = client.download_ioc(id, name, accept_encoding)
        # In case the returned response is a file, output the file to the war room.
        if isinstance(response, dict) and response.get('File'):
            return response
        else:
            return CommandResults(
                outputs_prefix=OUTPUTS_PREFIX,
                outputs_key_field='ioc',
                outputs=response,
                readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", response),
                raw_response=response
            )
    except Exception as e:
        demisto.debug(f'Download ioc exception {e}')
        raise DemistoException(f'Download ioc encountered an exception: {e}', exception=e, res=response)


def check_quota_status_command(
        client: Client
) -> List[CommandResults]:
    """Search endpoint contains File Hash.
    :param client: the client object with an access token
    :return: Demisto outputs when entry_context and responses are lists
    """
    response = client.check_quota_status()
    quota_fields = ('total', 'used', 'in_progress')

    result = parse_outputs(response, client.reliability, quota_fields=quota_fields)

    return [
        CommandResults(
            outputs_prefix=OUTPUTS_PREFIX,
            outputs_key_field='id',
            readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
            raw_response=response,
            outputs=result.output
        )
    ]


def find_sandbox_reports_command(
        client: Client,
        limit: int = 50,
        filter: str = "",
        offset: str = "",
        sort: str = "",
        hashes: str = ""
) -> CommandResults:
    """Find sandbox reports by providing an FQL filter and paging details.
    :param client: the client object with an access token
    :param limit: maximum number of report IDs to return
    :param filter: optional filter and sort criteria in the form of an FQL query. takes precedence over filter.
    :param offset: the offset to start retrieving reports from.
    :param sort: sort order: asc or desc
    :param hashes: sha256 hashes to search for, overridden by filter.
    :return: Demisto outputs when entry_context and responses are lists
    """
    if hashes and not filter:
        found_reports = []
        all_report_ids = []
        raw_results: List[RawCommandResults] = []

        for single_hash in argToList(hashes):
            response = client.find_sandbox_reports(limit, filter, offset, sort, hashes=single_hash)
            raw_result = parse_outputs(response, reliability=client.reliability, resources_fields=('id',))
            if report_ids := (raw_result.output or {}).get('resources', []):
                found_reports.append({'sha256': single_hash, 'reportIds': report_ids})
                all_report_ids.extend(report_ids)

                total_count = response.get('meta', {}).get('pagination', {}).get('total', 0)
                if total_count > len(report_ids):
                    demisto.info(f'Warning: there are {total_count} reports, but only {len(report_ids)} were fetched.')
            else:
                found_reports.append({'sha256': single_hash, 'reportIds': []})

        outputs = {
            'resources': all_report_ids,
            'FindReport': found_reports,
        }

        readable_output = tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", {'resource': all_report_ids}) \
            if all_report_ids else f'No reports found for hashes {hashes}.'
        return CommandResults(
            outputs_key_field='id',
            outputs_prefix=OUTPUTS_PREFIX,
            outputs=outputs,
            readable_output=readable_output,
            raw_response=raw_results,
        )

    else:
        if filter:
            demisto.info('Both the hashes and filter arguments were provided to the find-reports command. '
                         'Hashes are ignored in this case.')
        response = client.find_sandbox_reports(limit, filter, offset, sort, hashes=None)
        result = parse_outputs(response, reliability=client.reliability, resources_fields=('id',))
        return CommandResults(
            outputs_key_field='id',
            outputs_prefix=OUTPUTS_PREFIX,
            outputs=result.output,
            readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
            raw_response=result.response,
        )


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
    result = parse_outputs(response, reliability=client.reliability, resources_fields=('id',))

    return CommandResults(
        outputs_key_field='id',
        outputs_prefix=OUTPUTS_PREFIX,
        outputs=result.output,
        readable_output=tableToMarkdown("CrowdStrike Falcon Intelligence Sandbox response:", result.output),
        raw_response=result.response,
    )


def get_results_function_args(outputs, extended_data, item_type, interval_in_secs) -> dict:
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


def pop_polling_related_args(args: dict) -> None:
    for key in ('submit_file', 'enable_tor', 'interval_in_seconds', 'polling', 'environment_id'):
        args.pop(key, None)


def is_new_polling_search(args: dict) -> bool:
    """
    Check if the polling func is a new search or in the polling flow.
    if there ids argument in the args dict its mean that the first search is finished and we should run the polling flow
    """
    return not args.get('ids')


def arrange_args_for_upload_func(args: dict) -> Any:
    args.pop('polling')
    args.pop('interval_in_seconds')
    extended_data = args.pop('extended_data')
    return extended_data


def run_polling_command(client, args: dict, cmd: str, upload_function: Callable, results_function: Callable,
                        item_type,
                        post_function: Optional[Callable] = None
                        ) -> Union[CommandResults, List[CommandResults]]:
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
    elif post_function is not None:
        # Validate the polling results
        post_function(command_result)
    return command_result


def validate_submit_file_polling_results(command_results: list[CommandResults] | CommandResults) -> None:
    """Validate the results of the polling function when submitting a file for analysis.

    Args:
        command_results (list[CommandResults] | CommandResults): The results of the polling method.

    Raises:
        DemistoException: If the results contain an error message, stating that the sandbox analysis was not able to run
        properly.
    """
    for command_result in always_iterable(command_results, CommandResults):
        raw_response: dict[str, Any] = command_result.raw_response
        try:
            validate_sandbox_report(raw_response.get('resources', []))
        except FileReportWarning as e:
            raise DemistoException(f'Sandbox was not able to analyze one of the files, failing with error: {e}')


def upload_file_with_polling_command(client: Client, args: dict):
    return run_polling_command(client, args, 'cs-fx-upload-file', upload_file_command, get_full_report_command, 'FILE',
                               post_function=validate_submit_file_polling_results)


def submit_uploaded_file_polling_command(client: Client, args: dict):
    return run_polling_command(client, args, 'cs-fx-submit-uploaded-file',
                               send_uploaded_file_to_sandbox_analysis_command, get_full_report_command, 'FILE')


def submit_uploaded_url_polling_command(client: Client, args: dict):
    return run_polling_command(client, args, 'cs-fx-submit-url', send_url_to_sandbox_analysis_command,
                               get_full_report_command, 'URL')


def validate_command_args(command: str, args: dict) -> None:
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


def remove_polling_related_args(args: dict) -> None:
    args.pop('interval_in_seconds', None)
    args.pop('extended_data', None)
    args.pop('polling', None)


def main():
    params = demisto.params()
    args = demisto.args()

    url = params.get('base_url', 'https://api.crowdstrike.com/')
    username = params.get('credentials', {}).get('identifier')
    password = params.get('credentials', {}).get('password')
    use_ssl = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('reliability', DBotScoreReliability.B)

    command = demisto.command()
    demisto.debug(f'Command being called in CrowdStrikeFalconX Sandbox is: {command}')

    try:
        client = Client(server_url=url, username=username, password=password, use_ssl=use_ssl, proxy=proxy,
                        reliability=reliability)
        polling_commands = {
            'cs-fx-upload-file': upload_file_with_polling_command,
            'cs-fx-submit-uploaded-file': submit_uploaded_file_polling_command,
            'cs-fx-submit-url': submit_uploaded_url_polling_command
        }
        commands: Dict[str, Callable] = {
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
            'cs-fx-find-submission-id': find_submission_id_command,
            'file': file_command,
        }
        if command in polling_commands:
            validate_command_args(command, args)
            if args.get('polling', '') == 'true':
                return_results(polling_commands[command](client, args))
            else:
                remove_polling_related_args(args)
                return_results(commands[command](client, **args))
        elif command == 'cs-fx-get-full-report':
            # 2nd returned value is a flag for polling
            command_results, _ = get_full_report_command(client, **args)  # pylint: disable=E1123
            return_results(command_results)
        elif command in commands:
            return_results(commands[command](client, **args))
        else:
            raise NotImplementedError(f'{command} is not an existing CrowdStrike Falcon X command')
    except Exception as e:
        return_error(f'Unexpected error:\n{str(e)}', error=traceback.format_exc())


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
