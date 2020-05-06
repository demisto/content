import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import jwt
from enum import Enum
import requests
import csv
import io
import json
from typing import List

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

''' CONSTANTS '''
HEADERS = {'Accept': 'application/json'}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
AUTH_URL_SUFFIX = '/auth/token'
LIST_TEMPLATES_URL_SUFFIX = '/api/v1/templates'
CANCEL_TASK_URL_SUFFIX = '/api/v1/taskRun/{taskRunId}/cancel'
GET_TASK_STATS_URL_SUFFIX = '/api/v1/taskRun/{taskRunId}'
RUN_BULK_URL_SUFFIX = '/api/v1/template/runBulk'
EXPORT_CSV_URL_SUFFIX = '/api/v1/taskRun/{taskRunId}/fullActionReportCSV'
FULL_ACTION_REPORT_FIELDNAMES = ['Severity', 'Time', 'Duration', 'Operation Type', 'Techniques', 'Parameters', 'Status']
RAW_NTLM_HASH_LENGTH = 32


class Request(Enum):
    POST = 'POST'
    GET = 'GET'


class AuthorizationError(Exception):
    pass


class Client(BaseClient):
    def __init__(self, base_url: str, client_id: str, verify: bool, proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=verify, proxy=proxy)
        self.client_id = client_id
        self.session = requests.Session()
        self.session.headers = headers

    def generic_request(self, method: str, url_suffix: str = None, full_url: str = None, headers: dict = None,
                        params: dict = None, data: dict = None, response_type: str = 'json'):

        full_url = full_url if full_url else f'{self._base_url}{url_suffix}'
        headers = headers if headers else self._headers
        try:
            res = self.session.request(
                method,
                full_url,
                headers=headers,
                verify=self._verify,
                data=data,
                params=params
            )
            demisto.debug(f'Got response: {res}')
            if not res.ok:
                if res.status_code == requests.status_codes.codes.UNAUTHORIZED:  # pylint: disable=no-member
                    raise AuthorizationError(
                        f'Unauthorized access to Pentera API. Status code: {res.status_code}. Raw response: {res.text}')
                raise ValueError(f'Error in API call to Pentera. Status code: {res.status_code}. Reason: {res.text}')

            try:
                if response_type == 'json':
                    demisto.debug('result is JSON')
                    return res.json()
                demisto.debug('result is TEXT')
                return res.text
            except Exception:
                raise ValueError(
                    f'Failed to parse http response to JSON format. Original response body: \n{res.text}')

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
            err_msg = f'\nError Type: {err_type}\nError Number: [{exception.errno}]\nMessage: {exception.strerror}\n ' \
                      f'Verify that the server URL parameter ' \
                      f'is correct and that you have access to the server from your host.'
            raise DemistoException(err_msg, exception)

        except Exception as exception:
            raise Exception(str(exception))

    def authenticate(self, client_id, tgt):
        data = {
            'client_id': client_id,
            'tgt': tgt
        }
        res = self.generic_request(method=Request.POST.value, url_suffix=AUTH_URL_SUFFIX, data=data)
        tgt = res.get('tgt')
        access_token = res.get('token')
        return tgt, access_token

    @staticmethod
    def create_basic_authentication_header(token: str):
        authentication_headers = HEADERS.copy()
        token = token + ':'
        encoded_bytes = base64.b64encode(token.encode("utf-8"))
        encoded_str = str(encoded_bytes, "utf-8")
        authentication_headers['Authorization'] = 'Basic ' + encoded_str
        return authentication_headers

    def run_template_by_name(self, template_name, access_token):
        headers = self.create_basic_authentication_header(access_token)
        data = {
            'templateNames': [template_name]
        }
        res = self.generic_request(method=Request.POST.value, url_suffix=RUN_BULK_URL_SUFFIX, headers=headers,
                                   data=data)
        return res

    def get_task_stats_by_task_run_id(self, task_run_id: str, access_token: str):
        headers = self.create_basic_authentication_header(access_token)
        url_suffix = GET_TASK_STATS_URL_SUFFIX.format(taskRunId=task_run_id)
        res = self.generic_request(method=Request.GET.value, url_suffix=url_suffix, headers=headers, data={})
        task_stats = res['taskRuns'][0]
        return task_stats

    def get_task_run_full_action_report_by_task_run_id(self, task_run_id: str, access_token: str):
        headers = self.create_basic_authentication_header(access_token)
        url_suffix = EXPORT_CSV_URL_SUFFIX.format(taskRunId=task_run_id)
        res = self.generic_request(method=Request.GET.value, url_suffix=url_suffix, headers=headers,
                                   response_type='csv')
        return res

    @staticmethod
    def is_access_token_valid(access_token: str, expiry: int):
        if not access_token or not expiry or expiry < int(datetime.utcnow().timestamp()):
            return False
        return True


def pentera_authentication(client: Client):
    try:
        tgt = demisto.getIntegrationContext().get('tgt')
        client_id = demisto.params().get('clientId')
        new_tgt, access_token = client.authenticate(client_id, tgt)
        jwt_decode_dict = jwt.get_unverified_header(access_token)
        expiry = jwt_decode_dict.get('exp', 0) if jwt_decode_dict else 0
        demisto.setIntegrationContext({
            'accessToken': access_token,
            'tgt': new_tgt,
            'expiry': expiry
        })
        return 'ok'

    except Exception as e:
        demisto.error(f'An error occurred during the authentication: {str(e)}')
        raise e


def pentera_get_task_run_full_action_report_command(client: Client, args, access_token: str):
    def _convert_csv_file_to_dict(csv_file):
        def _handle_hash_parameter(hash_param: str):
            def _is_raw_ntlm_hash(hash_str: str):
                return len(hash_str) == RAW_NTLM_HASH_LENGTH

            def _extract_user_name_and_host_name_from_ntlm_v1_2(hash_str: str):
                try:
                    hash_list_split_by_two_colons = hash_str.split('::')
                    hash_list_split_by_one_colon = hash_list_split_by_two_colons[1].split(':')
                    user_name = hash_list_split_by_two_colons[0]
                    domain_or_host_name = hash_list_split_by_one_colon[0]
                    return user_name, domain_or_host_name
                except IndexError:
                    return None

            if not isinstance(hash_param, str):
                return None

            if _is_raw_ntlm_hash(hash_param):
                return {'hash': f'Raw NTLM Hash: {hash_param[0]}{hash_param[1]}****'}

            username, domain_or_hostname = _extract_user_name_and_host_name_from_ntlm_v1_2(hash_param)
            return {'username': username,
                    'domainOrHostname': domain_or_hostname,
                    'hash': f'{hash_param[0]}{hash_param[1]}****'}

        def _map_parameters_string_to_object(str_parameters: str = None):
            if str_parameters:
                return json.loads(str_parameters)
            return None

        csv_reader = csv.DictReader(io.StringIO(csv_file), fieldnames=FULL_ACTION_REPORT_FIELDNAMES)
        data = []
        for row in csv_reader:
            # Skipping first line
            if list(row.values()) != FULL_ACTION_REPORT_FIELDNAMES:
                row_copy = row.copy()
                converted_params = _map_parameters_string_to_object(row_copy.get('Parameters'))
                if converted_params:
                    if 'hash' in converted_params:
                        hash_parameter = converted_params['hash']
                        parsed_hash_parameters = _handle_hash_parameter(hash_parameter)
                        if parsed_hash_parameters:
                            converted_params = parsed_hash_parameters
                    row_copy['Parameters'] = converted_params
                data.append(row_copy)

        return data

    def _convert_full_action_report_time(full_action_report_list: List[dict]):
        def _parse_date(full_date, separator):
            if isinstance(full_date, str) and isinstance(separator, str):
                date = full_date.split(separator)
                if len(date) > 2:
                    first_arg = date[0]
                    second_arg = date[1]
                    third_arg = date[2]
                    return first_arg, second_arg, third_arg

        res_list: List[dict] = []
        for ordered_dict in full_action_report_list:
            full_date_to_convert = ordered_dict['Time']
            full_date_list = full_date_to_convert.split(' ')
            year, month, day = _parse_date(full_date_list[0], '-')
            hours, minutes, seconds = _parse_date(full_date_list[1], ':')
            converted_date = year + '-' + month + '-' + day + 'T' + hours + ':' + minutes + ':' + seconds + 'Z'
            new_ordered_dict = ordered_dict.copy()
            new_ordered_dict['Time'] = converted_date
            res_list.append(new_ordered_dict)
        return res_list

    entries = []
    task_run_id = args.get('task_run_id')
    try:
        response_csv = client.get_task_run_full_action_report_by_task_run_id(task_run_id, access_token)
        readable_output = f"# Pentera Report for TaskRun ID {task_run_id}"
        entry = fileResult(f'penterascan-{task_run_id}.csv', response_csv, entryTypes['entryInfoFile'])
        entry["HumanReadable"] = readable_output
        entry["ContentsFormat"] = formats["markdown"]
        entries.append(entry)
        csv_dict = _convert_csv_file_to_dict(response_csv)
        date_converted_csv_dict = _convert_full_action_report_time(csv_dict)
        human_readable = tableToMarkdown(readable_output, date_converted_csv_dict,
                                         headers=FULL_ACTION_REPORT_FIELDNAMES)
        entries.append({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "ReadableContentsFormat": formats["markdown"],
            "Contents": date_converted_csv_dict,
            "EntryContext": {
                'Pentera.TaskRun(val.ID == obj.ID)': {
                    'FullActionReport': date_converted_csv_dict,
                    'ID': task_run_id
                }
            },
            "HumanReadable": human_readable
        })
        return entries
    except Exception as e:
        demisto.error(f'An error occurred when tried to get task run id: {task_run_id} full action report: {str(e)}')
        raise e


def pentera_get_task_run_stats_command(client: Client, args, access_token: str):
    task_run_id = args.get('task_run_id')
    try:
        task_run_stats = client.get_task_stats_by_task_run_id(task_run_id, access_token)
        parsed_response = parse_task_run_stats(task_run_stats)
        title = parsed_response['TemplateName'] + ': ' + parsed_response['Status']
        readable_output = tableToMarkdown(title, parsed_response, removeNull=True)
        return (
            readable_output,
            {'Pentera.TaskRun(val.ID == obj.ID)': parsed_response},
            task_run_stats  # raw response - the original response
        )
    except Exception as e:
        demisto.error(f'An error occurred when tried to get task run id: {task_run_id} stats: {str(e)}')
        raise e


def parse_task_run_stats(json_response):
    def _convert_time_in_millis_to_date_format(time_in_millis):
        time_in_date_format = None
        try:
            time_in_date_format = datetime.fromtimestamp(float(time_in_millis) / 1000).strftime(DATE_FORMAT)
            return time_in_date_format
        except TypeError:
            return time_in_date_format

    if isinstance(json_response, dict):
        end_time_date_format = _convert_time_in_millis_to_date_format(json_response.get('endTime'))
        start_time_date_format = _convert_time_in_millis_to_date_format(json_response.get('startTime'))
        parsed_json_response = {
            'ID': json_response.get('taskRunId'),
            'TemplateName': json_response.get('taskRunName'),
            'StartTime': start_time_date_format,
            'EndTime': end_time_date_format,
            'Status': json_response.get('status'),
        }
        return parsed_json_response


def pentera_run_template_command(client, args, access_token):
    template_name = args.get('template_name')
    try:
        response = client.run_template_by_name(template_name, access_token)
        task_run_json = response['taskRuns'][0]
        parsed_response = parse_task_run_stats(task_run_json)
        readable_output = tableToMarkdown(template_name, parse_task_run_stats(task_run_json),
                                          removeNull=True)
        return (
            readable_output,
            {'Pentera.TaskRun(val.ID == obj.ID)': parsed_response},
            response  # raw response - the original response
        )

    except Exception as e:
        demisto.error(f'An error occurred when tried to run a template by name. Template name: {template_name}. '
                      f'Error message: {str(e)}')
        raise e


def main():
    client_id = demisto.params().get('clientId')
    application_port = demisto.params().get('port')
    base_url = demisto.params()['url'].rstrip('/') + ':' + application_port
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    tgt = demisto.getIntegrationContext().get('tgt', None)
    if not tgt:
        params_tgt = demisto.params()['tgt']
        demisto.setIntegrationContext({
            'tgt': params_tgt
        })
    access_token = demisto.getIntegrationContext().get('accessToken', None)
    expiry = demisto.getIntegrationContext().get('expiry', 0)
    demisto.debug(f'Got command: {demisto.command()}')
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            client_id=client_id,
            proxy=proxy,
            headers=HEADERS
        )
        if demisto.command() == 'test-module':
            demisto.results('ok')

        elif demisto.command() == 'pentera-run-template-by-name':
            if not client.is_access_token_valid(access_token, expiry):
                pentera_authentication(client)
            return_outputs(*pentera_run_template_command(client, demisto.args(),
                                                         demisto.getIntegrationContext().get('accessToken')))

        elif demisto.command() == 'pentera-get-task-run-status':
            if not client.is_access_token_valid(access_token, expiry):
                pentera_authentication(client)
            return_outputs(*pentera_get_task_run_stats_command(client, demisto.args(),
                                                               demisto.getIntegrationContext()
                                                               .get('accessToken')))

        elif demisto.command() == 'pentera-get-task-run-full-action-report':
            if not client.is_access_token_valid(access_token, expiry):
                pentera_authentication(client)
            demisto.results(pentera_get_task_run_full_action_report_command(client, demisto.args(),
                                                                            demisto.getIntegrationContext().get(
                                                                                'accessToken')))
    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
