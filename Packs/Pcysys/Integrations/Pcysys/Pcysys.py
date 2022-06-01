import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import jwt
import requests
import csv
import io
import json

from typing import List
from enum import Enum

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

HEADERS = {'Accept': 'application/json'}
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

HEALTH_URL_SUFFIX = '/health/dbChecks'
AUTH_URL_SUFFIX = '/auth/token'
LIST_TEMPLATES_URL_SUFFIX = '/api/v1/templates'
CANCEL_TASK_URL_SUFFIX = '/api/v1/taskRun/{taskRunId}/cancel'
GET_TASK_RUN_STATUS_URL_SUFFIX = '/api/v1/taskRun/{taskRunId}'
RUN_BULK_URL_SUFFIX = '/api/v1/template/runBulk'
EXPORT_CSV_URL_SUFFIX = '/api/v1/taskRun/{taskRunId}/fullActionReportCSV'


class Request(Enum):
    POST = 'POST'
    GET = 'GET'


class AuthorizationError(Exception):
    pass


class Client(BaseClient):
    def __init__(self, base_url: str, tgt: str, client_id: str, verify: bool, proxy: bool, headers):
        super().__init__(base_url=f'{base_url}', headers=headers, verify=verify, proxy=proxy)
        self.session = requests.Session()
        self.session.headers = headers
        self.client_id = client_id
        self.tgt = tgt
        self.access_token = str()
        self.expiry = 0
        self.load_session_parameters()

    def load_session_parameters(self):
        context: dict = get_integration_context()
        if context and context['base_url'] == self._base_url:
            self.tgt = context['tgt']
            self.access_token = context['accessToken']
            self.expiry = context['expiry']

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
                status_code = res.status_code
                if status_code == requests.status_codes.codes.UNAUTHORIZED:  # pylint: disable=no-member
                    info = "Check that your system clock is set to the correct date and time before you try again."
                    raise AuthorizationError(f'Status code: {status_code}, reason: {res.text}. {info}')
                raise ValueError(f'Error in API call to Pentera. Status code: {status_code}, reason: {res.text}')

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
            err_msg = getattr(exception, 'message', str(exception))
            raise DemistoException(err_msg, exception)

        except Exception as request_error:
            message = getattr(request_error, 'message', str(request_error))
            raise DemistoException(
                f"Could not send request to Pentera, reason: {message}",
                exception=request_error
            )

    def authenticate(self):
        data = {
            'client_id': self.client_id,
            'tgt': self.tgt
        }
        res = self.generic_request(method=Request.POST.value, url_suffix=AUTH_URL_SUFFIX, data=data)
        self.tgt = res.get('tgt')
        self.access_token = res.get('token')
        jwt_decode_dict = jwt.get_unverified_header(self.access_token)
        self.expiry = jwt_decode_dict.get('exp', 0) if jwt_decode_dict else 0
        self.save_session_parameters()

    def save_session_parameters(self):
        context = {
            'base_url': self._base_url,
            'tgt': self.tgt,
            'accessToken': self.access_token,
            'expiry': self.expiry
        }
        set_integration_context(context)

    def is_access_token_valid(self):
        if not self.access_token or not self.expiry or self.expiry < int(datetime.utcnow().timestamp()):
            return False
        return True

    def create_basic_authentication_header(self):
        authentication_headers = HEADERS.copy()
        token = self.access_token + ':'
        encoded_bytes = base64.b64encode(token.encode("utf-8"))
        encoded_str = str(encoded_bytes, "utf-8")
        authentication_headers['Authorization'] = 'Basic ' + encoded_str
        return authentication_headers

    def run_health_checks(self):
        res = self.generic_request(method=Request.GET.value, url_suffix=HEALTH_URL_SUFFIX)
        return res

    def run_template_by_name(self, template_name):
        headers = self.create_basic_authentication_header()
        data = {
            'templateNames': [template_name]
        }
        res = self.generic_request(method=Request.POST.value, url_suffix=RUN_BULK_URL_SUFFIX, headers=headers,
                                   data=data)
        return res

    def get_task_run_status_by_task_run_id(self, task_run_id: str):
        headers = self.create_basic_authentication_header()
        url_suffix = GET_TASK_RUN_STATUS_URL_SUFFIX.format(taskRunId=task_run_id)
        res = self.generic_request(method=Request.GET.value, url_suffix=url_suffix, headers=headers, data={})
        task_status = res.get('taskRuns')[0]
        return task_status

    def get_task_run_full_action_report_by_task_run_id(self, task_run_id: str):
        headers = self.create_basic_authentication_header()
        url_suffix = EXPORT_CSV_URL_SUFFIX.format(taskRunId=task_run_id)
        res = self.generic_request(method=Request.GET.value, url_suffix=url_suffix, headers=headers,
                                   response_type='csv')
        return res


def pentera_test_module_command(client: Client):
    try:
        response = client.run_health_checks()
    except Exception as test_error:
        message = getattr(test_error, 'message', str(test_error))
        raise DemistoException(message)
    exceptions: list = response.get('exceptions')
    if exceptions:
        raise DemistoException(", ".join(exceptions))
    return 'ok'


def pentera_run_template_command(client: Client, args):
    template_name = args.get('template_name')
    try:
        response = client.run_template_by_name(template_name)
        task_run_json = response.get('taskRuns')[0]
        parsed_response = parse_task_run_status(task_run_json)
        readable_output = tableToMarkdown(template_name, parse_task_run_status(task_run_json),
                                          removeNull=True)
        return (
            readable_output,
            {'Pentera.TaskRun(val.ID == obj.ID)': parsed_response},
            response  # raw response - the original response
        )

    except Exception as run_template_error:
        message = getattr(run_template_error, 'message', str(run_template_error))
        raise DemistoException(
            f"Could not run template with template_name: '{template_name}', reason: {message}",
            exception=run_template_error
        )


def pentera_get_task_run_status_command(client: Client, args):
    task_run_id = args.get('task_run_id')
    try:
        task_run_status = client.get_task_run_status_by_task_run_id(task_run_id)
        parsed_response = parse_task_run_status(task_run_status)
        title = parsed_response['TemplateName'] + ': ' + parsed_response['Status']
        readable_output = tableToMarkdown(title, parsed_response, removeNull=True)
        return (
            readable_output,
            {'Pentera.TaskRun(val.ID == obj.ID)': parsed_response},
            task_run_status  # raw response - the original response
        )
    except Exception as status_error:
        message = getattr(status_error, 'message', str(status_error))
        raise DemistoException(
            f"Could not get task run status for task_run_id: '{task_run_id}', reason: {message}",
            exception=status_error
        )


def pentera_get_task_run_full_action_report_command(client: Client, args):
    def _convert_csv_file_to_dict(csv_file):
        def _map_parameters_string_to_object(str_parameters: str = None):
            if str_parameters:
                return json.loads(str_parameters)
            return None

        csv_reader = csv.DictReader(io.StringIO(csv_file))
        data = []
        for row in csv_reader:
            row_copy = row.copy()
            converted_params = _map_parameters_string_to_object(row_copy.get('Parameters'))
            if converted_params:
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
        response_csv = client.get_task_run_full_action_report_by_task_run_id(task_run_id)
        readable_output = f"# Pentera Report for TaskRun ID {task_run_id}"
        entry = fileResult(f'penterascan-{task_run_id}.csv', response_csv, entryTypes['entryInfoFile'])
        entry["HumanReadable"] = readable_output
        entry["ContentsFormat"] = formats["markdown"]
        entries.append(entry)
        csv_dict = _convert_csv_file_to_dict(response_csv)
        date_converted_csv_dict = _convert_full_action_report_time(csv_dict)
        human_readable = tableToMarkdown(readable_output, date_converted_csv_dict)
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
    except Exception as report_error:
        message = getattr(report_error, 'message', str(report_error))
        raise DemistoException(
            f"Could not get full action report for task_run_id: '{task_run_id}', reason: {message}",
            exception=report_error
        )


def parse_task_run_status(json_response):
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


def pentera_authentication(client: Client):
    if not client.is_access_token_valid():
        try:
            client.authenticate()
        except Exception as auth_error:
            message = getattr(auth_error, 'message', str(auth_error))
            raise DemistoException(
                f"Could not authenticate to Pentera, reason: {message}",
                exception=auth_error
            )


def increase_csv_field_size_limit():
    """
    This method will try to increase the csv field size limit as files might contain huge fields.
    :return: None
    """
    try:
        csv.field_size_limit(sys.maxsize)
    except OverflowError:
        pass


def main():
    params: dict = demisto.params()
    application_port = params['port']
    base_url = params['url'].rstrip('/') + ':' + application_port
    client_id = params['clientId']
    tgt = params['tgt']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    client = Client(
        base_url=base_url,
        tgt=tgt,
        verify=verify_certificate,
        client_id=client_id,
        proxy=proxy,
        headers=HEADERS
    )
    command = demisto.command()
    demisto.debug(f'Got command: {command}')
    try:
        if demisto.command() == 'test-module':
            demisto.results(pentera_test_module_command(client))
        else:
            pentera_authentication(client)
            if demisto.command() == 'pentera-run-template-by-name':
                return_outputs(*pentera_run_template_command(client, demisto.args()))
            elif demisto.command() == 'pentera-get-task-run-status':
                return_outputs(*pentera_get_task_run_status_command(client, demisto.args()))
            elif demisto.command() == 'pentera-get-task-run-full-action-report':
                demisto.results(pentera_get_task_run_full_action_report_command(client, demisto.args()))
    except Exception as e:
        return_error(f'Failed to execute command: {command}, {getattr(e, "message", str(e))}', error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    increase_csv_field_size_limit()
    main()
