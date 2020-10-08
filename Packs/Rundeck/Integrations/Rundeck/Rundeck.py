import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

VERSION = 24

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def __init__(self, base_url, project_name, params, verify=True, proxy=False, ok_codes=tuple(), headers=None,
                 auth=None):
        self.project_name = project_name
        self.params = params
        super().__init__(base_url, verify, proxy, ok_codes, headers, auth)

    def get_project_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'/projects',
            params=self.params
        )

    def get_webhooks_list(self):
        return self._http_request(
            method='GET',
            url_suffix=f'/project/{self.project_name}/webhooks',
            params=self.params
        )

    def get_jobs_list(self, id_list: list, group_path: str, job_filter: str, job_exec_filter: str,
                      group_path_exact: str,
                      scheduled_filter: str, server_node_uuid_filter: str):
        """
        This function returns a list of all existing projects.
        :param id_list: list of Job IDs to include
        :param group_path: include all jobs within that group path. if not specified, default is: "*".
        :param job_filter: specify a filter for a job Name, apply to any job name that contains this value
        :param job_exec_filter: specify an exact job name to match
        :param group_path_exact: specify an exact group path to match. if not specified, default is: "*".
        :param scheduled_filter: return only scheduled or only not scheduled jobs
        :param server_node_uuid_filter: return all jobs related to a selected server UUID. can either be "true" or "false".
        :return: api response.
        """
        request_params: Dict[str, Any] = {}

        if id_list:
            request_params['idlist'] = ','.join(id_list)
        if group_path:
            request_params['groupPath'] = group_path
        if job_filter:
            request_params['jobFilter'] = job_filter
        if job_exec_filter:
            request_params['jobExactFilter'] = job_exec_filter
        if group_path_exact:
            request_params['groupPathExact'] = group_path_exact
        if scheduled_filter:
            request_params['scheduledFilter'] = scheduled_filter
        if server_node_uuid_filter:
            request_params['serverNodeUUIDFilter'] = server_node_uuid_filter

        request_params.update(self.params)

        return self._http_request(
            method='GET',
            url_suffix=f'/project/{self.project_name}/jobs',
            params=request_params
        )

    def execute_job(self, job_id: str, arg_string: str, log_level: str, as_user: str, node_filter: str, run_at_time: str, options: dict):
        """
        This function runs an existing job
        :param arg_string: execution arguments for the selected job: -opt1 value1 -opt2 value2
        :param job_id: id of the job you want to execute
        :param log_level: specifying the loglevel to use: 'DEBUG','VERBOSE','INFO','WARN','ERROR'
        :param as_user: identifying the user who ran the job
        :param node_filter: can be a node filter string
        :param run_at_time:  select a time to run the job
        :param options: add options for running a job
        :return: api response
        """
        request_body: Dict[str, Any] = {}

        if arg_string:
            request_body["argString"] = arg_string
        if log_level:
            request_body["loglevel"] = log_level
        if as_user:
            request_body["asUser"] = as_user
        if node_filter:
            request_body["filter"] = node_filter
        if run_at_time:
            request_body["runAtTime"] = run_at_time
        if options:
            request_body["options"] = options

        return self._http_request(
            method='POST',
            url_suffix=f'/job/{job_id}/executions',
            params=self.params,
            data=str(request_body)
        )

    def retry_job(self, job_id: str, arg_string: str, log_level: str, as_user: str, failed_nodes: str, execution_id: str,
                  options: dict):
        """
        This function retry running a failed execution.
        :param arg_string: execution arguments for the selected job: -opt1 value1 -opt2 value2
        :param job_id: id of the job you want to execute
        :param log_level: specifying the log level to use: 'DEBUG','VERBOSE','INFO','WARN','ERROR'
        :param as_user: identifying the user who ran the job
        :param failed_nodes: can either ben true or false. true for run all nodes and true for running only failed nodes
        :param execution_id: for specified what execution to rerun
        :param options: add options for running a job
        :return: api response
        """
        request_body: Dict[str, Any] = {}

        if arg_string:
            request_body["argString"] = arg_string
        if log_level:
            request_body["loglevel"] = log_level
        if as_user:
            request_body["asUser"] = as_user
        if failed_nodes:
            request_body["failedNodes"] = failed_nodes
        if options:
            request_body["options"] = options

        return self._http_request(
            method='POST',
            url_suffix=f'/job/{job_id}/retry/{execution_id}',
            params=self.params,
            data=str(request_body)
        )

    def job_execution_query(self, status_filter: str, aborted_by_filter: str, user_filter: str, recent_filter: str,
                            older_filter: str, begin: str, end: str, adhoc: str, job_id_list_filter: list,
                            exclude_job_id_list_filter: list, job_list_filter: list, exclude_job_list_filter: list,
                            group_path: str, group_path_exact: str, exclude_group_path: str,
                            exclude_group_path_exact: str, job_filter: str, exclude_job_filter: str,
                            job_exact_filter: str, exclude_job_exact_filter: str, execution_type_filter: str,
                            max_paging: Optional[int], offset: Optional[int], project_name: str):
        """
        This function returns previous and active executions
        :param status_filter: execution status, can be either: "running", succeeded", "failed" or "aborted"
        :param aborted_by_filter: Username who aborted an execution
        :param user_filter: Username who started the execution
        :param recent_filter: for specify when the execution has occur. the format is 'XY' when 'X' is a number and 'Y'
        can be: h - hour, d - day, w - week, m - month, y - year
        :param older_filter: return executions that completed before the specified relative period of time. works with
        the same format as 'recent_filter'
        :param begin: Specify exact date for earliest execution completion time
        :param end: Specify exact date for latest execution completion time
        :param adhoc: can be true or false. true for include Adhoc executions
        :param job_id_list_filter: specify a Job IDs to filter by
        :param exclude_job_id_list_filter: specify a Job IDs to exclude
        :param job_list_filter: specify a full Job group/name to include.
        :param exclude_job_list_filter: specify a full Job group/name to exclude
        :param group_path: specify a group or partial group to include all jobs within that group path.
        :param group_path_exact: like 'group_path' but you need to specify an exact group path to match
        :param exclude_group_path specify a group or partial group path to exclude all jobs within that group path
        :param exclude_group_path_exact: specify a group or partial group path to exclude jobs within that group path
        :param job_filter: provide here a job name to query
        :param exclude_job_filter: provide here a job name to exclude
        :param job_exact_filter: provide here an exact job name to match
        :param exclude_job_exact_filter: specify an exact job name to exclude
        :param execution_type_filter: specify the execution type, can be: 'scheduled', 'user' or 'user-scheduled'
        :param max_paging: maximum number of results to get from the api
        :param offset: offset for first result to include
        :param project_name: the project name that you want to get its execution
        :return: api response
        """

        request_params: Dict[str, Any] = {}

        if status_filter:
            request_params['statusFilter'] = status_filter
        if aborted_by_filter:
            request_params['abortedbyFilter'] = aborted_by_filter
        if user_filter:
            request_params['userFilter'] = user_filter
        if recent_filter:
            request_params['recentFilter'] = recent_filter
        if older_filter:
            request_params['olderFilter'] = older_filter
        if begin:
            request_params['begin'] = begin
        if end:
            request_params['end'] = end
        if adhoc:
            request_params['adhoc'] = adhoc
        if job_id_list_filter:
            request_params['jobIdListFilter'] = job_id_list_filter
        if exclude_job_id_list_filter:
            request_params['excludeJobIdListFilter'] = exclude_job_id_list_filter
        if job_list_filter:
            request_params['jobListFilter'] = job_list_filter
        if exclude_job_list_filter:
            request_params['excludeJobListFilter'] = exclude_job_list_filter
        if group_path:
            request_params['groupPath'] = group_path
        if group_path_exact:
            request_params['groupPathExact'] = group_path_exact
        if exclude_group_path:
            request_params['excludeGroupPath'] = exclude_group_path
        if exclude_group_path_exact:
            request_params['excludeGroupPathExact'] = exclude_group_path_exact
        if job_filter:
            request_params['jobFilter'] = job_filter
        if exclude_job_filter:
            request_params['excludeJobFilter'] = exclude_job_filter
        if job_exact_filter:
            request_params['jobExactFilter'] = job_exact_filter
        if exclude_job_exact_filter:
            request_params['excludeJobExactFilter'] = exclude_job_exact_filter
        if execution_type_filter:
            request_params['executionTypeFilter'] = execution_type_filter
        if max_paging:
            request_params['max'] = max_paging
        if offset:
            request_params['offset'] = offset
        if project_name:
            project_name_to_pass = project_name
        else:
            project_name_to_pass = self.project_name

        request_params.update(self.params)

        return self._http_request(
            method='POST',
            url_suffix=f'/project/{project_name_to_pass}/executions',
            params=request_params,
        )


''' HELPER FUNCTIONS '''


def filter_results(results: list, fields_to_remove: list) -> List:
    new_results = []
    for record in results:
        new_record = {}
        for key, value in record.items():
            if key not in fields_to_remove:
                new_record[key] = value
        new_results.append(new_record)
    return new_results


def attribute_pairs_to_dict(attrs_str: Optional[str], delim_char: str = ","):
    """
    Transforms a string of multiple inputs to a dictionary list

    :param attrs_str: attributes separated by key=val pairs sepearated by ','
    :param delim_char: delimiter character between atrribute pairs
    :return:
    """
    if not attrs_str:
        return attrs_str
    attrs = {}
    regex = re.compile(r"(.*)=(.*)")
    for f in attrs_str.split(delim_char):
        match = regex.match(f)
        if match is None:
            raise ValueError(f"Could not parse field: {f}")

        attrs.update({match.group(1): match.group(2)})

    return attrs


def convert_str_to_int(val_to_convert: Optional[str], param_name: str) -> Optional[int]:
    if val_to_convert:
        try:
            return int(val_to_convert)
        except ValueError:
            raise DemistoException(f'\'{param_name}\' most be a number.')


''' COMMAND FUNCTIONS '''


def job_retry_command(client: Client, args: dict):
    arg_string: str = args.get('arg_string', '')
    log_level: str = args.get('log_level', '')  # TODO: add list options 'DEBUG','VERBOSE','INFO','WARN','ERROR'
    as_user: str = args.get('as_user', '')
    failed_nodes: str = args.get('failed_nodes', '')  # TODO: add list options 'true' or 'false'
    job_id: str = args.get('job_id')
    execution_id: str = args.get('execution_id')
    options: str = args.get('options')

    converted_options: dict = attribute_pairs_to_dict(options)
    result = client.retry_job(job_id, arg_string, log_level, as_user, failed_nodes, execution_id, converted_options)
    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    query_entries: list = createContext(
        result, keyTransform=underscoreToCamelCase
    )
    headers = [key.replace("-", " ") for key in [*result.keys()]]

    readable_output = tableToMarkdown('Execute Job:', result, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Rundeck.ExecutedJobs',
        outputs=query_entries,
        outputs_key_field='id'
    )


def execute_job_command(client: Client, args: dict):
    arg_string: str = args.get('arg_string', '')
    log_level: str = args.get('log_level', '')  # TODO: add list options 'DEBUG','VERBOSE','INFO','WARN','ERROR'
    as_user: str = args.get('as_user', '')
    node_filter: str = args.get('filter', '')
    run_at_time: str = args.get('run_at_time', '')
    options: str = args.get('options')
    job_id: str = args.get('job_id')

    converted_options: dict = attribute_pairs_to_dict(options)
    result = client.execute_job(job_id, arg_string, log_level, as_user, node_filter, run_at_time, converted_options)
    if not isinstance(result, dict):
        raise DemistoException(f"Got unexpected output from api: {result}")

    query_entries: list = createContext(
        result, keyTransform=underscoreToCamelCase
    )
    headers = [key.replace("-", " ") for key in [*result.keys()]]

    readable_output = tableToMarkdown('Execute Job:', result, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Rundeck.ExecutedJobs',
        outputs=query_entries,
        outputs_key_field='id'
    )


def project_list_command(client: Client):
    """
    This function returns a list of all existing projects.
    :param client: Demisto client
    :return: CommandResults object
    """
    result: list = client.get_project_list()
    if not isinstance(result, list):
        raise DemistoException(f"Got unexpected output from api: {result}")

    filtered_results = filter_results(result, ['url'])
    query_entries: list = createContext(
        filtered_results, keyTransform=underscoreToCamelCase
    )
    headers = [key.replace("_", " ") for key in [*filtered_results[0].keys()]]

    readable_output = tableToMarkdown('Projects List:', filtered_results, headers=headers,
                                      headerTransform=pascalToSpace)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Rundeck.Projects',
        outputs=query_entries,
        outputs_key_field='name'
    )


def jobs_list_command(client: Client, args: dict):
    """
    This function returns a list of all existing jobs.
    :param client: Demisto client
    :param args: command's arguments
    :return: CommandResults object
    """
    id_list: list = argToList(args.get('id_list', []))
    group_path: str = args.get('group_path', '')
    job_filter: str = args.get('job_filter', '')
    job_exec_filter: str = args.get('job_exec_filter', '')
    group_path_exact: str = args.get('group_path_exact', '')
    scheduled_filter: str = args.get('scheduled_filter', '')  # ￿￿￿￿￿ TODO: set it as list option 'true' or 'false'
    server_node_uuid_filter: str = args.get('server_node_uuid_filter', '')

    result = client.get_jobs_list(id_list, group_path, job_filter, job_exec_filter, group_path_exact, scheduled_filter,
                                  server_node_uuid_filter)
    if not isinstance(result, list):
        raise DemistoException(f"Got unexpected output from api: {result}")

    filtered_results = filter_results(result, ['href', 'permalink'])
    query_entries: list = createContext(
        filtered_results, keyTransform=underscoreToCamelCase
    )
    headers = [key.replace("_", " ") for key in [*filtered_results[0].keys()]]

    readable_output = tableToMarkdown('Jobs List:', filtered_results, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Rundeck.Jobs',
        outputs=query_entries,
        outputs_key_field='id'
    )


def webhooks_list_command(client: Client):
    """
    This function returns a list of all existing webhooks.
    :param client: Demisto client
    :return: CommandResults object
    """
    result = client.get_webhooks_list()
    if not isinstance(result, list):
        raise DemistoException(f"Got unexpected output from api: {result}")

    query_entries: list = createContext(
        result, keyTransform=underscoreToCamelCase
    )
    headers = [key.replace("_", " ") for key in [*result[0].keys()]]

    readable_output = tableToMarkdown('Webhooks List:', result, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Rundeck.Webhooks',
        outputs=query_entries,
        outputs_key_field='id'
    )


def job_execution_query_command(client: Client, args: dict):
    """
    This function returns a list of all existing executions.
    :param client: Demisto client
    :param args: command's arguments
    :return: CommandResults object
    """
    status_filter: str = args.get('status_filter', '')  # TODO: add a list options: "running", succeeded", "failed" or "aborted"
    aborted_by_filter: str = args.get('aborted_by_filter', '')
    user_filter: str = args.get('user_filter', '')
    recent_filter: str = args.get('recent_filter', '')
    older_filter: str = args.get('older_filter', '')
    begin: str = args.get('begin', '')
    end: str = args.get('end', '')
    adhoc: str = args.get('adhoc', '')  # TODO: add list options: true or false
    job_id_list_filter: list = argToList(args.get('job_id_list_filter', []))
    exclude_job_id_list_filter: list = argToList(args.get('exclude_job_id_list_filter', []))
    job_list_filter: list = argToList(args.get('job_list_filter', []))
    exclude_job_list_filter: list = argToList(args.get('exclude_job_list_filter', []))
    group_path: str = args.get('group_path', '')
    group_path_exact: str = args.get('group_path_exact', '')
    exclude_group_path_exact: str = args.get('exclude_group_path_exact', '')
    job_filter: str = args.get('job_filter', '')
    exclude_job_filter: str = args.get('exclude_job_filter', '')
    job_exact_filter: str = args.get('job_exact_filter', '')
    exclude_job_exact_filter: str = args.get('exclude_job_exact_filter', '')
    execution_type_filter: str = args.get('execution_type_filter', '')  #￿￿￿ TODO: add list options: scheduled, user, user-scheduled
    max_paging: Optional[int] = convert_str_to_int(args.get('max_paging'), 'max')
    offset: Optional[int] = convert_str_to_int(args.get('offset'), 'offset')
    project_name: str = args.get('project_name', '')
    exclude_group_path: str = args.get('exclude_group_path', '')

    result = client.job_execution_query(status_filter, aborted_by_filter, user_filter, recent_filter, older_filter,
                                        begin, end, adhoc, job_id_list_filter, exclude_job_id_list_filter,
                                        job_list_filter, exclude_job_list_filter,
                                        group_path, group_path_exact, exclude_group_path,
                                        exclude_group_path_exact, job_filter, exclude_job_filter,
                                        job_exact_filter, exclude_job_exact_filter, execution_type_filter,
                                        max_paging, offset, project_name)

    if isinstance(result, dict):
        result = result.get('executions')
        if not result:
            return "No results were found"

    query_entries: list = createContext(
        result, keyTransform=underscoreToCamelCase
    )
    headers = [key.replace("_", " ") for key in [*result[0].keys()]]

    readable_output = tableToMarkdown('Webhooks List:', result, headers=headers, headerTransform=pascalToSpace)
    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='Rundeck.Webhooks',
        outputs=query_entries,
        outputs_key_field='id'
    )


def test_module(client: Client) -> str:
    # INTEGRATION DEVELOPER TIP
    # Client class should raise the exceptions, but if the test fails
    # the exception text is printed to the Cortex XSOAR UI.
    # If you have some specific errors you want to capture (i.e. auth failure)
    # you should catch the exception here and return a string with a more
    # readable output (for example return 'Authentication Error, API Key
    # invalid').
    # Cortex XSOAR will print everything you return different than 'ok' as
    # an error
    # try:
    #     client.search_alerts(max_results=1, start_time=first_fetch_time, alert_status=None, alert_type=None, severity=None)
    # except DemistoException as e:
    #     if 'Forbidden' in str(e):
    #         return 'Authorization Error: make sure API Key is correctly set'
    #     else:
    #         raise e
    # return 'ok'
    pass


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    params: dict = demisto.params()
    token: str = params.get('token')
    project_name: str = params.get('project_name')

    # get the service API url
    base_url: str = urljoin(demisto.params()['url'], f'/api/{VERSION}')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not demisto.params().get('insecure', False)

    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = demisto.params().get('proxy', False)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    args: Dict = demisto.args()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            params={'authtoken': f'{token}'},
            project_name=project_name)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif demisto.command() == 'rundeck-projects-list':
            result = project_list_command(client)
            return_results(result)
        elif demisto.command() == 'rundeck-jobs-list':
            result = jobs_list_command(client, args)
            return_results(result)
        elif demisto.command() == 'rundeck-webhooks-list':
            result = webhooks_list_command(client)
            return_results(result)
        elif demisto.command() == 'rundeck-job-execute':
            result = execute_job_command(client, args)
            return_results(result)
        elif demisto.command() == 'rundeck-job-retry':
            result = job_retry_command(client, args)
            return_results(result)
        elif demisto.command() == 'rundeck-job-executions-query':
            result = job_execution_query_command(client, args)
            return_results(result)
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
