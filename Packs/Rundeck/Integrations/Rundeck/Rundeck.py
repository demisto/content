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


VERSION = 18

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """
    def __init__(self, base_url, project_name, params, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None):
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

    def get_jobs_list(self, id_list: list, group_path: str, job_filter: str, job_exec_filter: str, group_path_exact: str,
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


''' COMMAND FUNCTIONS '''


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

    readable_output = tableToMarkdown('Projects List:', filtered_results, headers=headers, headerTransform=pascalToSpace)
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
    scheduled_filter: str = args.get('scheduled_filter', '')
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
    result: list = client.get_webhooks_list()
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
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
