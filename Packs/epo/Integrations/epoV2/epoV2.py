import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import traceback
from typing import Any, Tuple, Dict

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

GET = 'GET'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
EPO_SYSTEM_ATTRIBUTE_MAP = {
    'Name': 'EPOComputerProperties.ComputerName',
    'Domain': 'EPOComputerProperties.DomainName',
    'Hostname': 'EPOComputerProperties.IPHostName',
    'IPAddress': 'EPOComputerProperties.IPAddress',
    'OS': 'EPOComputerProperties.OSType',
    'OSVersion': 'EPOComputerProperties.OSVersion',
    'Processor': 'EPOComputerProperties.CPUType',
    'Processors': 'EPOComputerProperties.NumOfCPU',
    'Memory': 'EPOComputerProperties.TotalPhysicalMemory',
}

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url: str, headers: dict, auth: tuple, timeout: int = 120, proxy: bool = False,
                 verify: bool = True):
        self.timeout = timeout
        super().__init__(base_url=base_url, headers=headers, auth=auth, proxy=proxy, verify=verify)

    def test_module(self) -> str:
        """
        Tests API connectivity and authentication

        """
        _, response = self.epo_help()
        return json.dumps(response)

    def epo_help(self, command: str = None, prefix: str = None) -> Tuple[dict, dict]:
        """

        Args:
            command (str): command to get detail help
            prefix (str): list all commands with the given prefix

        Returns (str):
            core.help command json output
        """
        params = {":output": "json"}
        if command:
            params['command'] = command
        elif prefix:
            params['prefix'] = prefix

        epo_response = self._http_request(method='GET',
                                          url_suffix='core.help',
                                          params=params,
                                          timeout=self.timeout,
                                          resp_type='text')
        return self._parse_response(epo_response)

    def epo_get_latest_dat(self) -> Tuple[dict, dict]:
        """
        a direct call to specific url to get the version of the most updated dat file
        dat file is the McAfee A/V software definitions file.
        """
        dat_file_url = 'http://update.nai.com/products/commonupdater/gdeltaavv.ini'
        raw_response = self._http_request(
            method=GET,
            full_url=dat_file_url,
            resp_type='text',
            timeout=self.timeout)
        latest_version = raw_response.split('\r\n\r\n')[0].split('CurrentVersion=')[1]
        json_response = {'LatestVersion': latest_version}

        return json_response, raw_response

    def epo_get_current_dat(self) -> Tuple[dict, dict]:
        """
        returns the currently installed dat file on the ePO system
        Returns(str):
        returns the version number of the currently installed dat file
        """
        params = {
            'searchText': 'VSCANDAT1000',
            ':output': 'json'
        }
        url_suffix = 'repository.findPackages'
        response = self._http_request(method=GET, url_suffix=url_suffix, params=params, resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def epo_command(self, command: str, params: dict, resp_type: str = 'json') -> Tuple[dict, dict]:
        """
        Runs any given command
        Args:
            command (str): command
            resp_type (str): define response type format
            params (dict): dictionary represents the arguments
        Returns:
        the command result
        """
        if resp_type == 'json':
            params[':output'] = 'json'

        response = self._http_request(method=GET,
                                      url_suffix=command,
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def update_client_dat(self, names: str, product_id: str, task_id: str,
                          retry_attempts: str = None,
                          retry_interval_in_seconds: str = None,
                          abort_after_minutes: str = None,
                          stop_after_minutes: str = None,
                          randomization_interval: str = None
                          ) -> Tuple[dict, dict]:

        params = {
            'names': names,
            ':output': 'json',
            'productId': product_id,
            'taskId': task_id
        }

        if retry_attempts:
            params['retryAttempts'] = retry_attempts
        if retry_interval_in_seconds:
            params['retryIntervalInSeconds'] = retry_interval_in_seconds
        if abort_after_minutes:
            params['abortAfterMinutes'] = abort_after_minutes
        if stop_after_minutes:
            params['stopAfterMinutes'] = stop_after_minutes
        if randomization_interval:
            params['randomizationInterval'] = randomization_interval

        response = self._http_request(method=GET,
                                      url_suffix='clienttask.run',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def get_client_task_id_by_name(self, search_text: str) -> Tuple[str, str]:
        """
         list all client tasks in ePO server
        Args:
            search_text (str): filter client task list and list task contain searchText

        Returns:
            list the found the client task
        """
        params = {'searchText': search_text,
                  ':output': 'json'}
        raw_response = self._http_request(method=GET,
                                          url_suffix='clienttask.find',
                                          params=params,
                                          resp_type='text',
                                          timeout=self.timeout)

        json_response, response = self._parse_response(raw_response)

        if len(json_response) > 0:
            if json_response and isinstance(json_response, list):
                json_response = json_response[0]

            if 'objectId' in json_response:
                object_id = json_response['objectId']
            else:
                object_id = ""
                demisto.debug("no objectId in json_response")
            if 'productId' in json_response:
                product_id = json_response['productId']
            else:
                product_id = ""
                demisto.debug("no productId in json_response")

            return object_id, product_id
        else:
            # If reached here then the response is an empty "OK:", which means VSEContentUpdateDemisto was not found in
            # the server
            raise DemistoException(
                'Error getting DAT update task. It seems the task "VSEContentUpdateDemisto" is missing from the EPO '
                'server. Please contact support for more details')

    def update_repository(self, source_repo: str, target_branch: str) -> Tuple[dict, dict]:
        """
        Updating the local repository on the ePO from the public server.
        Returns:
        command submission status
        """
        params = {
            'sourceRepository': 'McAfeeHttp',
            'targetBranch': 'Current'
        }
        raw_response = self._http_request(method=GET,
                                          url_suffix='repository.pull',
                                          params=params,
                                          resp_type='text',
                                          timeout=self.timeout)
        return self._parse_response(raw_response)

    def get_system_tree_groups(self, search_text: str = None):
        """
        find a group of machine in the epo system tree
        Args:
            search_text (str): group name
        Returns:

        """
        params = {
            ':output': 'json'
        }
        if search_text:
            params['searchText'] = search_text

        raw_response = self._http_request(method=GET,
                                          url_suffix='system.findGroups',
                                          params=params,
                                          resp_type='text',
                                          timeout=self.timeout)
        return self._parse_response(raw_response)

    def get_system_group_path(self, group_id: int) -> str:
        """
        return the system group path for giving group_id
        Args:
            group_id (str): the groupID to find
        Returns (str): returns the system group path for a giving group id
        """
        response_json, response = self.get_system_tree_groups(search_text='')
        if response is None:
            return ''

        for entry in response_json:
            if group_id == entry['groupId']:
                return entry['groupPath']
        return ''

    def find_systems(self, group_id: int) -> Tuple[dict, dict]:
        """
        find all systems belongs to the given group Id
        Args:
            group_id (int): group Id to find in the system tree
        Returns:
            a list of system in json
        """

        params = {
            ':output': 'json',
            'groupId': group_id
        }
        raw_response = self._http_request(method=GET,
                                          url_suffix='epogroup.findSystems',
                                          params=params,
                                          resp_type='text',
                                          timeout=self.timeout)
        return self._parse_response(raw_response)

    def find_system(self, search_text: str) -> Tuple[dict, dict]:
        """
        find system in the ePO Server system tree
        Args:
            search_text (str): system name
        Returns:
            a list of system in json
        """
        params = {
            'searchText': search_text,
            ':output': 'json'
        }
        response = self._http_request(method=GET,
                                      url_suffix='system.find',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def wakeup_agent(self, names: str) -> Tuple[dict, dict]:
        """
        wakeup agent for as system or list of systems
        Args:
            names (str):
        Returns:
            operation result
        """
        params = {
            'names': names,
            ':output': 'json'
        }

        response = self._http_request(method=GET,
                                      url_suffix='system.wakeupAgent',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)

        # response = response.split('"')[1] if response.startswith('"') else response
        # response = response.replace(r'\n', '\n')
        return self._parse_response(response)

    def apply_tag(self, names: str, tag_name: str) -> Tuple[int, dict]:
        """
        Apply the given tag name to machine(s) in names
        Args:
            names (str): machine id or list of machine ids
            tag_name (str):
        Returns:
            operation result
        """
        params = {
            'names': names,
            'tagName': tag_name,
            ':output': 'json'
        }
        response = self._http_request(method=GET,
                                      url_suffix='system.applyTag',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def clear_tag(self, names: str, tag_name: str) -> Tuple[int, dict]:
        """
        Clear the given tag name for machine(s) in names
        Args:
            names (str): machine id or list of machine ids
            tag_name (str):
        Returns:
            operation result
        """
        params = {
            'names': names,
            'tagName': tag_name,
            ':output': 'json'
        }
        response = self._http_request(method=GET,
                                      url_suffix='system.clearTag',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def list_tag(self, search_text: str = None) -> Tuple[dict, dict]:
        """
        List tags available on ePO server
        Args:
            search_text (str): filter tags contains search_text
        Returns:
            list of tags
        """
        params = {
            'searchText': search_text,
            ':output': 'json'
        }
        response = self._http_request(method=GET,
                                      url_suffix='system.findTag',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def get_table(self, table_name: str = None) -> Tuple[dict, dict]:
        """
        Get tables from ePO server
        Args:
            table_name (): list tables that contains table_name
        Returns:
            lists of tables
        """
        params = {
            ':output': 'json'
        }
        if table_name:
            params['table'] = table_name

        response = self._http_request(method=GET,
                                      url_suffix='core.listTables',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def query_table(self,
                    target: str = None,
                    select: str = None,
                    where: str = None,
                    order: str = None,
                    group: str = None,
                    join_tables: str = None,
                    ) -> Tuple[dict, dict]:
        """
        query tables from ePO server
        Args:
            target (str): tablename to run query on
            select (str): The columns to select, in SQUID syntax.
                          Example: "(select EPOEvents.AutoID EPOEvents.DetectedUTC EPOEvents.ReceivedUTC)"
            where (str): Filter results, in SQUID syntax. Example: "(where ( eq ( OrionTaskLogTask .UserName "ga" )))"
            order (str): Order in which to return the results, in SQUID syntax.
                         Example: "(order (asc OrionTaskLogTask.StartDate) )"
            group (str): Group the results, in SQUID Syntax. Example: "(group EPOBranchNode.NodeName)"
            join_tables (str): The comma-separated list of SQUID targets to join with the target
                              type; * means join with all types
        Returns:
            query result
        """
        params = {
            ":output": "json"
        }
        if target:
            params['target'] = target

        if select:
            params['select'] = select

        if where:
            params['where'] = where

        if order:
            params['order'] = order

        if group:
            params['group'] = group

        if join_tables:
            params['joinTables'] = join_tables

        response = self._http_request(method=GET,
                                      url_suffix='core.executeQuery',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def get_version(self) -> Tuple[dict, dict]:
        """
        Get ePO Software Version
        Returns:
            return ePO Software version
        """
        params = {':output': 'json'}
        response = self._http_request(method=GET,
                                      url_suffix='epo.getVersion',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def move_system(self, names: str, parent_group_id: int) -> Tuple[dict, dict]:
        """
           Moves systems to a specified destination group by name or ID as returned
        Args:
           names (str): List of machine or machine id
           parent_group_id (int): destination parent group id
        Returns:
           lists of tables
        """
        params = {'names': names, 'parentGroupId': parent_group_id}
        response = self._http_request(method=GET,
                                      url_suffix='system.move',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def find_client_task(self, search_text: str = None) -> Tuple[dict, dict]:
        """
           find client task in the ePo system
        Args:
           search_text (str): List client tasks that contains searchText in their name field.
        Returns:
           lists of tables
        """
        params = {':output': 'json'}
        if search_text:
            params['searchText'] = search_text
        response = self._http_request(method=GET,
                                      url_suffix='clienttask.find',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def find_policy(self, search_text: str = None) -> Tuple[dict, dict]:
        """
           find policy task in the ePo system
        Args:
           search_text (str): List policies that contains searchText in their name field.
        Returns:
           lists of tables
        """
        params = {':output': 'json'}
        if search_text:
            params['searchText'] = search_text
        response = self._http_request(method=GET,
                                      url_suffix='policy.find',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def assign_policy_to_group(self, group_id: int, product_id: str, object_id: int,
                               reset_inheritance: str = 'false') -> Tuple[int, dict]:
        """
           Assign policy to group of machines
        Args:
           group_id (int): System tree Group ID.(as returned by system.findGroups)
           product_id (int): Product ID.(as returned by policy.find)
           object_id (int): Object ID.(as returned by policy.find)
           reset_inheritance (str):If true resets the inheritance for the specified policy on the given group. Defaults
                                    to false.
        Returns:
           string indication
        """
        params = {':output': 'json', 'groupId': group_id, 'productId': product_id, 'objectId': object_id,
                  'resetInheritance': reset_inheritance}
        response = self._http_request(method=GET,
                                      url_suffix='policy.assignToGroup',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def assign_policy_to_system(self, names: str, product_id: str, type_id: int, object_id: int,
                                reset_inheritance: str = 'false') -> Tuple[dict, dict]:
        """
           Assign policy to system(s)
        Args:
           names (int): list of system or system
           product_id (int): Product ID.(as returned by policy.find)
           type_id (int): Type ID.(as returned by policy.find)
           object_id (int): Object ID.(as returned by policy.find)
           reset_inheritance (str):If true resets the inheritance for the specified policy on the given group. Defaults
                                    to false.
        Returns:
           string indication
        """
        params = {':output': 'json', 'names': names, 'productId': product_id, 'typeId': type_id, 'objectId': object_id,
                  'resetInheritance': reset_inheritance}
        response = self._http_request(method=GET,
                                      url_suffix='policy.assignToSystem',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def list_issue(self, issue_id: str = '') -> Tuple[dict, dict]:
        """
        list issue in the system
        Args:
            issue_id (str): issue id to list if given
        Returns:
            list of issue
        """
        params = {
            ':output': 'json'
        }
        if issue_id:
            params['id'] = issue_id

        response = self._http_request(method=GET,
                                      url_suffix='issue.listIssues',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def delete_issue(self, issue_id: str) -> Tuple[dict, dict]:
        """
        delete issue in the system
        Args:
            issue_id (str): issue id to list if given
        Returns:
            list of issue
        """
        params = {':output': 'json', 'id': issue_id}

        response = self._http_request(method=GET,
                                      url_suffix='issue.deleteIssue',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def update_issue(self, issue_id: str,
                     issue_name: str = None,
                     issue_description: str = None,
                     issue_state: str = None,
                     issue_priority: str = None,
                     issue_severity: str = None,
                     issue_resolution: str = None,
                     issue_due: str = None,
                     issue_assignee_name: str = None,
                     issue_ticket_server_name: str = None,
                     issue_ticket_id: str = None,
                     issue_properties: str = None) -> Tuple[dict, dict]:
        """
        update an issue
        Args:
            issue_id (str): issue Id
            issue_name (str): Optional issue name
            issue_description (str): Optional issue description
            issue_state (str): Optional issue state
            issue_priority (str): Optional issue priority
            issue_severity (str): Optional issue severity
            issue_resolution (str): Optional issue resolution
            issue_due (str): Optional issue due
            issue_assignee_name (str): Optional  issue assignee name
            issue_ticket_server_name (str): Optional ticket server name
            issue_ticket_id (str): Optional issue ticket id
            issue_properties (str): Optional issue properties
        Returns:

        """
        params = {':output': 'json',
                  'id': issue_id}
        if issue_name:
            params['name'] = issue_name
        if issue_description:
            params['desc'] = issue_description
        if issue_state:
            params['state'] = issue_state
        if issue_priority:
            params['priority'] = issue_priority
        if issue_severity:
            params['severity'] = issue_severity
        if issue_resolution:
            params['resolution'] = issue_resolution
        if issue_due:
            params['due'] = issue_due
        if issue_assignee_name:
            params['assigneeName'] = issue_assignee_name
        if issue_ticket_server_name:
            params['ticketServerName'] = issue_ticket_server_name
        if issue_ticket_id:
            params['ticketId'] = issue_ticket_id
        if issue_properties:
            params['properties'] = issue_properties

        response = self._http_request(method=GET,
                                      url_suffix='issue.updateIssue',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    def create_issue(self,
                     issue_name: str,
                     issue_description: str,
                     issue_state: str = None,
                     issue_priority: str = None,
                     issue_severity: str = None,
                     issue_resolution: str = None,
                     issue_due: str = None,
                     issue_assignee_name: str = None,
                     issue_ticket_server_name: str = None,
                     issue_ticket_id: str = None,
                     issue_properties: str = None) -> Tuple[dict, dict]:
        """
        create an issue
        Args:
            issue_name (str): Optional issue name
            issue_description (str): Optional issue description
            issue_state (str): Optional issue state
            issue_priority (str): Optional issue priority
            issue_severity (str): Optional issue severity
            issue_resolution (str): Optional issue resolution
            issue_due (str): Optional issue due
            issue_assignee_name (str): Optional  issue assignee name
            issue_ticket_server_name (str): Optional ticket server name
            issue_ticket_id (str): Optional issue ticket id
            issue_properties (str): Optional issue properties
        Returns:

        """
        params = {':output': 'json', 'name': issue_name, 'desc': issue_description}
        if issue_state:
            params['state'] = issue_state
        if issue_priority:
            params['priority'] = issue_priority
        if issue_severity:
            params['severity'] = issue_severity
        if issue_resolution:
            params['resolution'] = issue_resolution
        if issue_due:
            params['due'] = issue_due
        if issue_assignee_name:
            params['assigneeName'] = issue_assignee_name
        if issue_ticket_server_name:
            params['ticketServerName'] = issue_ticket_server_name
        if issue_ticket_id:
            params['ticketId'] = issue_ticket_id
        if issue_properties:
            params['properties'] = issue_properties

        response = self._http_request(method=GET,
                                      url_suffix='issue.createIssue',
                                      params=params,
                                      resp_type='text',
                                      timeout=self.timeout)
        return self._parse_response(response)

    @staticmethod
    def _parse_response(response: str) -> Tuple[Any, Any]:
        """
        Parses the raw response returned from a remote command invocation, returning
        its content, which is trimmed of leading and trailing whitespace.
        The input will look like the following:

        OK:\r\ntrue                                ---->  returns "true"

        or in the error case,

        "Error # :\r\nSome error string goes here  ---->  throws CommandInvokerError(#, "Some error string goes here")

        where # is the integer representing the error code returned.

        @param response - the raw response from the server
        @throws DemistoException if the response from the server indicates an Error state
        @returns response from the server stripped of the protocol

        """
        code = 0
        try:
            status = response[:response.index(':')].split(' ')[0]
            result = response[response.index(':') + 1:].strip()
            if status == 'Error':
                code = int(response[:response.index(':')].split(' ')[1])
            else:
                code = 0
            res = {'status': status, 'code': code, 'result': result}
        except Exception:
            # for thoroughness, in case there's no colon in the output or something else
            # Or there was an error parsing the returned result from the server
            res = {'status': 'Error', 'code': code, 'result': 'Unable to parse the server\'s response'}
            err_msg = 'Error in API call [{}] - {}'.format(demisto.command, res['result'])
            demisto.error(err_msg)
            raise DemistoException(f"Error occurred. Status: ({res['status']}) Code: ({res['code']}) Result: "
                                   f"{res['result']}")

        if res['status'] == 'OK':
            try:
                json_response = json.loads(str(res['result']))
            except (TypeError, json.JSONDecodeError):
                json_response = res['result']
            return json_response, json_response
        elif res['status'] == 'Error':
            raise DemistoException(f"Error occurred. Status: ({res['status']}) Code: ({res['code']}) Result: "
                                   f"{res['result']}")
        else:
            raise DemistoException(f"Unknown error occurred.  Status: {res['status']} Result: {res['result']}")


''' HELPER FUNCTION'''


def prettify_system_tree(system_tree: dict) -> list:
    """
    reformatting the system tree output to fit the integration requirements

    :type system_tree: ``dict``
    :param system_tree: A dictionary that represent system tree

    Returns:
        List of dictionaries that to be populated in the context data
    """
    context_data_system_tree = []
    for system in system_tree:
        context_data_system_tree.append({
            'groupId': system["groupId"],
            'groupPath': system["groupPath"]
        })
    return context_data_system_tree


def prettify_find_system(find_system: list, extended: bool = True) -> list:
    """
    returns the list of dictionaries that fit with the context data requirements
    Args:
        find_system (list): dictionary contains list of systems
        extended (bool): to export all system information as context data this is the default behavior

    Returns: returns the list of dictionaries that fit with the context data requirements
    """
    context_data_find_system = []
    for system in find_system:
        if extended:
            system_xsoar = {}
            for key in system:
                modified_key = key.split('.')[1]
                system_xsoar[modified_key] = system[key]
            context_data_find_system.append(system_xsoar)
        else:
            context_data_find_system.append({
                'Name': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Name')),
                'Domain': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Domain')),
                'Hostname': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Hostname')),
                'IPAddress': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('IPAddress')),
                'OS': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('OS')),
                'OSVersion': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('OSVersion')),
                'Processor': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Processor')),
                'Processors': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Processors')),
                'Memory': system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Memory'))
            })
    return context_data_find_system


def system_to_md(system: dict, verbose: bool = False) -> str:
    """
        reformatting system information dictionary to markdown
    Args:
        system (dict): dictionary representation for system information
        verbose (boolean): verbosity boolean

    Returns:
        markdown representation for system information
    """
    md = ''
    if verbose:
        md += f'#### {system.get("EPOComputerProperties.ComputerName")} \n'
        md += 'Attribute|Value\n-|-\n'
        for key in system:
            md += f'{key} | {system[key]}\n'

        md += '---\n'
    else:
        md += '|'
        for key in EPO_SYSTEM_ATTRIBUTE_MAP:
            md += f'{system.get(EPO_SYSTEM_ATTRIBUTE_MAP.get(key))} |'

        md += '\n'
    return md


def systems_to_md(systems: dict, verbose: bool = False) -> str:
    """
        reformatting system information dictionary to markdown
    Args:
        systems (list): list of dictionaries, each dictionary represent a system
        verbose (boolean): verbosity boolean

    Returns:
        markdown representation for systems list
    """
    md = ''
    if verbose:
        for system in systems:
            md += system_to_md(system, verbose)
    else:
        tmp_head = '|'
        tmp_line = '|'
        for key in EPO_SYSTEM_ATTRIBUTE_MAP:
            tmp_head += key + '|'
            tmp_line += '-|'

        md += f'{tmp_head} \n {tmp_line} \n'
        for system in systems:
            md += system_to_md(system, verbose)
    return md


def parse_command_args(command: str, command_args: str) -> dict:
    # commandArgs should be in the format of:  keyName1:keyValue1, keyName2:KeyValue2
    if not command_args:
        return {}

    command_args_dict = {"command": command}
    command_args_list = command_args.split(',')
    key = []
    for arg in command_args_list:
        # commandArgsVal in commandArgsList:
        key = arg.split(':')
        command_args_dict[key[0]] = key[1]
    return command_args_dict


''' COMMAND FUNCTIONS '''


def epo_help_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Displays a list of all commands and help strings.
    XSOAR Cmd example: !epo-help command=epo.help
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.

    Returns:
        CommandResults with fancy help command output

    """

    command = args.get('command')
    search = args.get('search')
    prefix = args.get('prefix')

    json_response, raw_response = client.epo_help(command=command, prefix=prefix)

    if 'command' in args:
        readable_output = f"#### ePO Help - {args['command']} \n "
        for line in json_response:
            line = line.replace("\r\n", ' ')
            line = line.replace('\n', ' ')
            readable_output += line
    else:
        if search:
            search = search.lower()
        readable_output = '#### ePO Help\n'
        for line in json_response:
            line = line.replace("\r\n", ' ')
            line = line.replace('\n', ' ')

            if (not search) or (search in line.lower()):
                desc = ''
                cmd = ''
                if '-' in line:
                    desc = line.split('-')[1] if line.split('-')[1] else 'N/A'
                    cmd = line.split('-')[0].rstrip() if line.split('-')[0] else 'N/A'
                    readable_output += "- **" + cmd + "** - " + desc + '\n'

    return CommandResults(
        readable_output=readable_output
    )


def epo_get_latest_dat_command(client: Client) -> CommandResults:
    """
    get the latest available version of the dat file.
    dat file is the McAfee A/V software definition file.
    XSOAR Cmd example: !epo-get-latest-dat
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
    Returns:
        CommandResults (dict)
    """

    json_response, raw_response = client.epo_get_latest_dat()

    latest_dat_version = json_response.get('LatestVersion')
    readable_output = f'McAfee ePO Latest DAT file version available is: **{latest_dat_version}**\n'

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='McAfee.ePO.latestDAT',
        outputs=latest_dat_version,
        raw_response=raw_response
    )


def epo_get_current_dat_command(client: Client) -> CommandResults:
    """
    return the current installed dat file.
    dat file contains
    XSOAR CMD example: !epo-get-current-dat
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
    Returns:
        CommandResults
    """
    json_response, raw_response = client.epo_get_current_dat()
    if 'productDetectionProductVersion' in json_response[0]:
        current_dat_version = json_response[0]['productDetectionProductVersion'].split('.')[0]
    else:
        raise DemistoException('The installed DAT file version key is missing')

    current_version = {
        'CurrentVersion': current_dat_version
    }
    current_dat_version = current_version.get('CurrentVersion')
    readable_output = f'McAfee ePO Current DAT file version in repository is: **{current_dat_version}**\n'

    return CommandResults(
        outputs_prefix='McAfee.ePO.epoDAT',
        outputs=current_dat_version,
        readable_output=readable_output,
        raw_response=raw_response
    )


def epo_command_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Executes the ePO command
    XSOAR CMD example: !epo-command command=system.find searchText=10.0.0.1
    headers=EPOBranchNode.AutoID,EPOComputerProperties.ComputerName
        Args: client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.

    Returns:
        CommandResults
    """
    command = args.get('command')
    if not command:
        raise DemistoException('missing argument: **command**')

    resp_type = args.get('resp_type', 'json')

    params = {}

    if len(args) > 0:
        for key in args:
            if key in ['command', 'headers', 'resp_type']:
                continue
            params[key] = args.get(key)

    response_json, raw_response = client.epo_command(command=command, params=params, resp_type=resp_type)

    if resp_type != 'json':
        response_json = raw_response  # type: ignore

    if 'headers' in args:
        headers_list = list(args['headers'].split(','))
        md = tableToMarkdown(f'ePO command *{args["command"]}* results:', response_json, headers=headers_list)
    else:
        if isinstance(response_json, dict):
            headers_list = list(response_json.keys())
            md = tableToMarkdown(f'ePO command *{args["command"]}* results:', response_json, headers=headers_list)
        elif isinstance(response_json, str):
            md = f'#### ePO command *{args["command"]} * results:\n  {response_json}'
        elif isinstance(response_json, list) and len(response_json) and isinstance(response_json[0], str):
            headers_list = "output"
            md = tableToMarkdown(f'ePO command *{args["command"]}* results:', response_json, headers_list)
        else:
            try:
                headers_list = list(set().union(*(entry.keys() for entry in response_json)))
                md = tableToMarkdown(f'ePO command *{args["command"]}* results:', response_json, headers_list)
            except Exception:
                md = tableToMarkdown(f'ePO command *{args["command"]}* results:', response_json)

    return CommandResults(
        raw_response=raw_response,
        readable_output=md)


def epo_update_client_dat_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Executes the ePO command
       XSOAR CMD example: !epo-update-client-dat systems=192.168.1
       Args:
           client (Client: BaseClient): a utility class used for communicating with ePO Server
           args (dict): a dictionary that store the command argument.

       Returns:
           CommandResults
    """
    names: str = args.get('systems', str)
    if names is None:
        raise ValueError('Must provide systems')
    client_task_id, client_product_id = client.get_client_task_id_by_name(search_text='VSEContentUpdateDemisto')
    retry_attempts = args.get('retryAttempts', '')
    retry_interval_in_seconds = args.get('retryIntervalInSeconds', '')
    abort_after_minutes = args.get('abortAfterMinutes', '')
    stop_after_minutes = args.get('stopAfterMinutes', '')
    randomization_interval = args.get('randomizationInterval', '')

    json_response, response = client.update_client_dat(names,
                                                       client_product_id,
                                                       client_task_id,
                                                       retry_attempts=retry_attempts,
                                                       retry_interval_in_seconds=retry_interval_in_seconds,
                                                       abort_after_minutes=abort_after_minutes,
                                                       stop_after_minutes=stop_after_minutes,
                                                       randomization_interval=randomization_interval)

    md = f'ePO client DAT update task started: {json_response}'
    return CommandResults(
        raw_response=response,
        readable_output=md
    )


def epo_update_repository_command(client: Client) -> CommandResults:
    """
    Triggers a server task in specific ePO servers to retrieve the latest signatures from the update server.

    Args:
         client (Client: BaseClient): a utility class used for communicating with ePO Server
    Returns:
        CommandResults

    """

    source_repo = 'McAfeeHttp'
    target_branch = 'Current'
    json_response, response = client.update_repository(source_repo, target_branch)

    md = "ePO repository update started.\n"
    md += str(json_response)
    return CommandResults(
        raw_response=response,
        readable_output=md
    )


def epo_get_system_tree_groups_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        find a group of machine in the epo system tree
        XSOAR CMD example:!epo-get-system-tree-group search="Lost"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    search_text = args.get('search')

    json_response, raw_response = client.get_system_tree_groups(search_text=search_text)
    if isinstance(raw_response, str) and len(raw_response) == 0:
        return CommandResults(
            raw_response=raw_response,
            readable_output=f'System Tree Group {search_text} was not found.'
        )

    md = "#### ePO System Tree groups\n"
    md += "Group ID | Group path\n-|-\n"
    for entry in json_response:
        md += f'{entry["groupId"]}  | {entry["groupPath"]} \n'

    return CommandResults(
        raw_response=raw_response,
        readable_output=md,
        outputs_prefix='McAfee.ePO.SystemTreeGroups',
        outputs_key_field='groupId',
        outputs=prettify_system_tree(json_response)
    )


def epo_find_systems_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
        find a group of machine in the epo system tree
        XSOAR CMD Example: !epo-find-systems groupId=2
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    group_id = arg_to_number(args.get('groupId', str))
    if group_id is None:
        raise ValueError('Must provide groupId')

    verbose = args.get('verbose', 'false') == 'true'
    name = client.get_system_group_path(group_id)

    if not name:
        raise DemistoException(f'Could not find group with the given group id {group_id}')

    response_json, response = client.find_systems(group_id)

    if response:
        md = '#### Systems in ' + name + '\n'
        if len(response_json) > 0:
            md += systems_to_md(response_json, verbose)
            endpoints = prettify_find_system(list(response_json))
            res = [CommandResults(
                raw_response=response,
                readable_output=md,
                outputs_prefix='McAfee.ePO.Endpoint',
                outputs_key_field='IPAddress',
                outputs=endpoints,
            )]
            count = 0
            for endpoint_info in endpoints:
                endpoint = Common.Endpoint(
                    id=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Hostname', str).split('.')[1], ''),
                    hostname=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Hostname', str).split('.')[1], ''),
                    ip_address=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('IPAddress', str).split('.')[1], ''),
                    domain=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Domain', str).split('.')[1], ''),
                    os=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('OS', str).split('.')[1], ''),
                    os_version=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('OSVersion', str).split('.')[1], ''),
                    processor=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Processor', str).split('.')[1], ''),
                    processors=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Processors', str).split('.')[1], ''),
                    memory=endpoint_info.get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Memory', str).split('.')[1], ''))

                md = tableToMarkdown('Endpoint information:',
                                     prettify_find_system([response_json[count]], False), removeNull=True)
                res.append(CommandResults(readable_output=md, indicator=endpoint))

            return res
        else:
            md += 'No systems found\n'
            return [CommandResults(raw_response=response, readable_output=md)]
    else:
        raise DemistoException(f'No systems found. Response: {response}')


def epo_find_system_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        find a a system in the epo system tree
        XSOAR CMD example: !epo-find-system searchText="TIE"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """

    search_text: str = args.get('searchText', str)
    verbose = args.get('verbose', 'false') == 'true'

    response_json, response = client.find_system(search_text)

    md = '#### Systems in the System Tree\n'
    if len(response_json) > 0:
        md += systems_to_md(response_json, verbose)
        endpoint_info = prettify_find_system(list(response_json))
        endpoint = Common.Endpoint(
            id=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Hostname', str).split('.')[1], ''),
            hostname=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Hostname', str).split('.')[1], ''),
            ip_address=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('IPAddress', str).split('.')[1], ''),
            domain=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Domain', str).split('.')[1], ''),
            os=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('OS', str).split('.')[1], ''),
            os_version=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('OSVersion', str).split('.')[1], ''),
            processor=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Processor', str).split('.')[1], ''),
            processors=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Processors', str).split('.')[1], ''),
            memory=endpoint_info[0].get(EPO_SYSTEM_ATTRIBUTE_MAP.get('Memory', str).split('.')[1], ''))
        return CommandResults(
            raw_response=response,
            readable_output=md,
            outputs_prefix='McAfee.ePO.Endpoint',
            outputs_key_field='IPAddress',
            outputs=prettify_find_system(list(response_json)),
            indicator=endpoint
        )
    else:
        md += 'No systems found\n'
        return CommandResults(raw_response=response,
                              readable_output=md)


def epo_wakeup_agent_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        wake up agent for a system or list of systems
        XSOAR CMD example:epo-wakeup-agent names="TIE"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    names = args.get('names', str)
    response_json, response = client.wakeup_agent(names)
    response_str = json.dumps(response)
    if response_str.find('No systems found') >= 0:
        md = '#### No systems were found.'
    else:
        md = '#### ePO agents was awaken.\n'
        pattern_match = re.search(r'completed:\s([-]*\d+)\\nfailed:\s([-]*\d+)\\nexpired:\s([-]*\d+)', response_str)
        if pattern_match:
            md += '| Completed | Failed | Expired |\n'
            md += '|-|-|-|\n'
            for i in pattern_match.groups():
                md += '|' + i
            md += '|'
    return CommandResults(
        raw_response=response,
        readable_output=md
    )


def epo_apply_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        apply tag to a machine or machines
        XSOAR CMD example: !epo-apply-tag names="TIE" tagName="Server"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    names = args.get('names', str)
    tag_name = args.get('tagName', str)

    response_int, response = client.apply_tag(names, tag_name)

    if response_int > 0:
        md = "ePO applied the tags on the hostnames successfully.\n"
    else:
        md = "ePO could not find server or server already assigned to the given tag.\n"

    return CommandResults(
        raw_response=response,
        readable_output=md
    )


def epo_clear_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        apply tag to a machine or machines
        XSOAR CMD example: !epo-clear-tag names="TIE" tagName="MARSERVER"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    names = args.get('names', str)
    tag_name = args.get('tagName', str)

    response_json, response = client.clear_tag(names, tag_name)

    if response_json > 0:
        md = 'ePO cleared the tags from the hostnames successfully.\n'
    else:
        md = "ePO could not find server or server already assigned to the given tag.\n"

    return CommandResults(
        raw_response=response,
        readable_output=md
    )


def epo_list_tag_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        apply tag to a machine or machines
        XSOAR CMD example: !epo-list-tag searchText="server"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    search_text = args.get('searchText')

    response_json, response = client.list_tag(search_text=search_text)

    md = tableToMarkdown("ePO Tags", response_json, headers=['tagId', 'tagName', 'tagNotes'])
    return CommandResults(
        outputs=response_json,
        outputs_prefix='McAfee.ePO.Tags',
        outputs_key_field='tagId',
        raw_response=response,
        readable_output=md
    )


def epo_get_tables_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        get table details from ePO
        XSOAR CMD example: !epo-get-tables table="Client Events"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    table_name = args.get('table')
    response_json, response = client.get_table(table_name=table_name)

    if type(response_json) is dict:
        headers = list(response_json.keys())
    else:
        headers = list(set().union(*(entry.keys() for entry in response_json)))
    md = tableToMarkdown(
        'ePO tables:',
        response_json,
        headers=headers,
    )
    return CommandResults(
        raw_response=response,
        readable_output=md
    )


def epo_query_table_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        query table details from ePO
        XSOAR CMD example: !epo-query-table target="FW_Rule"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """

    target = args.get('target')
    select = args.get('select')
    where = args.get('where')
    order = args.get('order')
    group = args.get('group')
    join_tables = args.get('joinTables')
    query_name = args.get('query_name')

    response_json, response = client.query_table(target=target,
                                                 select=select,
                                                 where=where,
                                                 order=order,
                                                 group=group,
                                                 join_tables=join_tables)

    if type(response_json) is dict:
        headers = list(response_json.keys())
    else:
        headers = list(set().union(*(entry.keys() for entry in response_json)))

    if query_name:
        query_title = query_name
    else:
        query_title = target

    md = tableToMarkdown(
        f'ePO Table Query: {query_title}',
        response_json,
        headers
    )
    prefix = f'McAfee.ePO.Query.{query_title}'
    return CommandResults(
        raw_response=response,
        readable_output=md,
        outputs=response_json,
        outputs_prefix=prefix
    )


def epo_get_version_command(client: Client) -> CommandResults:
    """
    Get ePO Server Software Version
    XSOAR CMD Example: !epo-get-version
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
    Returns:
        CommandResults

    """
    response_json, response = client.get_version()

    readable_output = f'### ePO version is: {response_json}'

    return CommandResults(
        raw_response=response,
        readable_output=readable_output,
        outputs=response_json,
        outputs_prefix='McAfee.ePO.Version',
        outputs_key_field='Version'
    )


def epo_move_system_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
       Moves systems to a specified destination group ID
       XSOAR CMD example: !epo-move-system names="TIE" parentGroupId="3"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    names = args.get('names', str)
    parent_group_id = arg_to_number(args.get('parentGroupId'))
    if parent_group_id is None:
        raise ValueError('Must provide parentGroupId')

    json_response, raw_response = client.move_system(names=names, parent_group_id=parent_group_id)

    if json_response:
        response = f'System(s) {names} moved successfully to GroupId {parent_group_id}'
    else:
        response = f'System(s) {names} failed to move to GroupId {parent_group_id}'
    return CommandResults(
        raw_response=raw_response,
        readable_output=response
    )


def epo_advanced_command_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        Executes the ePO command in advance mode
        XSOAR  CMD example: !epo-advanced-command command="clienttask.find" commandArgs="searchText:On-Demand"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """

    parsed_args = parse_command_args(args["command"], args["commandArgs"])
    return epo_command_command(client, parsed_args)


def epo_find_client_task_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    find client task
    XSOAR CMD Example: !epo-find-client-task searchText="On-Demand"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    search_text = args.get('searchText')

    response_json, response = client.find_client_task(search_text=search_text)
    headers: List[Any] = list(set().union(*(entry.keys() for entry in response_json)))

    md = tableToMarkdown("ePO Client Tasks:", response_json, headers=headers)
    return CommandResults(
        raw_response=response,
        readable_output=md,
        outputs=response_json,
        outputs_prefix='McAfee.ePO.ClientTask',
        outputs_key_field='objectName'
    )


def epo_find_policy_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    find policy in ePO
    XSOAR CMD Example: !epo-find-policy searchText="On-Access"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    search_text = args.get('searchText')

    response_json, response = client.find_policy(search_text=search_text)
    headers: List[Any] = list(set().union(*(entry.keys() for entry in response_json)))

    md = tableToMarkdown("ePO Policies:", response_json, headers=headers, removeNull=True)
    return CommandResults(
        outputs=response_json,
        outputs_prefix='McAfee.ePO.Policy',
        raw_response=response,
        readable_output=md
    )


def epo_assign_policy_to_group(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        Assigns policy to the specified group or resets group's inheritance for the specified policy
        XSOAR CMD Example: !epo-assign-policy-to-group groupId="2" productId="ENDP_AM_1000" objectId="130"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """

    group_id = arg_to_number(args.get('groupId', str))
    if group_id is None:
        raise ValueError('Must provide groupId')
    product_id = args.get('productId', str)
    object_id = arg_to_number(args.get('objectId', str))
    if object_id is None:
        raise ValueError('Must provide objectId')
    reset_inheritance = args.get('resetInheritance', 'false')

    json_response, raw_response = client.assign_policy_to_group(group_id, product_id, object_id,
                                                                reset_inheritance=reset_inheritance)

    if json_response:
        response = f'Policy productId:{product_id} objectId:{object_id} assigned successfully to GroupId {group_id}'
    else:
        response = f'failed to assigned policy productId:{product_id} objectId:{object_id} to GroupId {group_id}'

    return CommandResults(
        raw_response=raw_response,
        readable_output=response
    )


def epo_assign_policy_to_system(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        Assigns policy to a supplied list of systems or resets systems' inheritance for the specified policy
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """

    names = args.get('names', str)
    product_id = args.get('productId', str)
    type_id = arg_to_number(args.get('typeId', str))
    if type_id is None:
        raise ValueError('Must provide typeId')
    object_id = arg_to_number(args.get('objectId', str))
    if object_id is None:
        raise ValueError('Must provide objectId')
    reset_inheritance = args.get('resetInheritance', 'false')

    response_json, raw_response = client.assign_policy_to_system(names, product_id, type_id, object_id,
                                                                 reset_inheritance=reset_inheritance)
    headers: List[Any] = list(set().union(*(entry.keys() for entry in response_json)))

    md = tableToMarkdown("ePO Policies:", response_json, headers=headers)

    return CommandResults(
        raw_response=raw_response,
        readable_output=md
    )


def epo_list_issues_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        list issue in the system
        XSOAR CMD Example: !epo-list-issues
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    issue_id = args.get('id', '')
    response_json, raw_response = client.list_issue(issue_id)
    if response_json != '<null>':
        if isinstance(response_json, list):
            headers = list(set().union(*(entry.keys() for entry in response_json)))
        else:
            headers = response_json.keys()
        md = tableToMarkdown("ePO Issue List:", response_json, headers=headers)
        return CommandResults(
            raw_response=raw_response,
            outputs=response_json,
            outputs_prefix='McAfee.ePO.Issue',
            readable_output=md,
            outputs_key_field='id'
        )
    else:
        if issue_id:
            md = f'issue with id:{issue_id} is not exists\n'
        else:
            md = 'The operation has failed\n'
        return CommandResults(
            raw_response=raw_response,
            readable_output=md
        )


def epo_delete_issue_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        delete issue from the system
        XSOAR CMD Example: !epo-delete-issue id=8
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    """
        delete issue in the system
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    issue_id = args.get('id', str)
    json_response, raw_response = client.delete_issue(issue_id)

    md = f'Issue with id={json_response} was deleted'

    return CommandResults(
        raw_response=raw_response,
        readable_output=md
    )


def epo_update_issue_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        update issue in the system
        XSOAR CMD Example: !epo-update-issue id="9" name="test issue" desc="update from epo integration"
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    issue_id = args.get('id', str)
    if issue_id is None:
        raise ValueError('Must provide id')
    issue_name = args.get('name')
    issue_description = args.get('description')
    issue_state = args.get('state')
    issue_priority = args.get('priority')
    issue_severity = args.get('severity')
    issue_resolution = args.get('resolution')
    issue_due = args.get('due')
    issue_assignee_name = args.get('assignee_name')
    issue_ticket_server_name = args.get('ticketServerName')
    issue_ticket_id = args.get('ticketId')
    issue_properties = args.get('properties')
    json_response, raw_response = client.update_issue(issue_id, issue_name=issue_name,
                                                      issue_description=issue_description,
                                                      issue_state=issue_state, issue_priority=issue_priority,
                                                      issue_severity=issue_severity, issue_resolution=issue_resolution,
                                                      issue_due=issue_due, issue_assignee_name=issue_assignee_name,
                                                      issue_ticket_server_name=issue_ticket_server_name,
                                                      issue_ticket_id=issue_ticket_id,
                                                      issue_properties=issue_properties)
    md = f'Issue with id={json_response} was updated'

    return CommandResults(
        raw_response=raw_response,
        readable_output=md
    )


def epo_create_issue_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
        Create an issue
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    """
        create issue in the system
    Args:
        client (Client: BaseClient): a utility class used for communicating with ePO Server
        args (dict): a dictionary that store the command argument.
    Returns:
        CommandResults
    """
    issue_name = args.get('name', str)
    if issue_name is None:
        raise ValueError("Must provide name")
    issue_description = args.get('description')
    if issue_description is None:
        raise ValueError("Must provide description")
    issue_state = args.get('state')
    issue_priority = args.get('priority')
    issue_severity = args.get('severity')
    issue_resolution = args.get('resolution')
    issue_due = args.get('due')
    issue_assignee_name = args.get('assignee_name')
    issue_ticket_server_name = args.get('ticketServerName')
    issue_ticket_id = args.get('ticketId')
    issue_properties = args.get('properties')
    response_json, raw_response = client.create_issue(issue_name, issue_description,
                                                      issue_state=issue_state, issue_priority=issue_priority,
                                                      issue_severity=issue_severity, issue_resolution=issue_resolution,
                                                      issue_due=issue_due, issue_assignee_name=issue_assignee_name,
                                                      issue_ticket_server_name=issue_ticket_server_name,
                                                      issue_ticket_id=issue_ticket_id,
                                                      issue_properties=issue_properties)
    md = f'Issue with the following ID: {response_json} was created successfully'
    outputs = [{'id': response_json,
                'name': issue_name,
                'description': issue_description}]

    return CommandResults(
        raw_response=raw_response,
        readable_output=md,
        outputs=outputs,
        outputs_prefix="McAfee.ePO.Issue",
        outputs_key_field='id'
    )


'''MAIN'''


def main() -> None:
    """
    integration main function where command get executed
    Returns: None
    """

    # get the epo service url
    base_url = urljoin(demisto.params()['address'], 'remote/')  # rename to url
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    demisto.debug(f'****EPO****:Command being called is {demisto.command()}')

    try:
        timeout = int(demisto.params().get('timeout', 120))
    except ValueError as e:
        demisto.debug(f'Failed casting timeout parameter to int, falling back to 120 - {e}')
        timeout = 120

    try:
        headers = {
            'accept': 'application/json'  # To do make sure all quotes are single qoute
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            auth=(demisto.params().get('authentication', {}).get('identifier', ''),
                  demisto.params().get('authentication', {}).get('password', '')),
            timeout=timeout
        )

        args = demisto.args()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            client.test_module()
            return_results('ok')
        elif demisto.command() == 'epo-help':
            return_results(epo_help_command(client, args))
        elif demisto.command() == 'epo-get-latest-dat':
            return_results(epo_get_latest_dat_command(client))
        elif demisto.command() == 'epo-get-current-dat':
            return_results(epo_get_current_dat_command(client))
        elif demisto.command() == 'epo-command':
            return_results(epo_command_command(client, args))
        elif demisto.command() == 'epo-update-client-dat':
            return_results(epo_update_client_dat_command(client, args))
        elif demisto.command() == 'epo-update-repository':
            return_results(epo_update_repository_command(client))
        elif demisto.command() == 'epo-get-system-tree-group':
            return_results(epo_get_system_tree_groups_command(client, args))
        elif demisto.command() == 'epo-find-systems':
            return_results(epo_find_systems_command(client, args))
        elif demisto.command() == 'epo-find-system':
            return_results(epo_find_system_command(client, args))
        elif demisto.command() == 'epo-wakeup-agent':
            return_results(epo_wakeup_agent_command(client, args))
        elif demisto.command() == 'epo-apply-tag':
            return_results(epo_apply_tag_command(client, args))
        elif demisto.command() == 'epo-clear-tag':
            return_results(epo_clear_tag_command(client, args))
        elif demisto.command() == 'epo-list-tag':
            return_results(epo_list_tag_command(client, args))
        elif demisto.command() == 'epo-get-tables':
            return_results(epo_get_tables_command(client, args))
        elif demisto.command() == 'epo-query-table':
            return_results(epo_query_table_command(client, args))
        elif demisto.command() == 'epo-get-version':
            return_results(epo_get_version_command(client))
        elif demisto.command() == 'epo-move-system':
            return_results(epo_move_system_command(client, args))
        elif demisto.command() == 'epo-advanced-command':
            return_results(epo_advanced_command_command(client, args))
        elif demisto.command() == 'epo-find-client-task':
            return_results(epo_find_client_task_command(client, args))
        elif demisto.command() == 'epo-find-policy':
            return_results(epo_find_policy_command(client, args))
        elif demisto.command() == 'epo-assign-policy-to-group':
            return_results(epo_assign_policy_to_group(client, args))
        elif demisto.command() == 'epo-assign-policy-to-system':
            return_results(epo_assign_policy_to_system(client, args))
        elif demisto.command() == 'epo-list-issues':
            return_results(epo_list_issues_command(client, args))
        elif demisto.command() == 'epo-delete-issue':
            return_results(epo_delete_issue_command(client, args))
        elif demisto.command() == 'epo-create-issue':
            return_results(epo_create_issue_command(client, args))
        elif demisto.command() == 'epo-update-issue':
            return_results(epo_update_issue_command(client, args))
        else:
            raise NotImplementedError(f'Command "{demisto.command()}" is not implemented.')
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
