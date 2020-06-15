from datetime import datetime
from typing import Dict, Tuple, Optional, List, Callable, Any

import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


def reformat_resource_groups_outputs(text: str) -> str:
    """rg_*text -> ResourceGroupText
    Args:
        text: the text to transform
    Returns:
        A Camel Cased string.
    """
    suffix = text[3:]
    if suffix == 'id':
        suffix = 'ID'
    elif suffix == 'resourcetypeid':
        suffix = 'TypeID'
    else:
        suffix = suffix.title()
    return f'ResourceGroup{suffix}'


def reformat_outputs(text: str) -> str:
    """camelCase -> Camel Case, id -> ID
    Args:
        text: the text to transform
    Returns:
        A Demisto output standard string
    """
    if text.startswith('rg_'):
        return reformat_resource_groups_outputs(text)
    if text == 'id':
        return 'ID'
    if text in ['lanid', 'u_lanid']:
        return 'LanID'
    if text == 'jobId':
        return 'JobID'
    if text == 'eventId':
        return 'EventID'
    if text == 'entityId':
        return 'EntityID'
    if text in ['tenantId', 'tenantid']:
        return 'TenantID'
    if text == 'incidentId':
        return 'IncidentID'
    if text == 'Datasourceid':
        return 'DataSourceID'
    if text in ['employeeId', 'employeeid', 'u_employeeid']:
        return 'EmployeeID'
    if text == 'violatorId':
        return 'ViolatorID'

    if text.startswith('U_') or text.startswith('u_'):
        text = text[2:]
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_data_arr(data_arr: Any, fields_to_drop: list = [], fields_to_include: list = []):
    """Parse data as received from Securonix into Demisto's conventions
    Args:
        data_arr: a dictionary containing the data
        fields_to_drop: Fields to drop from the array of the data
        fields_to_include: Fields to include from the array of the data
    Returns:
        A Camel Cased dictionary with the relevant fields.
        readable: for the human readable
        outputs: for the entry context
    """
    if isinstance(data_arr, list):
        readable_arr, outputs_arr = [], []
        for data in data_arr:
            readable = {reformat_outputs(i): j for i, j in data.items() if i not in fields_to_drop}
            if fields_to_include:
                readable = {i: j for i, j in readable.items() if i in fields_to_include}
            readable_arr.append(readable)
            outputs_arr.append({k.replace(' ', ''): v for k, v in readable.copy().items()})
        return readable_arr, outputs_arr

    readable = {reformat_outputs(i): j for i, j in data_arr.items() if i not in fields_to_drop}
    if fields_to_include:
        readable = {i: j for i, j in readable.items() if i in fields_to_include}
    outputs = {k.replace(' ', ''): v for k, v in readable.copy().items()}

    return readable, outputs


def incident_priority_to_dbot_score(priority_str: str):
    """Converts an priority string to DBot score representation
        alert severity. Can be one of:
        Low    ->  1
        Medium ->  2
        High   ->  3

    Args:
        priority_str: String representation of proirity.

    Returns:
        Dbot representation of severity
    """
    priority = priority_str.lower()
    if priority == 'low':
        return 1
    if priority == 'medium':
        return 2
    if priority == 'high':
        return 3
    demisto.info(f'Securonix incident priority: {priority} is not known. Setting as unknown(DBotScore of 0).')
    return 0


class Client(BaseClient):
    """
    Client to use in the Securonix integration. Overrides BaseClient
    """

    def __init__(self, tenant: str, server_url: str, username: str, password: str, verify: bool,
                 proxy: bool):
        super().__init__(base_url=server_url, verify=verify)
        self._username = username
        self._password = password
        self._tenant = tenant
        self._proxies = handle_proxy() if proxy else None
        self._token = self._generate_token()

    def http_request(self, method, url_suffix, headers=None, params=None, response_type: str = 'json'):
        """
        Generic request to Securonix
        """
        full_url = urljoin(self._base_url, url_suffix)
        try:
            result = requests.request(
                method,
                full_url,
                params=params,
                headers=headers,
                verify=self._verify,
                proxies=self._proxies
            )
            if not result.ok:
                raise ValueError(f'Error in API call to Securonix {result.status_code}. Reason: {result.text}')
            try:
                if response_type != 'json':
                    return result.text
                return result.json()
            except Exception:
                raise ValueError(
                    f'Failed to parse http response to JSON format. Original response body: \n{result.text}')

        except requests.exceptions.ConnectTimeout as exception:
            err_msg = 'Connection Timeout Error - potential reasons might be that the Server URL parameter' \
                      ' is incorrect or that the Server is not accessible from your host.'
            raise Exception(f'{err_msg}\n{exception}')

        except requests.exceptions.SSLError as exception:
            err_msg = 'SSL Certificate Verification Failed - try selecting \'Trust any certificate\' checkbox in' \
                      ' the integration configuration.'
            raise Exception(f'{err_msg}\n{exception}')

        except requests.exceptions.ProxyError as exception:
            err_msg = 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is' \
                      ' selected, try clearing the checkbox.'
            raise Exception(f'{err_msg}\n{exception}')

        except requests.exceptions.ConnectionError as exception:
            error_class = str(exception.__class__)
            err_type = '<' + error_class[error_class.find('\'') + 1: error_class.rfind('\'')] + '>'
            err_msg = f'Error Type: {err_type}\n' \
                      f'Error Number: [{exception.errno}]\n' \
                      f'Message: {exception.strerror}\n' \
                      f'Verify that the tenant parameter is correct' \
                      f'and that you have access to the server from your host.'
            raise Exception(f'{err_msg}\n{exception}')

        except Exception as exception:
            raise Exception(str(exception))

    def _generate_token(self) -> str:
        """Generate a token

        Returns:
            token valid for 1 day
        """
        headers = {
            'username': self._username,
            'password': self._password,
            'validity': "1",
            'tenant': self._tenant,
        }
        token = self.http_request('GET', '/token/generate', headers=headers, response_type='text')
        return token

    def test_module_request(self):
        """
        Testing the instance configuration by sending a GET request
        """
        self.list_workflows_request()

    def list_workflows_request(self) -> Dict:
        """List workflows.

        Returns:
            Response from API.
        """
        workflows = self.http_request('GET', '/incident/get', headers={'token': self._token},
                                      params={'type': 'workflows'})
        return workflows.get('result').get('workflows')

    def get_default_assignee_for_workflow_request(self, workflow: str) -> Dict:
        """Get default assignee for a workflow..

        Args:
            workflow: workflow name

        Returns:
            Response from API.
        """
        params = {
            'type': 'defaultAssignee',
            'workflow': workflow
        }
        default_assignee = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        return default_assignee.get('result')

    def list_possible_threat_actions_request(self) -> Dict:
        """List possible threat actions.

        Returns:
            Response from API.
        """

        threat_actions = self.http_request('GET', '/incident/get', headers={'token': self._token},
                                           params={'type': 'threatActions'})
        return threat_actions.get('result')

    def list_policies_request(self) -> Dict:
        """List policies.

        Returns:
            Response from API.
        """

        policies = self.http_request('GET', '/policy/getAllPolicies', headers={'token': self._token},
                                     response_type='xml')
        return policies

    def list_resource_groups_request(self) -> Dict:
        """List resource groups.

        Returns:
            Response from API.
        """

        resource_groups = self.http_request('GET', '/list/resourceGroups', headers={'token': self._token},
                                            response_type='xml')
        return resource_groups

    def list_users_request(self) -> Dict:
        """List users.

        Returns:
            Response from API.
        """

        users = self.http_request('GET', '/list/allUsers', headers={'token': self._token},
                                  response_type='xml')
        return users

    def list_activity_data_request(self, from_: str, to_: str, query: str = None) -> Dict:
        """List activity data.

        Args:
            from_: eventtime start range in format MM/dd/yyyy HH:mm:ss.
            to_: eventtime end range in format MM/dd/yyyy HH:mm:ss.
            query: open query.

        Returns:
            Response from API.
        """
        params = {
            'query': 'index=activity',
            'eventtime_from': from_,
            'eventtime_to': to_,
            'prettyJson': True
        }
        if query:
            params['query'] = f'{params["query"]} AND {query}'
        activity_data = self.http_request('GET', '/spotter/index/search', headers={'token': self._token},
                                          params=params)
        return activity_data

    def list_violation_data_request(self, from_: str, to_: str, query: str = None) -> Dict:
        """List violation data.

        Args:
            from_: eventtime start range in format MM/dd/yyyy HH:mm:ss.
            to_: eventtime end range in format MM/dd/yyyy HH:mm:ss.
            query: open query.

        Returns:
            Response from API.
        """
        params = {
            'query': 'index=violation',
            'generationtime_from': from_,
            'generationtime_to': to_,
            'prettyJson': True
        }
        if query:
            params['query'] = f'{params["query"]} AND {query}'
        violation_data = self.http_request('GET', '/spotter/index/search', headers={'token': self._token},
                                           params=params)
        return violation_data

    def list_incidents_request(self, from_epoch: str, to_epoch: str, incident_status: str, max_incidents: str = '50')\
            -> Dict:
        """List all incidents by sending a GET request.

        Args:
            from_epoch: from time in epoch
            to_epoch: to time in epoch
            incident_status: incident status e.g:closed, opened
            max_incidents: max incidents to get

        Returns:
            Response from API.
        """
        params = {
            'type': 'list',
            'from': from_epoch,
            'to': to_epoch,
            'rangeType': incident_status,
            'max': max_incidents,
            'order': 'asc',
        }
        incidents = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        return incidents.get('result').get('data')

    def get_incident_request(self, incident_id: str) -> Dict:
        """get incident meta data by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            'type': 'metaInfo',
            'incidentId': incident_id,
        }
        incident = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        return incident.get('result').get('data')

    def get_incident_status_request(self, incident_id: str) -> Dict:
        """get incident meta data by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            'type': 'status',
            'incidentId': incident_id,
        }
        incident = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        return incident.get('result')

    def get_incident_workflow_request(self, incident_id: str) -> Dict:
        """get incident workflow by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            'type': 'workflow',
            'incidentId': incident_id,
        }
        incident = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        return incident.get('result')

    def get_incident_available_actions_request(self, incident_id: str) -> Dict:
        """get incident available actions by sending a GET request.

        Args:
            incident_id: incident ID.

        Returns:
            Response from API.
        """
        params = {
            'type': 'actions',
            'incidentId': incident_id,
        }
        incident = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        return incident.get('result')

    def perform_action_on_incident_request(self, incident_id, action: str, action_parameters: str) -> Dict:
        """get incident available actions by sending a GET request.

        Args:
            incident_id: incident ID.
            action: action to perform on the incident.
            action_parameters: parameters needed in order to perform the action.

        Returns:
            Response from API.
        """

        params = {
            'type': 'actionInfo',
            'incidentId': incident_id,
            'actionName': action
        }
        if action_parameters:
            action_parameters_dict = {
                k: v.strip('"') for k, v in [i.split("=", 1) for i in action_parameters.split(',')]
            }
            params.update(action_parameters_dict)

        possible_action = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)

        if 'error' in possible_action:
            err_msg = possible_action.get('error')
            raise Exception(f'Failed to perform the action {action} on incident {incident_id}.\n'
                            f'Error from Securonix is: {err_msg}')

        incident = self.http_request('POST', '/incident/actions', headers={'token': self._token}, params=params)
        return incident.get('result')

    def add_comment_to_incident_request(self, incident_id: str, comment: str) -> Dict:
        """add comment to an incident by sending a POST request.

        Args:
            incident_id: incident ID.
            comment: action to perform on the incident

        Returns:
            Response from API.
        """
        params = {
            'incidentId': incident_id,
            'comment': comment,
            'actionName': 'comment'
        }
        incident = self.http_request('POST', '/incident/actions', headers={'token': self._token}, params=params)
        return incident.get('result')

    def create_incident_request(self, violation_name: str, resource_group: str, resource_name: str,
                                entity_type: str, entity_name: str, action_name: str, workflow: str = None,
                                comment: str = None, criticality: str = None) -> Dict:
        """create an incident by sending a POST request.

        Args:
            violation_name: violation or policy name.
            resource_group: resource group name.
            resource_name: resource name.
            entity_type: entity type.
            entity_name: entity name.
            action_name: action name.
            workflow: workflow name.
            comment: comment on the incident.
            criticality: criticality for the incident.

        Returns:
            Response from API.
        """
        params = {
            'violationName': violation_name,
            'datasourceName': resource_group,
            'resourceName': resource_name,
            'entityType': entity_type,
            'entityName': entity_name,
            'actionName': action_name,
        }
        if workflow:
            params['workflow'] = workflow
        if comment:
            params['comment'] = comment
        if criticality:
            params['criticality'] = criticality

        response = self.http_request('POST', '/incident/actions', headers={'token': self._token}, params=params)
        return response

    def list_watchlist_request(self):
        """list watchlists by sending a GET request.

        Returns:
            Response from API.
        """
        watchlists = self.http_request('GET', '/incident/listWatchlist', headers={'token': self._token})
        return watchlists.get('result')

    def get_watchlist_request(self, watchlist_name: str) -> Dict:
        """Get a watchlist by sending a GET request.

        Args:
            watchlist_name: watchlist name.

        Returns:
            Response from API.
        """
        params = {
            'query': f'index=watchlist AND watchlistname=\"{watchlist_name}\"',
        }
        watchlist = self.http_request('GET', '/spotter/index/search', headers={'token': self._token}, params=params)
        return watchlist

    def create_watchlist_request(self, watchlist_name: str) -> Dict:
        """Create a watchlist by sending a POST request.

        Args:
            watchlist_name: watchlist name.

        Returns:
            Response from API.
        """
        params = {
            'watchlistname': watchlist_name
        }
        watchlist = self.http_request('POST', '/incident/createWatchlist',
                                      headers={'token': self._token}, params=params, response_type='text')
        return watchlist

    def check_entity_in_watchlist_request(self, entity_name: str, watchlist_name: str) -> Dict:
        """Check if an entity is whitelisted by sending a GET request.

        Args:
            entity_name: Entity name.
            watchlist_name: Watchlist name.

        Returns:
            Response from API.
        """
        params = {
            'entityId': entity_name,
            'watchlistname': watchlist_name
        }
        response = self.http_request('GET', '/incident/checkIfWatchlisted',
                                     headers={'token': self._token}, params=params)
        return response

    def add_entity_to_watchlist_request(self, watchlist_name: str, entity_type: str, entity_name: str,
                                        expiry_days: str) -> Dict:
        """Check if an entity is whitelisted by sending a GET request.

        Args:
            watchlist_name: Watchlist name.
            entity_type: Entity type.
            entity_name: Entity name.
            expiry_days: Expiry in days.
        Returns:
            Response from API.
        """
        params = {
            'watchlistname': watchlist_name,
            'entityType': entity_type,
            'entityId': entity_name,
            'expirydays': expiry_days,
            'resourcegroupid': '-1'
        }
        watchlist = self.http_request('POST', '/incident/addToWatchlist',
                                      headers={'token': self._token}, params=params, response_type='txt')
        return watchlist


def test_module(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """
    Performs basic get request to get incident samples
    """
    client.test_module_request()
    demisto.results('ok')
    return '', {}, {}


def list_workflows(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all workflows.

    Args:
        client: Client object with request.
        *_:

    Returns:
        Outputs.
    """
    workflows = client.list_workflows_request()
    workflows_readable, workflows_outputs = parse_data_arr(workflows)
    human_readable = tableToMarkdown(name="Available workflows:", t=workflows_readable,
                                     headers=['Workflow', 'Type', 'Value'],
                                     removeNull=True)
    entry_context = {'Securonix.Workflows(val.Workflow == obj.Workflow)': workflows_outputs}
    return human_readable, entry_context, workflows


def get_default_assignee_for_workflow(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Perform action on an incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    workflow = str(args.get('workflow'))
    default_assignee = client.get_default_assignee_for_workflow_request(workflow)
    workflow_output = {
        'Workflow': workflow,
        'Type': default_assignee.get("type"),
        'Value': default_assignee.get("value"),
    }
    entry_context = {'Securonix.Workflows(val.Workflow === obj.Workflow)': workflow_output}
    human_readable = f'Default assignee for the workflow {workflow} is: {default_assignee.get("value")}.'
    return human_readable, entry_context, default_assignee


def list_possible_threat_actions(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all workflows.

    Args:
        client: Client object with request.
        *_:

    Returns:
        Outputs.
    """
    threat_actions = client.list_possible_threat_actions_request()
    human_readable = f'Possible threat actions are: {", ".join(threat_actions)}.'
    entry_context = {'Securonix.ThreatActions': threat_actions}
    return human_readable, entry_context, threat_actions


def list_policies(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all policies.

    Args:
        client: Client object with request.
        *_:

    Returns:
        Outputs.
    """
    policies_xml = client.list_policies_request()
    policies_json = xml2json(policies_xml)
    policies = json.loads(policies_json)
    policies_arr = policies.get('policies').get('policy')
    policies_readable, policies_outputs = parse_data_arr(policies_arr)
    headers = ['ID', 'Name', 'Criticality', 'Created On', 'Created By', 'Description']
    human_readable = tableToMarkdown(name="Policies:", t=policies_readable, headers=headers, removeNull=True)
    entry_context = {'Securonix.Policies(val.ID === obj.ID)': policies_outputs}

    return human_readable, entry_context, policies


def list_resource_groups(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all resource groups.

    Args:
        client: Client object with request.
        *_:

    Returns:
        Outputs.
    """
    resource_groups_xml = client.list_resource_groups_request()

    resource_groups_json = xml2json(resource_groups_xml)
    resource_groups = json.loads(resource_groups_json)
    resource_groups_arr = resource_groups.get('resourceGroups').get('resourceGroup')

    resource_groups_readable, resource_groups_outputs = parse_data_arr(resource_groups_arr)
    headers = ['Name', 'Type']
    human_readable = tableToMarkdown(name="Resource groups:", t=resource_groups_readable, headers=headers,
                                     removeNull=True)
    entry_context = {'Securonix.ResourceGroups(val.Name === obj.Name)': resource_groups_outputs}

    return human_readable, entry_context, resource_groups


def list_users(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all users.

    Args:
        client: Client object with request.
        *_:

    Returns:
        Outputs.
    """
    users_xml = client.list_users_request()

    users_json = xml2json(users_xml)
    users = json.loads(users_json)
    users_arr = users.get('users').get('user')

    users_readable, users_outputs = parse_data_arr(users_arr)
    headers = ['Employee Id', 'First Name', 'Last Name', 'Criticality', 'Title', 'Email']
    human_readable = tableToMarkdown(name="Resource groups:", t=users_readable, headers=headers, removeNull=True)
    entry_context = {'Securonix.Users(val.EmployeeID === obj.EmployeeID)': users_outputs}

    return human_readable, entry_context, users


def list_activity_data(client: Client, args) -> Tuple[str, Dict, Dict]:
    """List activity data.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    from_ = args.get('from')
    to_ = args.get('to')
    query = args.get('query')
    activity_data = client.list_activity_data_request(from_, to_, query)

    if activity_data.get('error'):
        raise Exception(f'Failed to get activity data in the given time frame.\n'
                        f'Error from Securonix is: {activity_data.get("errorMessage")}')

    activity_events = activity_data.get('events')
    fields_to_include = ['Accountname', 'Agentfilename', 'Categorybehavior', 'Categoryobject', 'Categoryseverity',
                         'Collectionmethod', 'Collectiontimestamp', 'Destinationprocessname', 'Destinationusername',
                         'Deviceaddress', 'Deviceexternalid', 'Devicehostname', 'EventID', 'Eventoutcome', 'Eventtime',
                         'Filepath', 'Ingestionnodeid', 'JobID', 'Jobstarttime', 'Message', 'Publishedtime',
                         'Receivedtime', 'Resourcename', 'Rg_category', 'Rg_functionality', 'Rg_id', 'Rg_name',
                         'Rg_resourcetypeid', 'Rg_vendor', 'Sourcehostname', 'Sourceusername', 'TenantID', 'Tenantname',
                         'Timeline']
    activity_readable, activity_outputs = parse_data_arr(activity_events, fields_to_include=fields_to_include)
    headers = ['Eventid', 'Eventtime', 'Message', 'Accountname']
    human_readable = tableToMarkdown(name="Activity data:", t=activity_readable, headers=headers, removeNull=True)
    entry_context = {'Securonix.ActivityData(val.EventID === obj.EventID)': activity_outputs}

    return human_readable, entry_context, activity_data


def list_violation_data(client: Client, args) -> Tuple[str, Dict, Dict]:
    """List violation data.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    from_ = args.get('from')
    to_ = args.get('to')
    query = args.get('query')
    violation_data = client.list_violation_data_request(from_, to_, query)

    if violation_data.get('error'):
        raise Exception(f'Failed to get violation data in the given time frame.\n'
                        f'Error from Securonix is: {violation_data.get("errorMessage")}')
    violation_events = violation_data.get('events')
    fields_to_include = ['Accountname', 'Baseeventid', 'Category', 'Categorybehavior', 'Categoryobject',
                         'Categoryseverity', 'Destinationaddress', 'Destinationntdomain', 'Destinationuserid',
                         'Gestinationusername', 'Deviceaddress', 'Deviceeventcategory', 'Deviceexternalid',
                         'Devicehostname', 'EventID', 'Eventoutcome', 'Eventtime', 'Generationtime', 'Invalid', 'JobID',
                         'Jobstarttime', 'Message', 'Policyname', 'Resourcename', 'Rg_id', 'Rg_name', 'Riskscore',
                         'Riskthreatname', 'Sessionid', 'Sourcehostname', 'Sourcentdomain', 'Sourceuserid',
                         'Sourceusername', 'Sourceuserprivileges', 'TenantID', 'Tenantname', 'Timeline',
                         'Createdate', 'Criticality', 'Datasourceid', 'Department', 'Division',
                         'EmployeeID', 'Encrypted', 'Firstname', 'Fullname', 'ID', 'LanID', 'Lastname',
                         'Lastsynctime', 'Masked', 'Mergeuniquecode', 'Riskscore', 'Skipencryption',
                         'Status', 'Timezoneoffset', 'Title', 'Uniquecode', 'UserID', 'Workemail',
                         'Violator']
    violation_readable, violation_outputs = parse_data_arr(violation_events, fields_to_include=fields_to_include)
    headers = ['EventID', 'Eventtime', 'Message', 'Policyname', 'Accountname']
    human_readable = tableToMarkdown(name="Activity data:", t=violation_readable, headers=headers, removeNull=True)
    entry_context = {'Securonix.ViolationData(val.Uniquecode === obj.Uniquecode)': violation_outputs}

    return human_readable, entry_context, violation_data


def list_incidents(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """List incidents.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    from_, _ = parse_date_range(args.get('from'), utc=True)
    from_epoch = date_to_timestamp(from_, date_format=timestamp_format)
    to_ = args.get('to') if 'to_' in args else datetime.now()
    to_epoch = date_to_timestamp(to_, date_format=timestamp_format)
    incident_types = str(args.get('incident_types')) if 'incident_types' in args else 'opened'
    max_incidents = str(args.get('max', '50'))
    incidents = client.list_incidents_request(from_epoch, to_epoch, incident_types, max_incidents)

    total_incidents = incidents.get('totalIncidents')
    if not total_incidents or float(total_incidents) <= 0.0:
        return 'No incidents where found in this time frame.', {}, incidents

    incidents_items = incidents.get('incidentItems')
    incidents_readable, incidents_outputs = parse_data_arr(incidents_items)
    headers = ['Incident Id', 'Incident Status', 'Incident Type', 'Priority', 'Reason']
    human_readable = tableToMarkdown(name="Incidents:", t=incidents_readable,
                                     headers=headers, removeNull=True)
    entry_context = {'Securonix.Incidents(val.IncidentID === obj.IncidentID)': incidents_outputs}
    return human_readable, entry_context, incidents


def get_incident(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))
    incident = client.get_incident_request(incident_id)

    incident_items = incident.get('incidentItems')
    if not incident_items:
        raise Exception('Incident ID is not in Securonix.')
    incident_readable, incident_outputs = parse_data_arr(incident_items)
    human_readable = tableToMarkdown(name="Incident:", t=incident_readable, removeNull=True)
    entry_context = {'Securonix.Incidents(val.IncidentID === obj.IncidentID)': incident_outputs}
    return human_readable, entry_context, incident


def get_incident_status(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))
    incident = client.get_incident_status_request(incident_id)
    incident_status = incident.get('status')
    incident_outputs = {
        'IncidentID': incident_id,
        'IncidentStatus': incident_status
    }
    entry_context = {'Securonix.Incidents(val.IncidentID === obj.IncidentID)': incident_outputs}
    return f'Incident {incident_id} status is {incident_status}.', entry_context, incident


def get_incident_workflow(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get incident workflow.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))

    incident = client.get_incident_workflow_request(incident_id)
    incident_workflow = incident.get('workflow')
    incident_outputs = {
        'IncidentID': incident_id,
        'WorkflowName': incident_workflow
    }
    entry_context = {'Securonix.Incidents(val.IncidentId === obj.IncidentId)': incident_outputs}
    return f'Incident {incident_id} workflow is {incident_workflow}.', entry_context, incident


def get_incident_available_actions(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get incident available actions.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))

    incident_actions = client.get_incident_available_actions_request(incident_id)
    if not incident_actions:
        return f'Incident {incident_id} does not have any available actions.', {}, incident_actions
    actions = []
    for action_details in incident_actions:
        actions.append(action_details.get('actionName'))

    incident_outputs = {
        'IncidentID': incident_id,
        'AvailableActions': actions
    }
    entry_context = {'Securonix.Incidents(val.IncidentID === obj.IncidentID)': incident_outputs}
    return f'Incident {incident_id} available actions: {actions}.', entry_context, incident_actions


def perform_action_on_incident(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Perform action on an incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))
    action = str(args.get('action'))
    action_parameters = str(args.get('action_parameters', ''))
    incident_result = client.perform_action_on_incident_request(incident_id, action, action_parameters)
    if incident_result != 'submitted':
        raise Exception(f'Failed to perform the action {action} on incident {incident_id}.')
    return f'Action {action} was performed on incident {incident_id}.', {}, incident_result


def add_comment_to_incident(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Add comment to an incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))
    comment = str(args.get('comment'))
    incident = client.add_comment_to_incident_request(incident_id, comment)
    if not incident:
        raise Exception(f'Failed to add comment to the incident {incident_id}.')
    return f'Comment was added to the incident {incident_id} successfully.', {}, incident


def create_incident(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create an incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    violation_name = str(args.get('violation_name'))
    resource_group = str(args.get('resource_group'))
    resource_name = str(args.get('resource_name'))
    entity_type = str(args.get('entity_type'))
    entity_name = str(args.get('entity_name'))
    action_name = str(args.get('action_name'))
    workflow = str(args.get('workflow')) if 'workflow' in args else None
    comment = str(args.get('comment')) if 'comment' in args else None
    criticality = str(args.get('criticality')) if 'criticality' in args else None

    if 'create incident' in action_name and not workflow:
        raise Exception(f'Creating an incident with the action: {action_name}, Supply a workflow.')
    response = client.create_incident_request(violation_name, resource_group, resource_name, entity_type, entity_name,
                                              action_name, workflow, comment, criticality)
    result = response.get('result')
    if not result:
        raise Exception(f'Failed to create the incident.\nResponse from Securonix is: {str(response)}')

    message = response.get('messages')
    if message:
        if isinstance(message, list) and 'Invalid' in message[0]:
            message = message[0]
            raise Exception(f'Failed to create the incident with message:\n{message}')
        if 'Invalid' in message:
            raise Exception(f'Failed to create the incident with message:\n{message}')

    incident_data = result.get('data')
    incident_items = incident_data.get('incidentItems')
    incident_readable, incident_outputs = parse_data_arr(incident_items)
    headers = ['Entity', 'Incident Status', 'Incident Type', 'IncidentID', 'Priority', 'Reason', 'Url']
    human_readable = tableToMarkdown(name="Incident was created successfully", t=incident_readable,
                                     headers=headers, removeNull=True)
    entry_context = {'Securonix.Incidents(val.IncidentID === obj.IncidentID)': incident_outputs}
    return human_readable, entry_context, response


def list_watchlists(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all watchlists.

    Args:
        client: Client object with request.

    Returns:
        Outputs.
    """
    watchlists = client.list_watchlist_request()
    if not watchlists:
        raise Exception('Failed to list watchlists.')

    human_readable = f'Watchlists: {", ".join(watchlists)}.'
    entry_context = {'Securonix.WatchlistsNames': watchlists}
    return human_readable, entry_context, watchlists


def get_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """Get watchlist data.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Outputs.
    """
    watchlist_name = args.get('watchlist_name')
    watchlist = client.get_watchlist_request(watchlist_name)

    watchlist_events = watchlist.get('events')
    if not watchlist_events:
        raise Exception('Watchlist does not contain items.\n'
                        'Make sure the watchlist is not empty and that the watchlist name is correct.')
    fields_to_drop = ['decayflag', 'tenantid', 'tenantname', 'watchlistname', 'type']
    watchlist_readable, watchlist_events_outputs = parse_data_arr(watchlist_events, fields_to_drop=fields_to_drop)
    watchlist_outputs = {
        'Watchlistname': watchlist_name,
        'Type': watchlist_events[0].get('type'),
        'TenantID': watchlist_events[0].get('tenantid'),
        'TenantName': watchlist_events[0].get('tenantname'),
        'Events': watchlist_events_outputs
    }
    headers = ['Entityname', 'Fullname', 'Workemail', 'Expired']
    human_readable = tableToMarkdown(name=f"Watchlist {watchlist_name} of type {watchlist_outputs.get('Type')}:",
                                     t=watchlist_readable, headers=headers, removeNull=True)
    entry_context = {'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)': watchlist_outputs}
    return human_readable, entry_context, watchlist


def create_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """Create a watchlist.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Outputs.
    """
    watchlist_name = args.get('watchlist_name')

    response = client.create_watchlist_request(watchlist_name)

    if 'successfully' not in response:
        raise Exception(f'Failed to list watchlists.\nResponse from Securonix is:{str(response)}')
    human_readable = f'Watchlist {watchlist_name} was created successfully.'
    entry_context = {'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)': watchlist_name}
    return human_readable, entry_context, response


def check_entity_in_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """Check if entity is in a watchlist.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Outputs.
    """
    entity_name = args.get('entity_name')
    watchlist_name = args.get('watchlist_name')
    watchlist = client.check_entity_in_watchlist_request(entity_name, watchlist_name)

    result = watchlist.get('result')
    if result == 'NO' or (isinstance(result, list) and result[0] == 'NO'):
        human_readable = f'Entity unique identifier {entity_name} provided is not on the watchlist: {watchlist_name}.'
        output = {'Entityname': entity_name}
    else:  # YES
        human_readable = f'The Entity unique identifier {entity_name} provided is on the watchlist: {watchlist_name}.'
        output = {
            'Entityname': entity_name,
            'Watchlistname': watchlist_name
        }
    entry_context = {'Securonix.EntityInWatchlist(val.Entityname === obj.Entityname)': output}
    return human_readable, entry_context, watchlist


def add_entity_to_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """Adds an entity to a watchlist.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Outputs.
    """
    watchlist_name = args.get('watchlist_name')
    entity_type = args.get('entity_type')
    entity_name = args.get('entity_name')
    expiry_days = args.get('expiry_days') if 'expiry_days' in args else '30'

    response = client.add_entity_to_watchlist_request(watchlist_name, entity_type, entity_name, expiry_days)

    if 'successfull' not in response:
        raise Exception(f'Failed to add entity {entity_name} to the watchlist {watchlist_name}.\n'
                        f'Error from Securonix is: {response}.')
    human_readable = f'Added successfully the entity {entity_name} to the watchlist {watchlist_name}.'
    return human_readable, {}, response


def fetch_incidents(client: Client, fetch_time: Optional[str], incident_status: str, max_fetch: str, last_run: Dict)\
        -> list:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        incident_status: Incident statuses to fetch, can be: all, opened, closed, updated
        last_run: Last fetch object.
        max_fetch: maximum amount of incidents to fetch

    Returns:
        incidents, new last_run
    """
    timestamp_format = '%Y-%m-%dT%H:%M:%S.%fZ'
    if not last_run:  # if first time running
        new_last_run = {'time': parse_date_range(fetch_time, date_format=timestamp_format)[0]}
    else:
        new_last_run = last_run

    demisto_incidents: List = list()
    from_epoch = date_to_timestamp(new_last_run.get('time'), date_format=timestamp_format)
    to_epoch = date_to_timestamp(datetime.now(), date_format=timestamp_format)
    # Get incidents from Securonix
    demisto.info(f'Fetching Securonix incidents. From: {from_epoch}. To: {to_epoch}')
    securonix_incidents = client.list_incidents_request(from_epoch, to_epoch, incident_status, max_fetch)

    if securonix_incidents:
        already_fetched = last_run.get('already_fetched', [])
        incidents_items = list(securonix_incidents.get('incidentItems'))  # type: ignore
        for incident in incidents_items:
            incident_id = str(incident.get('incidentId', 0))
            # check if incident was already fetched due to updating over lastUpdateDate
            if incident_id not in already_fetched:
                incident_name = get_incident_name(incident, incident_id)  # Try to get incident reason as incident name
                demisto_incidents.append({
                    'name': incident_name,
                    'occurred': timestamp_to_datestring(incident.get('lastUpdateDate')),
                    'severity': incident_priority_to_dbot_score(incident.get('priority')),
                    'rawJSON': json.dumps(incident)
                })
                already_fetched.append(str(incident_id))  # add already fetched incidents ids to the set

        if incidents_items:
            now = timestamp_to_datestring(incidents_items[-1].get('lastUpdateDate'))
        else:
            now = datetime.now().strftime(timestamp_format)
        new_last_run.update({'time': now, 'already_fetched': already_fetched})

    demisto.setLastRun({'value': json.dumps(new_last_run)})
    return demisto_incidents


def get_incident_name(incident: Dict, incident_id: str) -> str:
    """Get the incident name by concatenating the incident reasons if possible

    Args:
        incident: incident details
        incident_id: the incident id


    Returns:
        incident name.
    """
    incident_reasons = incident.get('reason', [])
    try:
        incident_reason = ''
        for reason in incident_reasons:
            if reason.startswith('Policy: '):
                incident_reason += f"{reason[8:]}, "
        if incident_reason:
            # Remove ", " last chars and concatenate with the incident ID
            incident_name = f"{incident_reason[:-2]}: {incident_id}"
        else:
            incident_name = f"Securonix Incident: {incident_id}."
    except ValueError:
        incident_name = f"Securonix Incident: {incident_id}."

    return incident_name


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    host = params.get("host", None)
    tenant = params.get("tenant")
    if not host:
        server_url = tenant
        if not tenant.startswith('http://') and not tenant.startswith('https://'):
            server_url = f'https://{tenant}'
        if not tenant.endswith('.securonix.net/Snypr/ws/'):
            server_url += '.securonix.net/Snypr/ws/'
    else:
        host = host.rstrip('/')
        if not host.endswith('/ws'):
            host += '/ws/'
        server_url = host

    username = params.get('username')
    password = params.get('password')
    verify = not params.get('unsecure', False)
    proxy = demisto.params().get('proxy') is True

    command = demisto.command()
    LOG(f'Command being called in Securonix is: {command}')

    try:
        client = Client(tenant=tenant, server_url=server_url, username=username, password=password,
                        verify=verify, proxy=proxy)
        commands: Dict[str, Callable[[Client, Dict[str, str]], Tuple[str, Dict[Any, Any], Dict[Any, Any]]]] = {
            'test-module': test_module,
            'securonix-list-workflows': list_workflows,
            'securonix-get-default-assignee-for-workflow': get_default_assignee_for_workflow,
            'securonix-list-possible-threat-actions': list_possible_threat_actions,
            'securonix-list-policies': list_policies,
            'securonix-list-resource-groups': list_resource_groups,
            'securonix-list-users': list_users,
            'securonix-list-activity-data': list_activity_data,
            'securonix-list-violation-data': list_violation_data,
            'securonix-list-incidents': list_incidents,
            'securonix-get-incident': get_incident,
            'securonix-get-incident-status': get_incident_status,
            'securonix-get-incident-workflow': get_incident_workflow,
            'securonix-get-incident-available-actions': get_incident_available_actions,
            'securonix-perform-action-on-incident': perform_action_on_incident,
            'securonix-add-comment-to-incident': add_comment_to_incident,
            'securonix-create-incident': create_incident,
            'securonix-list-watchlists': list_watchlists,
            'securonix-get-watchlist': get_watchlist,
            'securonix-create-watchlist': create_watchlist,
            'securonix-check-entity-in-watchlist': check_entity_in_watchlist,
            'securonix-add-entity-to-watchlist': add_entity_to_watchlist
        }
        if command == 'fetch-incidents':
            fetch_time = params.get('fetch_time', '1 hour')
            incident_status = params.get('incident_status') if 'incident_status' in params else 'opened'
            max_fetch = str(params.get('max_fetch', '50'))
            max_fetch = str(min('50', max_fetch))  # fetch size should no exceed 50
            last_run = json.loads(demisto.getLastRun().get('value', '{}'))
            incidents = fetch_incidents(client, fetch_time, incident_status, max_fetch, last_run=last_run)
            demisto.incidents(incidents)
        elif command in commands:
            return_outputs(*commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
