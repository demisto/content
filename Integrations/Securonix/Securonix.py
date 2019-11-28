from datetime import datetime
from typing import Dict, Tuple, Optional, MutableMapping

import urllib3

from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()


def get_now():
    """ A wrapper function of datetime.now
    helps handle tests

    Returns:
        datetime: time right now
    """
    return datetime.now()


def get_fetch_times(last_fetch):
    """ Get list of every hour since last_fetch. last is now.
    Args:
        last_fetch (datetime or str): last_fetch time

    Returns:
        List[str]: list of str represents every hour since last_fetch
    """
    now = get_now()
    times = list()
    time_format = "%Y-%m-%dT%H:%M:%SZ"
    if isinstance(last_fetch, str):
        times.append(last_fetch)
        last_fetch = datetime.strptime(last_fetch, time_format)
    elif isinstance(last_fetch, datetime):
        times.append(last_fetch.strftime(time_format))
    while now - last_fetch > timedelta(minutes=59):
        last_fetch += timedelta(minutes=59)
        times.append(last_fetch.strftime(time_format))
    times.append(now.strftime(time_format))
    return times


def convert_unix_to_date(timestamp):
    """Convert unix timestamp to datetime in iso format.

    Args:
        timestamp: the date in unix to convert.

    Returns:
        converted date.
    """
    return datetime.fromtimestamp(int(timestamp) / 1000).isoformat()


def convert_date_to_unix(date):
    """Convert datetime in iso format to unix timestamp.

    Args:
        date: the date in ISO to convert.

    Returns:
        unix timestamp.
    """
    return datetime.datetime(date).strftime('%s')  # type: ignore


def camel_case_to_readable(text: str) -> str:
    """'camelCase' -> 'Camel Case'
    Args:
        text: the text to transform
    Returns:
        A Camel Cased string.
    """
    if text == 'id':
        return 'ID'
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_data_arr(data_arr):
    """Parse data as received from Microsoft Graph API into Demisto's conventions
    Args:
        data_arr: a dictionary containing the group data
    Returns:
        A Camel Cased dictionary with the relevant fields.
        readable: for the human readable
        outputs: for the entry context
    """
    if isinstance(data_arr, list):
        readable_arr, outputs_arr = [], []
        for data in data_arr:
            readable = {camel_case_to_readable(i): j for i, j in data.items()}
            readable_arr.append(readable)
            outputs_arr.append({k.replace(' ', ''): v for k, v in readable.copy().items()})
        return readable_arr, outputs_arr

    readable = {camel_case_to_readable(i): j for i, j in data_arr.items()}
    outputs = {k.replace(' ', ''): v for k, v in readable.copy().items()}

    return readable, outputs


class Client(BaseClient):
    """
    Client to use in the Securonix integration. Overrides BaseClient
    """

    def __init__(self, tenant: str, server_url: str, username: str, password: str, verify: bool,
                 proxies: Optional[MutableMapping[str, str]]):
        super().__init__(base_url=server_url, verify=verify, proxy=proxies)
        self._username = username
        self._password = password
        self._tenant = tenant
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

    def list_incidents_request(self, from_epoch: str, to_epoch: str, range_type: str) -> Dict:
        """List all incidents by sending a GET request.

        Args:
            from_epoch: from time in epoch
            to_epoch: to time in epoch
            range_type: incident types

        Returns:
            Response from API.
        """
        params = {
            'type': 'list',
            'from': from_epoch,
            'to': to_epoch,
            'rangeType': range_type
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

    def perform_action_on_incident_request(self, incident_id, action: str) -> Dict:
        """get incident available actions by sending a GET request.

        Args:
            incident_id: incident ID.
            action: action to perform on the incident

        Returns:
            Response from API.
        """
        params = {
            'type': 'actionInfo',
            'incidentId': incident_id,
            'actionName': action
        }
        possible_action = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)

        if 'error' in possible_action:
            err_msg = possible_action.get('error')
            raise Exception(f'Failed to perform the action {action} on incident {incident_id}.\n'
                            f'Error from Securonix is: {err_msg}')

        incident = self.http_request('POST', '/incident/actions', headers={'token': self._token}, params=params)
        return incident.get('result')

    def create_incident_request(self, policy_name: str, resource_group: str, entity_type: str, entity_name: str,
                                action_name, resource_name: str = None, workflow: str = None, comment: str = None,
                                employee_id: str = None, criticality: str = None) -> Dict:
        """create an incident by sending a POST request.

        Args:
            policy_name: policy name.
            resource_group: resource group name.
            entity_type: entity type.
            entity_name: entity id.
            action_name: action name.
            resource_name: resource name.
            workflow: workflow name.
            comment: comment on the incident.
            employee_id: employee id.
            criticality: criticality for the incident.

        Returns:
            Response from API.
        """
        params = {
            'violationName': policy_name,
            'datasourceName': resource_group,
            'entityType': entity_type,
            'entityName': entity_name,
            'actionName': action_name,
        }
        if comment:
            params['comment'] = comment
        if resource_name:
            params['resource name'] = resource_name
        if employee_id:
            params['employeeid'] = employee_id
        if workflow:
            params['workflow'] = workflow
        if criticality:
            params['criticality'] = criticality

        incident = self.http_request('POST', '/incident/actions', headers={'token': self._token}, params=params)
        return incident

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
        demisto.log(str(incident))
        return incident.get('result')

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
                                      headers={'token': self._token}, params=params)
        return watchlist

    def check_entity_in_watchlist_request(self, entity_id: str) -> Dict:
        """Check if an entity is whitelisted by sending a GET request.

        Args:
            entity_id: Entity ID.

        Returns:
            Response from API.
        """
        params = {
            'entityid': entity_id
        }
        watchlist = self.http_request('GET', '/incident/checkIfWatchlisted',
                                      headers={'token': self._token}, params=params)
        return watchlist

    def add_entity_to_watchlist_request(self, watchlist_name: str, entity_type: str, entity_id: str,
                                        expiry_days: str, resource_name: str = None) -> Dict:
        """Check if an entity is whitelisted by sending a GET request.

        Args:
            watchlist_name: Watchlist name.
            entity_type: Entity type.
            entity_id: Entity ID.
            resource_name: Resource name.
            expiry_days: Expiry in days.
        Returns:
            Response from API.
        """
        params = {
            'watchlistname': watchlist_name,
            'entitytype': entity_type,
            'entityid': entity_id,
            'expirydays': expiry_days,
        }
        if resource_name:
            params['resourcegroupid'] = resource_name
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
                                     headers=['Workflow', 'Type Name', 'Value'],
                                     removeNull=True)
    entry_context = {f'Securonix.Workflows(val.Workflow == obj.Workflow)': workflows_outputs}
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
    entry_context = {f'Securonix.Workflows(val.Workflow == obj.Workflow)': workflow_output}
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
    entry_context = {f'Securonix.ThreatActions': threat_actions}
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
    entry_context = {f'Securonix.Policies(val.ID === obj.ID)': policies_outputs}

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
    entry_context = {f'Securonix.ResourceGroups(val.Name === obj.Name)': resource_groups_outputs}

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
    entry_context = {f'Securonix.Users(val.EmployeeId === obj.EmployeeId)': users_outputs}

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
    activity_readable, activity_outputs = parse_data_arr(activity_events)
    headers = ['Eventid', 'Eventtime', 'Message', 'Accountname']
    human_readable = tableToMarkdown(name="Activity data:", t=activity_readable, headers=headers, removeNull=True)
    entry_context = {f'Securonix.ActivityData(val.Eventid === obj.Eventid)': activity_outputs}

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
    violation_readable, violation_outputs = parse_data_arr(violation_events)
    headers = ['Eventid', 'Eventtime', 'Message', 'Policyname', 'Accountname']
    human_readable = tableToMarkdown(name="Activity data:", t=violation_readable, headers=headers, removeNull=True)
    entry_context = {f'Securonix.ViolationData(val.Eventid === obj.Eventid)': violation_outputs}

    return human_readable, entry_context, violation_data


def list_incidents(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """List incidents.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    from_, _ = parse_date_range(args.get('from'), utc=True)
    from_epoch = date_to_timestamp(from_)
    to_ = args.get('to') if 'to_' in args else get_now()
    to_epoch = date_to_timestamp(to_)
    range_type = argToList(args.get('range_type')) if 'range_type' in args else ['updated', 'opened', 'closed']

    incidents = client.list_incidents_request(from_epoch, to_epoch, range_type)

    total_incidents = incidents.get('totalIncidents')
    if not total_incidents or float(total_incidents) <= 0.0:
        return 'No incidents where found in this time frame.', {}, incidents
    incidents_items = incidents.get('incidentItems')
    incidents_readable, incidents_outputs = parse_data_arr(incidents_items)
    headers = ['Incident Id', 'Incident Status', 'Incident Type', 'Priority', 'Reason']
    human_readable = tableToMarkdown(name="Incidents:", t=incidents_readable,
                                     headers=headers, removeNull=True)
    entry_context = {f'Securonix.Incidents(val.IncidentId === obj.IncidentId)': incidents_outputs}
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
    entry_context = {f'Securonix.Incidents(val.IncidentId === obj.IncidentId)': incident_outputs}
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

    return f'Incident {incident_id} status is {incident_status}.', {}, incident


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

    return f'Incident {incident_id} workflow is {incident_workflow}.', {}, incident


def get_incident_available_actions(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Get incident available actions.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    incident_id = str(args.get('incident_id'))

    incident = client.get_incident_available_actions_request(incident_id)
    if not incident:
        return f'Incident {incident_id} does not have any available actions.', {}, incident

    incident_actions = incident.get('actions')  # TODO - incident which is not closed
    return f'Incident {incident_id} available actions: {incident_actions}.', {}, incident


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
    incident = client.perform_action_on_incident_request(incident_id, action)
    incident_result = incident.get('result')  # TODO - real api action on a non closed incident
    if incident_result != 'submitted':
        raise Exception(f'Failed to perform the action {action} on incident {incident_id}.')
    return f'Action {action} was performed on incident {incident_id}.', {}, incident


def create_incident(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """Create an incident.

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    policy_name = str(args.get('policy_name'))
    resource_group = str(args.get('resource_group'))
    entity_type = str(args.get('entity_type'))
    entity_name = str(args.get('entity_id'))
    action_name = str(args.get('action_name'))
    resource_name = args.get('resource_name')
    workflow = args.get('workflow')
    comment = args.get('comment')
    employee_id = args.get('employee_id')
    criticality = args.get('criticality')

    incident = client.create_incident_request(policy_name, resource_group, entity_type, entity_name, action_name,
                                              resource_name, workflow, comment, employee_id, criticality)
    demisto.log(str(incident))
    incident_info = incident.get('result')  # TODO - check that really works - status OK is lying - not visible in UI
    if not incident_info:
        raise Exception('Failed to create the incident. something is missing...')
    return f'Incident was created successfully.', {}, incident_info


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
    demisto.log('really check it worksssssss')  # TODO - see comment in UI
    return f'Comment was added to the incident {incident_id} successfully.', {}, incident


def list_watchlists(client: Client, *_) -> Tuple[str, Dict, Dict]:
    """List all watchlists.

    Args:
        client: Client object with request.

    Returns:
        Outputs.
    """
    watchlists = client.list_watchlist_request()
    if not watchlists:
        raise Exception(f'Failed to list watchlists.')

    human_readable = f'Watchlists: {", ".join(watchlists)}.'
    entry_context = {f'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)': watchlists}
    return human_readable, entry_context, watchlists


def get_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """List all watchlists.

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
        raise Exception(f'Watchlist does not contain items.\n'
                        f'Make sure the watchlist is not empty and that the watchlist name is correct.')
    watchlist_readable, watchlist_events_outputs = parse_data_arr(watchlist_events)
    watchlist_outputs = {
        'Watchlistname': watchlist_name,
        'Events': watchlist_events_outputs
    }
    headers = ['Watchlistname', 'Type', 'Entityname', 'U_Fullname', 'U_Workemail', 'Expired']
    human_readable = tableToMarkdown(name="Watchlist items:", t=watchlist_readable, headers=headers, removeNull=True)
    entry_context = {f'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)': watchlist_outputs}
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

    watchlist = client.create_watchlist_request(watchlist_name)  # TODO - real api call since not working in our env

    if not watchlist:
        raise Exception(f'Failed to list watchlists.')

    human_readable = f'Watchlists: {", ".join(watchlist)}.'
    entry_context = {f'Securonix.Watchlists(val.Watchlistname === obj.Watchlistname)': watchlist}
    return human_readable, entry_context, watchlist


def check_entity_in_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """Check if entity is in a watchlist.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Outputs.
    """
    entity_id = args.get('entity_id')

    watchlist = client.check_entity_in_watchlist_request(entity_id)  # TODO - real api call since not working in our env

    watchlist_names = watchlist.get('result')
    if not watchlist_names:
        human_readable = f'Entity {entity_id} is not a part of any watchlist.'
        output = {'EntityID': entity_id}
    else:
        human_readable = f'Entity {entity_id} is a part of the watchlists: {", ".join(watchlist_names)}.'
        output = {
            'EntityID': entity_id,
            'Watchlistnames': watchlist_names
        }
    entry_context = {f'Securonix.EntityInWatchlist(val.EntityID === obj.EntityID)': output}
    return human_readable, entry_context, watchlist


def add_entity_to_watchlist(client: Client, args) -> Tuple[str, Dict, Dict]:
    """Check if entity is in a watchlist.

    Args:
        client: Client object with request.
        args: Usually demisto.args()
    Returns:
        Outputs.
    """
    watchlist_name = args.get('watchlist_name')
    entity_type = args.get('entity_type')
    entity_id = args.get('entity_id')
    resource_name = args.get('resource_name') if entity_type in ['Resources', 'Activityaccount'] else entity_id
    expiry_days = args.get('expiry_days')

    watchlist = client.add_entity_to_watchlist_request(watchlist_name, entity_type, entity_id,
                                                       expiry_days, resource_name)

    if 'Add to watchlist successfull' not in watchlist:
        raise Exception(f'Failed to add entity {entity_id} to watchlist {watchlist_name}.\n'
                        f'Error from Securonix is: {watchlist}.')
    human_readable = f'Added successfully the entity {entity_id} to the watchlist {watchlist_name}.'
    return human_readable, {}, watchlist


# def fetch_incidents(client, last_run, first_fetch_time, event_type_filter, threat_type, threat_status,
#                     limit='50', integration_context=None):
#     """Fetch incidents from Securonix to Demisto.
#
#     Args:
#         client:
#         last_run:
#         first_fetch_time:
#         event_type_filter:
#         threat_type:
#         threat_status:
#         limit:
#         integration_context:
#
#     Returns:
#         Incidents.
#     """
#     incidents: list = []
#     end_query_time = ''
#     # check if there're incidents saved in context
#     if integration_context:
#         remained_incidents = integration_context.get("incidents")
#         # return incidents if exists in context.
#         if remained_incidents:
#             return last_run, remained_incidents[:limit], remained_incidents[limit:]
#     # Get the last fetch time, if exists
#     start_query_time = last_run.get("last_fetch")
#     # Handle first time fetch, fetch incidents retroactively
#     if not start_query_time:
#         start_query_time, _ = parse_date_range(first_fetch_time, date_format='1', utc=True)
#     fetch_times = get_fetch_times(start_query_time)
#     for i in range(len(fetch_times) - 1):
#         start_query_time = fetch_times[i]
#         end_query_time = fetch_times[i + 1]
#         raw_events = client.get_events(interval=start_query_time + "/" + end_query_time,
#                                        event_type_filter=event_type_filter,
#                                        threat_status=threat_status, threat_type=threat_type)
#
#         message_delivered = raw_events.get("messagesDelivered", [])
#         for raw_event in message_delivered:
#             raw_event["type"] = "messages delivered"
#             event_guid = raw_event.get("GUID", "")
#             incident = {
#                 "name": "Proofpoint - Message Delivered - {}".format(event_guid),
#                 "rawJSON": json.dumps(raw_event),
#                 "occurred": raw_event["messageTime"]
#             }
#             incidents.append(incident)
#
#         message_blocked = raw_events.get("messagesBlocked", [])
#         for raw_event in message_blocked:
#             raw_event["type"] = "messages blocked"
#             event_guid = raw_event.get("GUID", "")
#             incident = {
#                 "name": "Proofpoint - Message Blocked - {}".format(event_guid),
#                 "rawJSON": json.dumps(raw_event),
#                 "occured": raw_event["messageTime"],
#             }
#             incidents.append(incident)
#
#         clicks_permitted = raw_events.get("clicksPermitted", [])
#         for raw_event in clicks_permitted:
#             raw_event["type"] = "clicks permitted"
#             event_guid = raw_event.get("GUID", "")
#             incident = {
#                 "name": "Proofpoint - Click Permitted - {}".format(event_guid),
#                 "rawJSON": json.dumps(raw_event),
#                 "occurred": raw_event["clickTime"] if raw_event["clickTime"] > raw_event["threatTime"] else raw_event[
#                     "threatTime"]
#             }
#             incidents.append(incident)
#
#         clicks_blocked = raw_events.get("clicksBlocked", [])
#         for raw_event in clicks_blocked:
#             raw_event["type"] = "clicks blocked"
#             event_guid = raw_event.get("GUID", "")
#             incident = {
#                 "name": "Proofpoint - Click Blocked - {}".format(event_guid),
#                 "rawJSON": json.dumps(raw_event),
#                 "occurred": raw_event["clickTime"] if raw_event["clickTime"] > raw_event["threatTime"] else raw_event[
#                     "threatTime"]
#             }
#             incidents.append(incident)
#
#     # Cut the milliseconds from last fetch if exists
#     end_query_time = end_query_time[:-5] + 'Z' if end_query_time[-5] == '.' else end_query_time
#     next_run = {"last_fetch": end_query_time}
#     return next_run, incidents[:limit], incidents[limit:]
#
#
# def fetch_incident_command():
#     """
#     Demisto Incidents
#     """
#     # How many time before the first fetch to retrieve incidents
#     fetch_time = params.get('fetch_time', '60 minutes')
#     fetch_limit = 50
#     integration_context = demisto.getIntegrationContext()
#     next_run, incidents, remained_incidents = fetch_incidents(  # type: ignore
#         client=client,
#         last_run=demisto.getLastRun(),
#         first_fetch_time=fetch_time,
#         limit=fetch_limit,
#         integration_context=integration_context
#     )
#     # Save last_run, incidents, remained incidents into integration
#     demisto.setLastRun(next_run)
#     demisto.incidents(incidents)
#     # preserve context dict
#     integration_context['incidents'] = remained_incidents
#     demisto.setIntegrationContext(integration_context)


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get('username')
    password = params.get('password')
    tenant = params.get("tenant")
    server_url = f'https://{tenant}.securonix.net/Snypr/ws/'
    verify = not params.get('insecure', False)
    proxies = handle_proxy()  # Remove proxy if not set to true in params

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client = Client(tenant=tenant, server_url=server_url, username=username, password=password,
                        verify=verify, proxies=proxies)
        commands = {
            'test-module': test_module,
            # 'fetch-incidents': fetch_incident_command,
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
            'securonix-create-incident': create_incident,
            'securonix-add-comment-to-incident': add_comment_to_incident,
            'securonix-list-watchlists': list_watchlists,
            'securonix-get-watchlist': get_watchlist,
            'securonix-create-watchlist': create_watchlist,
            'securonix-check-entity-in-watchlist': check_entity_in_watchlist,
            'securonix-add-entity-to-watchlist': add_entity_to_watchlist
        }
        if command in commands:
            return_outputs(*commands[command](client, demisto.args()))  # type: ignore

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
