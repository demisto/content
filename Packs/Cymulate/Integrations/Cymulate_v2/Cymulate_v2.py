from datetime import date
from typing import Any, Dict, Tuple, Optional

import copy
import json
import traceback
import urllib3

from CommonServerPython import *  # pylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CY_GENERAL_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
CY_UNIQUE_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'

MAX_INCIDENTS_TO_FETCH = 35
MAX_EVENTS_TO_DISPLAY = 20

SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
ACCESSED_STATUS = ['penetrated', 'accessed', 'executed completely', 'exfiltrated', 'completed']
ENDPOINT_DICT = {'web-gateway': 'browsing',
                 'exfiltration': 'dlp',
                 'email-gateway': 'mail',
                 'endpoint-security': 'edr',
                 'waf': 'waf',
                 'kill-chain': 'apt',
                 'immediate-threats': 'immediate-threats',
                 'phishing-awareness': 'phishing',
                 'lateral-movement': 'hopper'
                 }


class Client(BaseClient):
    """
    Client for Cymulate RESTful API.

    Args:
          base_url (str): Cymulate server url.
          token (str): Cymulate access token.
          verify (bool): Whether the request should verify the SSL certificate.
          proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, token: str, verify: bool, proxy: bool, **kwargs):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)
        self.headers = {'x-token': token,
                        'accept': '*/*',
                        'Content-Type': 'application/json'
                        }

    def validate(self):
        """ Helper function for test_module that creates a simple API call"""
        return self._http_request(method='GET',
                                  url_suffix='/user/modules',
                                  headers=self.headers,
                                  resp_type='response')

    def start_assessment(self, endpoint: Optional[str], data: dict):
        """ Start new assessment.

        Args:
            endpoint (str): Cymulate's endpoint to start the assessment on.
            data (dict): Dictionary containing all relevant data for running new assessment.
        """
        return self._http_request(method='POST',
                                  url_suffix=f'{endpoint}/start',
                                  headers=self.headers,
                                  data=json.dumps(data))

    def stop_assessment(self, endpoint: Optional[str]):
        """ Stop a running assessment.

        Args:
            endpoint (str): The Cymulate endpoint to stop the assessment.
        """
        return self._http_request(method='POST',
                                  url_suffix=f'/{endpoint}/stop',
                                  headers=self.headers)

    def get_assessment_status(self, endpoint: Optional[str], assessment_id: Optional[str]):
        """ Retrieve an assessment status.

        Args:
            endpoint (str): Cymulate's endpoint to get the assessment status for.
            assessment_id (str): The assessment ID to get the status to.
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/{endpoint}/status',
                                  headers=self.headers,
                                  params={'id': assessment_id})

    def list_templates(self, endpoint: Optional[str]):
        """ Retrieve a list af all Cymulate templates to run the assessments on.

        Args:
            endpoint (str): The Cymulate endpoint templates list.
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/{endpoint}/templates',
                                  headers=self.headers)

    def list_phishing_contacts(self):
        """ Retrieve a list af all phishing contacts."""
        return self._http_request(method='GET',
                                  url_suffix='/phishing/contacts/groups',
                                  headers=self.headers)

    def get_phishing_contacts(self, group_id: Optional[str]):
        """ Retrieve a list of phishing contacts by group ID."""
        return self._http_request(method='GET',
                                  url_suffix='/phishing/contacts',
                                  headers=self.headers,
                                  params={'groupId': group_id})

    def create_phishing_contacts(self, group_name: Optional[str]):
        """ Create phishing contacts group."""
        return self._http_request(method='POST',
                                  url_suffix='/phishing/contacts/group',
                                  headers=self.headers,
                                  params={'groupName': group_name})

    def get_agents(self):
        """ Retrieve a list af all agents."""
        return self._http_request(method='GET',
                                  url_suffix='/agents/get/',
                                  headers=self.headers,
                                  resp_type='json')

    def list_attacks(self, endpoint: Optional[str]):
        """Retrieves attacks by module.

        Args:
            endpoint (str): Cymulate's endpoint to list attacks by module.
        """
        response = self._http_request(method='GET',
                                      url_suffix=f'/{endpoint}/attacks/technical',
                                      headers=self.headers)
        return response.get('data')

    def list_attack_ids_by_date(self, endpoint: Optional[str], from_date: Optional[str],
                                to_date: Optional[str] = None):
        """Retrieves attack IDs by their dates.

        Args:
            endpoint (str): Cymulate's endpoint to list attacks.
            from_date (str): From which date to fetch data.
            to_date (str): End date to fetch data. If no argument is given, value will be now.
        """
        to_date = to_date if to_date else date.today().strftime("%Y-%m-%d")
        response = self._http_request(method='GET',
                                      url_suffix=f'/{endpoint}/history/get-ids',
                                      params={'fromDate': from_date,
                                              'toDate': to_date},
                                      headers=self.headers)
        return dict_safe_get(dict_object=response, keys=['data', 'attack'], return_type=list)

    def list_immediate_threats_ids_by_date(self, from_date: Optional[str], to_date: Optional[str]):
        """Retrieves immediate threats attack IDs by their dates.

        Args:
            from_date (str): From which date to fetch data.
            to_date (str): End date to fetch data. If no argument is given, value will be now.
        """
        response = self._http_request(method='GET',
                                      url_suffix='/immediate-threats/ids',
                                      params={'fromDate': from_date,
                                              'toDate': to_date},
                                      headers=self.headers)
        return response.get('data')

    def list_attack_ids(self, endpoint: Optional[str]):
        """Retrieves all attack IDs.

        Args:
            endpoint (str): The Cymulate endpoint to list attacks.
        """
        response = self._http_request(method='GET',
                                      url_suffix=f'/{endpoint}/ids',
                                      headers=self.headers)
        return response.get('data')

    def get_attack_by_id(self, endpoint: Optional[str], attack_id: Optional[str]):
        """Retrieves data regarding an attack by the attack ID.

        Args:
            endpoint (str): The Cymulate endpoint to retrieve attacks data from.
            attack_id (str): ID of the attack to retrieve data to.
        """
        response = self._http_request(method='GET',
                                      url_suffix=f'/{endpoint}/attack/technical/{attack_id}',
                                      headers=self.headers)
        return response.get('data')

    def get_immediate_threat_assessment(self, attack_id: Optional[str]):
        """Retrieves data regarding immediate threats attack by the attack ID.

        Args:
            attack_id (str): ID of the attack to retrieve data to.
        """
        response = self._http_request(method='GET',
                                      url_suffix=f'/immediate-threats/attack/technical/{attack_id}',
                                      headers=self.headers).get('data')
        return response.get('payloads')

    def get_simulations_by_id(self, endpoint: Optional[str], attack_id: Optional[str]):
        """ Retrieves all event data."""
        return self._http_request(method='GET',
                                  url_suffix=f'{endpoint}/history/technical/{attack_id}',
                                  headers=self.headers,
                                  params={'id': attack_id})


''' HELPER FUNCTIONS '''


def extract_status_commands_output(result: dict) -> dict:
    """Parse the dictionary returned from the API call to a XSOAR output.

    Args:
        result (dict): API call result.
    """
    output = {
        'id': result.get('id') if result.get('id') else result.get('_id'),
        'inProgress': result.get('inProgress'),
        'progress': result.get('progress'),
        'categories': result.get('categories'),
        'addresses': result.get('addresses'),
    }
    return remove_empty_elements(output)


def extract_template_output(raw_response: dict):
    """Helper function to replace all the `_id` key to `id`.

    Args:
        raw_response (dict): Raw response returned from the API.

    Returns:
        list[Dict]: The raw response where the `_id` key has replaced with `id`.
    """
    outputs = copy.deepcopy(raw_response)
    for dictionary in outputs:
        dictionary['id'] = dictionary.pop('_id', None)
    return outputs


def validate_timestamp(timestamp: Any) -> bool:
    """
        Helper function to validate the input timestamp format. Cymulate API can return empty
        timestamp or an invalid string (for example the string 'no timestamp').

    Args:
        timestamp: input timestamp

    Returns:
        bool: True if the input is in valid format, else False.
    """
    try:
        if re.match(r'\d{4}-\d{2}-\d{2}', timestamp):
            return True
    except Exception:  # pylint: disable=broad-except
        return False
    return False


def get_alerts_by_module(client: Client, module_name: str,
                         last_fetch: int) -> Tuple[List[Any], int, int, int]:
    """Helper function to retrieves raw data from the API according to the module currently fetched,
    and using format_incidents() function to format the raw data into XSOAR incident format.

    Args:
        client (Client): Cymulate client.
        module_name (str): The module we are currently fetching.
        last_fetch (int): Timestamp in milliseconds on when to start fetching incidents.

    Returns:
        list: incidents,
        int: event_offset,
        str: alert_created_time,
        int: len(events)

    """

    raw_data = []
    timestamp_endpoint = None
    event_offset = get_integration_context().get('offset', 0)

    if module_name in ('web-gateway', 'exfiltration', 'endpoint-security'):
        raw_data = client.list_attacks(ENDPOINT_DICT.get(module_name))

    elif module_name == 'email-gateway':
        raw_data = client.list_attacks(ENDPOINT_DICT.get(module_name))
        timestamp_endpoint = 'Email_Received'

    elif module_name == 'waf':
        id_data = client.list_attack_ids(module_name)

        # Extracting the attack data for each site ID.
        for cur_id in id_data:
            raw_data.extend(client.get_attack_by_id(ENDPOINT_DICT.get(module_name),
                                                    cur_id.get('Id')))

    elif module_name == 'kill-chain':
        id_data = client.list_attack_ids(ENDPOINT_DICT.get(module_name))

        # Kill Chain endpoint returns IDs from all times so filter by time before creating incidents
        relevant_id_list = []
        for cur_id in id_data:
            alert_created_time = int(date_to_timestamp(cur_id.get('Timestamp'),
                                                       date_format=CY_GENERAL_DATE_FORMAT))
            if alert_created_time >= last_fetch:
                relevant_id_list.append(cur_id.get('Id'))

        # Extracting the attack data for each site ID.
        for cur_id in relevant_id_list:
            raw_data.extend(client.get_attack_by_id(ENDPOINT_DICT.get(module_name), cur_id))

    elif module_name == 'immediate-threats':
        from_date = timestamp_to_datestring(last_fetch, '%Y-%m-%d')
        id_data = client.list_attack_ids_by_date(ENDPOINT_DICT.get(module_name), from_date)

        # Immediate threats endpoint returns IDs from all times so filter by time.
        relevant_id_list = []
        for cur_id in id_data:
            alert_created_time = int(date_to_timestamp(cur_id.get('Timestamp'),
                                                       date_format=CY_UNIQUE_DATE_FORMAT))
            if alert_created_time >= last_fetch:
                relevant_id_list.append(cur_id.get('Id'))

        # Extracting the attack data for each site ID.
        site_id_list = format_id_list(id_data)

        for cur_id in site_id_list:
            raw_data.extend(client.get_immediate_threat_assessment(cur_id))

    elif module_name in ('phishing-awareness', 'lateral-movement'):
        from_date = timestamp_to_datestring(last_fetch, '%Y-%m-%d')
        id_data = client.list_attack_ids_by_date(ENDPOINT_DICT.get(module_name), from_date)

        # Extracting the attack data for each site ID.
        site_id_list = format_id_list(id_data)

        for cur_id in site_id_list:
            raw_data.extend(client.get_attack_by_id(ENDPOINT_DICT.get(module_name), cur_id))

        if module_name == 'phishing-awareness':
            timestamp_endpoint = 'Campaign_Start_Timestamp'

    return format_incidents(raw_data, event_offset, last_fetch, module_name, timestamp_endpoint)


def format_id_list(id_data_dict: dict) -> list:
    """ Helper function to create an ID list from an ID data dictionary.

    Args:
        id_data_dict (dict): Dictionary containing full IDs data.

    Returns:
        list: containing IDs only.
    """
    id_list = []

    for id_data in id_data_dict:
        # The API might return ID, Id or id as key, so converting dict keys to be lowercase.
        data = {k.lower(): v for k, v in id_data.items()}
        id_list.append(data.get('id', None))

    # Remove None objects from ID list, if exists.
    id_list = [id for id in id_list if id]
    return id_list


def format_incidents(events: list, event_offset: int, last_fetch: int, module_name: str,
                     timestamp_endpoint: str = None) -> Tuple[List[Any], int, int, int]:
    """
    This function loops over the alerts list and create incidents from different events.
    For `Endpoint Security` and `Kill Chain` modules, if current event name is identical to previous
    event name, then both are part of the same incident and we will only update the existing
    incident description and won't create a new incident.

    Args:
        events (list): Events list to create incidents from.
        event_offset (int): Event offset.
        last_fetch (int): Timestamp in milliseconds on when to start fetching incidents.
        module_name (str): Module name.
        timestamp_endpoint(str): What API endpoint represent the event timestamp. If None is given,
                                timestamp endpoint from API can be 'Timestamp' or 'Attack_Timestamp'

    Returns:
        list: incidents,
        int: event_offset,
        str: alert_created_time,
        int: len(events)
    """
    incidents: List[Any] = []
    event_counter = 0
    offset = event_offset
    alert_created_time = last_fetch
    max_alert_created_time = alert_created_time
    for event in events[offset:]:

        # if current event name is identical to previous, then only update incident description.
        if (module_name in ('endpoint-security', 'kill-chain')) and \
                (incidents and extract_event_name(event, module_name) == incidents[-1].get('name')):
            event_offset += 1
            last_incident = incidents[-1]
            alert_created_time = last_incident.get('occurred')

            if module_name == 'endpoint-security':
                alert_created_time = int(date_to_timestamp(alert_created_time,
                                                           date_format=DATE_FORMAT))
            elif module_name == 'kill-chain':
                alert_created_time = int(date_to_timestamp(alert_created_time,
                                                           date_format=CY_GENERAL_DATE_FORMAT))

            step_num = event.get('Scenario_Counter') if module_name == 'endpoint-security' \
                else event.get('Stage_Phase')

            data = json.loads(last_incident.get('rawJSON'))
            current_description = data.get('description')
            new_description = f"\nStep {step_num}:\n{extract_event_description(event)}"

            data['description'] = f'{current_description}{new_description}' if current_description \
                else new_description

            # Insert new description to the previous incident.
            last_incident['rawJSON'] = json.dumps(data)
            incidents[-1] = last_incident

            # Keep track on the latest incident timestamp. Events that are part of an incident are
            # returned without timestamp so we only use the first the event's timestamp (First step)
            if alert_created_time > max_alert_created_time:
                max_alert_created_time = alert_created_time

        # The current event is new (has new name), then we need to build a new incident.
        else:
            if event_counter >= min(MAX_INCIDENTS_TO_FETCH,
                                    int(demisto.params().get('max_fetch', MAX_INCIDENTS_TO_FETCH))):
                break

            # Incrementing the event offset, regardless of whether new incident will be created.
            event_offset += 1

            # If attack status is identical to previous assessment status, or the current attack was
            # unsuccessful, we won't create incident.
            if not event_status_changed(event):
                continue

            if timestamp_endpoint is None:
                t_stamp = event.get('Timestamp') if event.get('Timestamp') else \
                    event.get('Attack_Timestamp')
            else:
                t_stamp = event.get(timestamp_endpoint)

            # Validate API timestamp.
            if validate_timestamp(t_stamp):
                try:
                    alert_created_time = date_to_timestamp(t_stamp,
                                                           date_format=CY_GENERAL_DATE_FORMAT)
                except Exception:
                    alert_created_time = date_to_timestamp(t_stamp,
                                                           date_format=CY_UNIQUE_DATE_FORMAT)

                # If current alert was created since last fetch time, create XS0AR incident.
                if alert_created_time >= last_fetch:
                    incidents.append(build_incident_dict(event, module_name, t_stamp))
                    event_counter += 1

                    # Keep track on the latest incident timestamp.
                    if alert_created_time > max_alert_created_time:
                        max_alert_created_time = alert_created_time

    return incidents, event_offset, max_alert_created_time, len(events)


def extract_event_name(event: dict, module_name: str) -> str:
    """Helper function to extract event name according to the event module.

    Args:
        event (dict): Full event data return from API.
        module_name (str): Module name.
    """
    event_name = f"Cymulate - {module_name} - "

    if module_name in ('web-gateway', 'email-gateway', 'immediate-threats'):
        event_name = f"{event_name}{event.get('Attack_Payload')}"

    elif module_name == 'exfiltration':
        event_name = f"{event_name}{event.get('Phrase_Title')}-{event.get('Classification')}"

    elif module_name == 'endpoint-security':
        event_name = f"{event_name}{event.get('Scenario_Title')}"

    elif module_name == 'waf':
        event_name = f"{event_name}{event.get('Payload')}"

    elif module_name == 'kill-chain':
        event_name = f"{event_name}{event.get('Template_Name')}"

    elif module_name == 'phishing-awareness':
        event_name = f"{event_name}{event.get('User')}"

    elif module_name == 'lateral-movement':
        event_name = f"{event_name}" \
                     f"{event.get('Source_Hostname')}-{event.get('Destination_Hostname')}"

    return event_name


def extract_event_description(event) -> Optional[Any]:
    """Helper function to extract event description.

    Args:
        event (dict): Full event data return from API.

    Returns:
        str: event description if exists, else: None.
    """
    event_description = None
    if event.get('Description'):
        event_description = event.get('Description')

    elif event.get('Phrase'):
        event_description = event.get('Phrase')

    elif event.get('Summery'):
        event_description = event.get('Summery')
    return event_description


def event_status_changed(event: dict) -> bool:
    """We only create incidents from penetrated attacks, that were not penetrated in the last
    attack scenario. This function checks if the event is penetrated for the first time.

    Args:
        event (dict): Event dictionary returned from API.

    Returns:
        bool: True if the event was penetrated for the first time, else False.
    """
    status_changed = True

    prev = event.get('PrevStatus') if event.get('PrevStatus') \
        else event.get('Previous_Scenario_Status')
    if (prev and prev.lower() in ACCESSED_STATUS) or event.get('Previously_Phished'):
        status_changed = False

    cur = event.get('Status') if event.get('Status') else event.get('Step_Status')
    if cur and cur.lower() not in ACCESSED_STATUS:
        status_changed = False

    return status_changed


def build_incident_dict(event: dict, module_name: str, event_timestamp=None) -> dict:
    """ Helper function for fetch incident that builds the incidents.

    Args:
        event (dict): Event dictionary.
        module_name (str): Module name.
        event_timestamp: Event timestamp.

    Returns:
        dict: XSOAR incident.
    """
    if event is None:
        return {}

    incident_data = {
        'cymulateStatus': event.get('Status'),
        'module': event.get('Module'),
        'user': event.get('User'),
        'lastAction': event.get('Last_Action'),
        'source': event.get('Source'),
        'testCase': event.get('Test_Case'),
        'attackType': event.get('Attack_Type'),
        'attackVector': event.get('Attack_Vector'),
        'templateName': event.get('Template_Name'),
        'inProgress': event.get('InProgress'),
        'url': event.get('Url'),
        'input': event.get('Input'),
        'sourceEmailAddress': event.get('Source_Email_Address'),
        'agentless': event.get('Agentless'),
        'analysis': event.get('Analysis'),
        'command': event.get('Command'),
        'description': extract_event_description(event),
        'md5': event.get('MD5') if event.get('MD5') else event.get('Md5'),
        'sha256': event.get('SHA256') if event.get('SHA256') else event.get('Sha256'),
        'sha1': event.get('SHA1') if event.get('SHA1') else event.get('Sha1'),
    }

    mitigation = event.get('Mitigation_Details') if event.get('Mitigation_Details') else event.get(
        'Mitigation')
    if mitigation:
        incident_data['mitigationDetails'] = mitigation

    attack_payload = event.get('Attack_Payload')
    if attack_payload and attack_payload.startswith('http'):
        incident_data['url'] = attack_payload

    elif attack_payload:
        incident_data['attackType'] = attack_payload

    incident = {
        'name': extract_event_name(event, module_name),
        'occurred': event_timestamp,
        'severity': convert_to_xsoar_severity(event.get('Risk')),
        'rawJSON': json.dumps(remove_empty_elements(incident_data)),
    }

    if not event_timestamp:
        event_timestamp = event.get('Timestamp') if event.get('Timestamp') \
            else event.get('Attack_Timestamp')
    if validate_timestamp(event_timestamp):
        try:
            occurred = datetime.strptime(event_timestamp, CY_GENERAL_DATE_FORMAT).strftime(DATE_FORMAT)  # CHANGED
        except Exception:
            occurred = datetime.strptime(event_timestamp, CY_UNIQUE_DATE_FORMAT).strftime(DATE_FORMAT)  # CHANGED

        incident['occurred'] = occurred

    return incident


def convert_to_xsoar_severity(severity: Optional[Any]) -> int:
    """Maps Cymulate severity to Cortex XSOAR severity.

    Args:
        severity(str): severity as returned from Cymulate API. If API does not return severity,
                       The function will return 0.

    Returns:
        int: Cortex XSOAR Severity (1 to 4)
    """
    if severity:
        return {
            'low': IncidentSeverity.LOW,
            'medium': IncidentSeverity.MEDIUM,
            'high': IncidentSeverity.HIGH,
            'critical': IncidentSeverity.CRITICAL
        }.get(severity.lower(), IncidentSeverity.UNKNOWN)
    return IncidentSeverity.UNKNOWN


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication. Returning 'ok' indicates that the integration
    works like it is supposed to. Connection to the service is successful.

    Args:
        client (Client): Cymulate client.
    """
    test_message = 'ok'
    try:
        response = client.validate()
        if not response.ok:
            raise DemistoException('Authorization Error: make sure API Key is correctly set.',
                                   res=response)
    except DemistoException as err:
        if 'Unauthorized' in str(err):
            test_message = f'Authorization Error: make sure API Key is correctly set.\n\n{err}'
        else:
            raise

    return test_message


def list_exfiltration_template_command(client: Client) -> CommandResults:
    """Retrieve a list of all exfiltration templates.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all exfiltration templates.

    """
    raw_response = client.list_templates(ENDPOINT_DICT.get('exfiltration'))
    outputs = extract_template_output(raw_response.get('data'))

    readable_output = tableToMarkdown('Exfiltration templates list:', outputs, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.Exfiltration.Template',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def start_exfiltration_assessment_command(client: Client, template_id: str, agent_name: str,
                                          schedule: bool, schedule_loop: str) -> CommandResults:
    """Start a new exfiltration assessment.

    Args:
        client (Client): Cymulate client.
        template_id (str): The ID of the template to run the exfiltration Assessment with.
        agent_name (str): Agent name to run simulation attacks.
        schedule (bool): Whether to schedule the automated assessment periodically.
        schedule_loop (str): Loop size of the scheduled agent.
                             For example: to run the agent only once, use the value 'one-time'.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the start assessment data.

    """
    params = {
        'templateID': template_id,
        'agentName': agent_name,
        'schedule': schedule,
        'scheduleLoop': schedule_loop
    }

    raw_response = client.start_assessment(ENDPOINT_DICT.get('exfiltration'), params)
    output = {
        'id': raw_response.get('data'),
        'success': raw_response.get('success'),
    }

    readable_output = tableToMarkdown('Starting exfiltration assessment:', output)
    command_results = CommandResults(
        outputs_prefix='Cymulate.Exfiltration',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def stop_exfiltration_assessment_command(client: Client) -> CommandResults:
    """Stop a running exfiltration assessment.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the stop assessment data.
    """
    raw_response = client.stop_assessment(ENDPOINT_DICT.get('exfiltration'))
    readable_output = tableToMarkdown('Stopping exfiltration assessment:', raw_response)

    command_results = CommandResults(
        outputs_prefix='Cymulate.Exfiltration',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def get_exfiltration_assessment_status_command(client: Client,
                                               assessment_id: str) -> CommandResults:
    """Retrieve exfiltration assessment status.

    Args:
        client (Client): Cymulate client.
        assessment_id (str): The ID of the assessment to retrieve the status to.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the assessment status.

    """
    raw_response = client.get_assessment_status(ENDPOINT_DICT.get('exfiltration'), assessment_id)
    outputs = extract_status_commands_output(raw_response)
    readable_output = tableToMarkdown('Exfiltration assessment status:', outputs, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.Exfiltration',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def list_email_gateway_template_command(client: Client) -> CommandResults:
    """Retrieve a list of all email gateway templates.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all email-gateway templates.
    """
    raw_response = client.list_templates(ENDPOINT_DICT.get('email-gateway'))
    outputs = extract_template_output(raw_response)
    readable_output = tableToMarkdown('Email gateway templates list:',
                                      outputs,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.EmailGateway.Template',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def start_email_gateway_assessment_command(client: Client, template_id: str, agent_email: str,
                                           schedule: bool, schedule_loop: str) -> CommandResults:
    """Start a new email gateway assessment.

    Args:
        client (Client): Cymulate client.
        template_id (str): The ID of the template to run the assessment with.
        agent_email (str): Agent email to run simulation attacks.
        schedule (bool): Whether to schedule the automated assessment periodically.
        schedule_loop (str): Loop size of the scheduled agent.
                             For example: to run the agent only once, use the value 'one-time'.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the start assessment data.
    """

    params = {
        'templateID': template_id,
        'agentEmail': agent_email,
        'schedule': schedule,
        'scheduleLoop': schedule_loop
    }

    raw_response = client.start_assessment(ENDPOINT_DICT.get('email-gateway'), params)
    output = {
        'id': raw_response.get('data'),
        'success': raw_response.get('success')
    }

    readable_output = tableToMarkdown('Starting email gateway assessment:', output)
    command_results = CommandResults(
        outputs_prefix='Cymulate.EmailGateway',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def stop_email_gateway_assessment_command(client: Client) -> CommandResults:
    """Stop a running email gateway assessment.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the stop assessment data.
    """
    raw_response = client.stop_assessment(ENDPOINT_DICT.get('email-gateway'))
    readable_output = tableToMarkdown('Stopping email gateway assessment:', raw_response)

    command_results = CommandResults(
        outputs_prefix='Cymulate.EmailGateway',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def get_email_gateway_assessment_status_command(client: Client,
                                                assessment_id: str) -> CommandResults:
    """Retrieve email gateway assessment status.

    Args:
        client (Client): Cymulate client.
        assessment_id (str): The ID of the assessment to retrieve the status to.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the email gateway assessment status.
    """
    outputs = {}
    raw_response = client.get_assessment_status(ENDPOINT_DICT.get('email-gateway'), assessment_id)
    output = copy.deepcopy(raw_response).get('data')
    if output:
        outputs = extract_status_commands_output(output[0])

    readable_output = tableToMarkdown('Email gateway assessment status:', outputs, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.EmailGateway',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def list_endpoint_security_template_command(client: Client) -> CommandResults:
    """Retrieve a list of all endpoint security templates.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all endpoint security templates.
    """
    raw_response = client.list_templates(ENDPOINT_DICT.get('endpoint-security'))
    outputs = extract_template_output(raw_response)

    readable_output = tableToMarkdown('Endpoint security templates list:',
                                      outputs,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.EndpointSecurity.Template',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def start_endpoint_security_assessment_command(client: Client, template_id: str, agent_name: str,
                                               schedule: bool,
                                               schedule_loop: str) -> CommandResults:
    """Start a new endpoint security assessment.

    Args:
        client (Client): Cymulate client.
        template_id (str): The ID of the template to run the assessment with.
        agent_name (str): Agent's name to run simulation attacks with.
        schedule (bool): Whether to schedule the automated assessment periodically.
        schedule_loop (str): Loop size of the scheduled agent.
                             For example: to run the agent only once, use the value 'one-time'.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the start assessment data.
    """

    params = {
        'templateID': template_id,
        'agentName': agent_name,
        'schedule': schedule,
        'scheduleLoop': schedule_loop
    }

    raw_response = client.start_assessment(ENDPOINT_DICT.get('endpoint-security'), params)
    output = {
        'id': raw_response.get('data'),
        'success': raw_response.get('success')
    }

    readable_output = tableToMarkdown('Starting endpoint security assessment:', output)
    command_results = CommandResults(
        outputs_prefix='Cymulate.EndpointSecurity',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def stop_endpoint_security_assessment_command(client: Client) -> CommandResults:
    """Stop a running endpoint security assessment.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the stop assessment data.

    """

    raw_response = client.stop_assessment(ENDPOINT_DICT.get('endpoint-security'))
    readable_output = tableToMarkdown('Stopping endpoint security assessment:', raw_response)

    command_results = CommandResults(
        outputs_prefix='Cymulate.EndpointSecurity',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def get_endpoint_security_assessment_status_command(client: Client,
                                                    assessment_id: str) -> CommandResults:
    """Retrieve endpoint security assessment status.

    Args:
        client (Client): Cymulate client.
        assessment_id (str): The ID of the assessment to retrieve the status to.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the assessment status.

    """
    endpoint = ENDPOINT_DICT.get('endpoint-security')
    raw_response = client.get_assessment_status(endpoint, assessment_id)
    output = extract_status_commands_output(raw_response)

    readable_output = tableToMarkdown('Endpoint security assessment status:', output,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.EndpointSecurity',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def list_waf_template_command(client: Client) -> CommandResults:
    """Retrieve a list of all WAF templates.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all WAF templates.

    """

    raw_response = client.list_templates(ENDPOINT_DICT.get('waf'))
    output = copy.deepcopy(raw_response).get('data')
    for dict in output:
        dict['id'] = dict.pop('_id')
    readable_output = tableToMarkdown('WAF templates list:', output, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.WAF.Template',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def start_waf_assessment_command(client: Client, template_id: str, sites, schedule: bool,
                                 schedule_loop: str) -> CommandResults:
    """Start a new WAF assessment.

    Args:
        client (Client): Cymulate client.
        template_id (str): The ID of the template to run the assessment with.
        sites (list[str] or str): Sites to run the assessment on.
        schedule (bool): Whether to schedule the automated assessment periodically.
        schedule_loop (str): Loop size of the scheduled agent.
                             For example: to run the agent only once, use the value 'one-time'.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the start assessment data.

    """
    sites = argToList(sites)
    params = {
        'templateID': template_id,
        'sites': sites,
        'schedule': schedule,
        'scheduleLoop': schedule_loop
    }

    raw_response = client.start_assessment(ENDPOINT_DICT.get('waf'), params)
    output = {
        'id': raw_response.get('data'),
        'success': raw_response.get('success')
    }

    readable_output = tableToMarkdown('Starting WAF assessment:', output)
    command_results = CommandResults(
        outputs_prefix='Cymulate.WAF',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def stop_waf_assessment_command(client: Client) -> CommandResults:
    """Stop a running WAF assessment.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the stop assessment data.

    """

    raw_response = client.stop_assessment(ENDPOINT_DICT.get('waf'))
    readable_output = tableToMarkdown('Stopping WAF assessment:', raw_response)

    command_results = CommandResults(
        outputs_prefix='Cymulate.WAF',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def get_waf_assessment_status_command(client: Client, assessment_id: str) -> CommandResults:
    """Retrieve WAF assessment status.

    Args:
        client (Client): Cymulate client.
        assessment_id (str): The ID of the assessment to retrieve the status to.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the assessment status.

    """
    endpoint = ENDPOINT_DICT.get('waf')
    raw_response = client.get_assessment_status(endpoint, assessment_id)
    output = extract_status_commands_output(raw_response)

    readable_output = tableToMarkdown('WAF assessment status:', output, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.WAF',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def start_immediate_threat_assessment_command(client: Client, template_id: str,
                                              browsing_address: str = "",
                                              mail_address: str = "",
                                              edr_address: str = "") -> CommandResults:
    """Start a new immediate threats assessment.

    Args:
        client (Client): Cymulate client.
        template_id (str): The ID of the template to run the assessment with.
        browsing_address (str): Browsing address.
        mail_address (str): Agent email address.
        edr_address (str): EDR address.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the start assessment data.

    """
    if browsing_address == "" and mail_address == "" and edr_address == "":
        raise ValueError("At least one of the addresses arguments should be filled.")

    params = {
        'templateID': template_id,
        'mailAddress': browsing_address,
        'browsingAddress': mail_address,
        'edrAddress': edr_address
    }

    raw_response = client.start_assessment(ENDPOINT_DICT.get('immediate-threats'), params)
    output = {
        'id': raw_response.get('data'),
        'success': raw_response.get('success')
    }

    readable_output = tableToMarkdown('Starting immediate-threats assessment:', output)
    command_results = CommandResults(
        outputs_prefix='Cymulate.ImmediateThreats',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def stop_immediate_threat_assessment_command(client: Client) -> CommandResults:
    """Stop the immediate threats assessment.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the stop assessment data.
    """
    raw_response = client.stop_assessment(ENDPOINT_DICT.get('immediate-threats'))

    readable_output = tableToMarkdown('Stop immediate-threats assessment:', raw_response)
    command_results = CommandResults(
        outputs_prefix='Cymulate.ImmediateThreats',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def get_immediate_threat_assessment_status_command(client: Client,
                                                   assessment_id: str) -> CommandResults:
    """Retrieve the immediate threats status.

    Args:
        client (Client): Cymulate client.
        assessment_id (str): The ID of the assessment to retrieve the status to.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the assessment status.
    """
    endpoint = ENDPOINT_DICT.get('immediate-threats')
    raw_response = client.get_assessment_status(endpoint, assessment_id)

    output = extract_status_commands_output(raw_response)
    readable_output = tableToMarkdown('Immediate-threats assessment status:',
                                      output,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.ImmediateThreats',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def list_lateral_movement_template_command(client: Client) -> CommandResults:
    """Retrieve a list of all lateral movement templates.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all lateral movement templates.
    """

    raw_response = client.list_templates(ENDPOINT_DICT.get('lateral-movement'))
    outputs = extract_template_output(raw_response.get('data'))

    readable_output = tableToMarkdown('Lateral movement templates list:', outputs, removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.LateralMovement.Template',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def start_lateral_movement_assessment_command(client: Client, agent_name: str, template_id: str,
                                              upload_to_cymulate: bool, schedule: bool,
                                              schedule_loop: str) -> CommandResults:
    """Start a new lateral movement assessment.

    Args:
        client (Client): Cymulate client.
        agent_name (str): Agent name to run the assessment with.
        template_id (str): The ID of the template to run the lateral movement with.
        upload_to_cymulate (bool): Whether to upload the result to Cymulate.
        schedule (bool): Whether to schedule the automated assessment periodically.
        schedule_loop (str): Loop size of the scheduled agent.
                             For example: to run the agent only once, use the value 'one-time'.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the start assessment data.

    """
    params = {
        "agentName": agent_name,
        "templateID": template_id,
        "uploadResultsToCymulate": upload_to_cymulate,
        "schedule": schedule,
        "scheduleLoop": schedule_loop
    }

    raw_response = client.start_assessment(ENDPOINT_DICT.get('lateral-movement'), params)
    output = {
        'id': raw_response.get('data'),
        'success': raw_response.get('success')
    }

    readable_output = tableToMarkdown('Starting lateral movement assessment:', output)
    command_results = CommandResults(
        outputs_prefix='Cymulate.LateralMovement',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def stop_lateral_movement_assessment_command(client: Client) -> CommandResults:
    """Stop a running lateral movement assessment.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the stop assessment data.

    """

    raw_response = client.stop_assessment(ENDPOINT_DICT.get('lateral-movement'))
    readable_output = tableToMarkdown('Stopping lateral movement assessment:', raw_response)

    command_results = CommandResults(
        outputs_prefix='Cymulate.LateralMovement',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def get_lateral_movement_assessment_status_command(client: Client,
                                                   assessment_id: str) -> CommandResults:
    """Retrieve lateral movement assessment status.

    Args:
        client (Client): Cymulate client.
        assessment_id (str): The ID of the assessment to retrieve the status to.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the assessment status.

    """
    endpoint = ENDPOINT_DICT.get('lateral-movement')
    raw_response = client.get_assessment_status(endpoint, assessment_id)
    output = extract_status_commands_output(raw_response.get('data'))

    readable_output = tableToMarkdown('Lateral movement assessment status:', output,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.LateralMovement',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=output,
        raw_response=raw_response,
    )
    return command_results


def list_phishing_awareness_contact_groups_command(client: Client) -> CommandResults:
    """Retrieve a list of all phishing awareness contact groups.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all contact groups.

    """
    raw_response = client.list_phishing_contacts()
    outputs = extract_template_output(raw_response)

    readable_output = tableToMarkdown('Phishing awareness contact groups:',
                                      outputs,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.Phishing.Groups',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def get_phishing_awareness_contact_groups_command(client: Client, group_id: str) -> CommandResults:
    """Retrieve a list of all phishing awareness contacts list by contact group ID.

    Args:
        client (Client): Cymulate client.
        group_id (str): Group ID.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of contact list by contact group ID.

    """
    raw_response = client.get_phishing_contacts(group_id)
    outputs = extract_template_output(raw_response)

    readable_output = tableToMarkdown('Phishing awareness contact groups:',
                                      outputs,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.Phishing.Groups',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def add_phishing_awareness_contact_groups_command(client: Client,
                                                  group_name: str) -> CommandResults:
    """ Create phishing awareness contact.

    Args:
        client (Client): Cymulate client.
        group_name (str): New group's name.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of contact list by contact group ID.
    """
    raw_response = client.create_phishing_contacts(group_name)
    readable_output = tableToMarkdown('Phishing awareness contact group created:',
                                      raw_response,
                                      removeNull=True)
    command_results = CommandResults(
        outputs_prefix='Cymulate.Phishing.Groups',
        outputs_key_field='id',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def list_agents_command(client: Client) -> CommandResults:
    """Retrieve a list of all agents.

    Args:
        client (Client): Cymulate client.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all agents connected to the current user.

    """
    raw_response = client.get_agents()
    headers = ['agentAddress', 'agentMethod', 'agentName', 'comment']
    readable_output = tableToMarkdown('Agents list:', raw_response, headers=headers,
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.Agent',
        outputs_key_field='',
        readable_output=readable_output,
        outputs=raw_response,
        raw_response=raw_response,
    )
    return command_results


def list_attack_simulations_command(client: Client, module: str, from_date: str,
                                    to_date: str = None) -> CommandResults:
    """ Retrieve a list of all simulations IDs.

    Args:
        client (Client): Cymulate client.
        module (str): Module to retrieve simulations IDs to.
        from_date (str): From which date to fetch data.
        to_date (str): End date to fetch data. If no argument is given, value will be now.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all module simulations from a specific ID.
    """
    outputs = []
    if not validate_timestamp(from_date) or (to_date and not validate_timestamp(to_date)):
        raise ValueError("Wrong date format. Year-Month-Day, for example: March 1st 2021 should be"
                         " written: 2021-03-01.")
    raw_response = client.list_attack_ids_by_date(ENDPOINT_DICT.get(module), from_date, to_date)
    num_simulations_to_display = min(MAX_EVENTS_TO_DISPLAY, len(raw_response))

    if raw_response:
        for simulation_id_data in raw_response:
            data = simulation_id_data
            data['Timestamp'] = str(parse_date_string(simulation_id_data.get('Timestamp')))
            outputs.append(data)

    readable_output = tableToMarkdown(f"Displaying {num_simulations_to_display}/{len(raw_response)}"
                                      f" Attack IDs:",
                                      outputs[:num_simulations_to_display])

    command_results = CommandResults(
        outputs_prefix='Cymulate.Simulations',
        outputs_key_field='ID',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def list_simulations_command(client: Client, module: str, attack_id: str):
    """ Retrieve a list of all simulations by ID.

    Args:
        client (Client): Cymulate client.
        module (str): Module to retrieve simulations to.
        attack_id (str): Attack ID.

    Returns:
        CommandResults: A CommandResults object that is then passed to 'return_results',
                        containing the list of all module simulations from a specific ID.
    """
    outputs = []
    raw_response = client.get_simulations_by_id(ENDPOINT_DICT.get(module), attack_id)

    raw_response = raw_response.get('data')
    num_simulations_to_display = min(MAX_EVENTS_TO_DISPLAY, len(raw_response))

    if raw_response:
        outputs = raw_response
        # Adding the attack ID to the simulation data.
        for simulation in outputs:
            simulation['Id'] = attack_id

    readable_output = tableToMarkdown(f"Displaying {num_simulations_to_display}/{len(raw_response)}"
                                      f" simulations:",
                                      outputs[:num_simulations_to_display],
                                      removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Cymulate.Simulations',
        outputs_key_field='Id',
        readable_output=readable_output,
        outputs=outputs,
        raw_response=raw_response,
    )
    return command_results


def fetch_incidents(client: Client, last_run: Dict[str, int],
                    first_fetch_time: int,
                    fetch_categories: list) -> Tuple[Dict[str, int], List[dict]]:
    """
    Retrieves new incidents every interval (default is 1 minute). The function will retrieve
    incidents from all selected modules chosen in the configuration page by the user.
    the next run will be calculated by the latest timestamp of all modules, to avoid duplications.
    NOTE: We fetch only one module per fetch call.

    Args:
        client (Client): Cymulate client object
        last_run (Optional[Dict[str, int]]): Dictionary with a key containing the latest incident
                                        created time we got from last fetch.
        first_fetch_time (Optional[int]): If last_run is None (first time we are fetching), it
                                        contains the timestamp in milliseconds on when to start
                                        fetching incidents.
        fetch_categories (list): a list of selected modules chosen in the configuration page.

    Returns:
        A tuple containing two elements:
                next_run (``Dict[str, int]``): Contains the timestamp that will be used in
                        ``last_run`` on the next fetch.
                incidents (``List[dict]``): List of incidents that will be created in XSOAR
    """
    last_fetch = last_run.get('last_fetch', None)
    last_fetch = int(last_fetch) if last_fetch else first_fetch_time * 1000
    next_run = last_fetch
    context = get_integration_context()
    current_module = context.get('current_module', None)

    if current_module:
        incidents, offset, creation_time, total_simulated_events \
            = get_alerts_by_module(client, current_module, last_fetch)

    else:
        incidents, offset, creation_time, total_simulated_events = [], 0, last_fetch, 0

    # current_time will help us save current's module time, and update next_run accordingly.
    if creation_time > context.get('current_time', last_fetch):
        current_time = creation_time
    else:
        current_time = context.get('current_time', last_fetch)

    # There are alerts left to fetch
    if total_simulated_events > offset:
        integration_context = {'offset': offset,
                               'current_module': context.get('current_module'),
                               'modules': context.get('modules'),
                               'current_time': current_time}
        demisto.info(f'Fetching {current_module} module. Offset: {offset}/{total_simulated_events}')

    # Finished fetching current module, checking if there are more modules to fetch.
    else:
        modules = context.get('modules', None)
        if modules:
            integration_context = {'offset': 0,
                                   'current_module': modules[0],
                                   'modules': modules[1:],
                                   'current_time': current_time}

        # Finished fetching all modules, re-initializing integration context.
        else:
            integration_context = {'offset': 0,
                                   'current_module': None,
                                   'modules': fetch_categories,
                                   'current_time': current_time}

            # Updating next run time after finish fetching all modules, if needed.
            if current_time >= next_run:
                next_run = current_time + 1000
            else:
                # Increment by 1 second, only if new incidents were fetched.
                if incidents:
                    next_run = next_run + 1000

    set_integration_context(integration_context)
    return {'last_fetch': next_run}, incidents


def main() -> None:
    """main function, parses params and runs command functions"""
    params = demisto.params()

    api_key = params.get('api_key') or (params.get('credentials') or {}).get('password')
    if not api_key:
        raise Exception('API Token must be provided.')
    base_url = params.get('base_url')

    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # How much time before the first fetch to retrieve incidents
    first_fetch_time = arg_to_datetime(
        arg=params.get('first_fetch', '3 days'),
        arg_name='First fetch time',
        required=True)

    first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    assert isinstance(first_fetch_timestamp, int)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            token=api_key,  # type: ignore[arg-type]
            verify=verify_certificate,
            proxy=proxy
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'fetch-incidents':
            fetch_categories = params.get('fetchCategory', None)

            # Handles first fetch
            if get_integration_context() is None:
                set_integration_context({'offset': 0,
                                         'current_module': None,
                                         'modules': fetch_categories,
                                         })

            next_run, incidents = fetch_incidents(client=client,
                                                  last_run=demisto.getLastRun(),
                                                  first_fetch_time=first_fetch_timestamp,
                                                  fetch_categories=fetch_categories)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif command == 'cymulate-simulations-id-list':
            return_results(list_attack_simulations_command(client, **demisto.args()))

        elif command == 'cymulate-simulations-list':
            return_results(list_simulations_command(client, **demisto.args()))

        # exfiltration
        elif command == 'cymulate-exfiltration-template-list':
            return_results(list_exfiltration_template_command(client))

        elif command == 'cymulate-exfiltration-start':
            return_results(start_exfiltration_assessment_command(client, **demisto.args()))

        elif command == 'cymulate-exfiltration-stop':
            return_results(stop_exfiltration_assessment_command(client))

        elif command == 'cymulate-exfiltration-status':
            return_results(get_exfiltration_assessment_status_command(client, **demisto.args()))

        # email-gateway
        elif command == 'cymulate-email-gateway-template-list':
            return_results(list_email_gateway_template_command(client))

        elif command == 'cymulate-email-gateway-start':
            return_results(start_email_gateway_assessment_command(client, **demisto.args()))

        elif command == 'cymulate-email-gateway-stop':
            return_results(stop_email_gateway_assessment_command(client))

        elif command == 'cymulate-email-gateway-status':
            return_results(get_email_gateway_assessment_status_command(client, **demisto.args()))

        # endpoint-security
        elif command == 'cymulate-endpoint-security-template-list':
            return_results(list_endpoint_security_template_command(client))

        elif command == 'cymulate-endpoint-security-start':
            return_results(start_endpoint_security_assessment_command(client, **demisto.args()))

        elif command == 'cymulate-endpoint-security-stop':
            return_results(stop_endpoint_security_assessment_command(client))

        elif command == 'cymulate-endpoint-security-status':
            return_results(get_endpoint_security_assessment_status_command(client,
                                                                           **demisto.args()))

        # waf
        elif command == 'cymulate-waf-template-list':
            return_results(list_waf_template_command(client))

        elif command == 'cymulate-waf-start':
            return_results(start_waf_assessment_command(client, **demisto.args()))

        elif command == 'cymulate-waf-stop':
            return_results(stop_waf_assessment_command(client))

        elif command == 'cymulate-waf-status':
            return_results(get_waf_assessment_status_command(client, **demisto.args()))

        # immediate_threat
        elif command == 'cymulate-immediate-threat-start':
            return_results(start_immediate_threat_assessment_command(client, **demisto.args()))

        elif command == 'cymulate-immediate-threat-stop':
            return_results(stop_immediate_threat_assessment_command(client))

        elif command == 'cymulate-immediate-threat-status':
            return_results(get_immediate_threat_assessment_status_command(client, **demisto.args()))

        # lateral_movement
        elif command == 'cymulate-lateral-movement-template-list':
            return_results(list_lateral_movement_template_command(client))

        elif command == 'cymulate-lateral-movement-start':
            return_results(start_lateral_movement_assessment_command(client, **demisto.args()))

        elif command == 'cymulate-lateral-movement-stop':
            return_results(stop_lateral_movement_assessment_command(client))

        elif command == 'cymulate-lateral-movement-status':
            return_results(get_lateral_movement_assessment_status_command(client, **demisto.args()))

        # phishing_awareness
        elif command == 'cymulate-phishing-awareness-contacts-group-list':
            return_results(list_phishing_awareness_contact_groups_command(client))

        elif command == 'cymulate-phishing-awareness-contacts-get':
            return_results(get_phishing_awareness_contact_groups_command(client, **demisto.args()))

        elif command == 'cymulate-phishing-awareness-contacts-group-create':
            return_results(add_phishing_awareness_contact_groups_command(client, **demisto.args()))

        # General
        elif command == 'cymulate-agent-list':
            return_results(list_agents_command(client))

    except Exception as error:
        demisto.error(traceback.format_exc())

        if 'unauthorized' in str(error):
            return_error(f'Failed to execute {command} command.\nAuthorization Error: make sure API'
                         f' Key is correctly set.\n\nFull error message:\n{error}')

        if 'invalid attack id' in str(error):
            return_error(f'Failed to execute {command} command.\nPlease make sure you '
                         f'entered the correct assessment id.\n\nFull error message:\n{str(error)}')

        return_error(f'Failed to execute {command} command.\n\n'
                     f'Full error message:\n{str(error)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
