import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
from typing import Dict, Tuple, List, Optional, Union, AnyStr
import urllib3

"""Example for Analytics and SIEM integration
"""
# Disable insecure warnings
urllib3.disable_warnings()

"""GLOBALS/PARAMS
Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""
INTEGRATION_NAME = 'Data Enrichment & Threat Intelligence'
INTEGRATION_COMMAND_NAME = 'phishlabs'
INTEGRATION_CONTEXT_NAME = ' DataEnrichmentAndThreatIntelligence'


class Client(BaseClient):
    def test_module(self) -> Dict:
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            Response json
        """
        return self._http_request('GET', 'version')

    def query(self, phish_type: str = 'incident' ,**kwargs) -> Dict:
        """Query the specified kwargs.

        Args:
            phish_type: Phishlabs type for suffix
            **kwargs: The keyword argument for which to search.

        Returns:
            Response JSON
        """
        # The service endpoint to request from
        if phish_type == 'incident':
            suffix = f'/idapi/v1/incidents/EIR/{kwargs.get("id")}'

        # Send a request using our http_request wrapper
        return self._http_request('GET', suffix, params=kwargs)


''' HELPER FUNCTIONS '''


def raw_response_to_context(events: Union[Dict, List]) -> Union[Dict, List]:
    """Formats the API response to Demisto context.

    Args:
        events: The raw response from the API call. Can be a List or Dict.

    Returns:
        The formatted Dict or List.

    Examples:
        >>> raw_response_to_context({'eventId': '1', 'description': 'event description', 'createdAt':\
        '2019-09-09T08:30:07.959533', 'isActive': True, 'assignee': [{'name': 'user1', 'id': '142'}]})
        {'ID': '1', 'Description': 'event description', 'Created': '2019-09-09T08:30:07.959533', 'IsActive': True,\
 'Assignee': [{'Name': 'user1', 'ID': '142'}]}
    """
    if isinstance(events, list):
        return [raw_response_to_context(event) for event in events]
    return {
        'ID': events.get('eventId'),
        'Description': events.get('description'),
        'Created': events.get('createdAt'),
        'IsActive': events.get('isActive'),
        'Assignee': [
            {
                'Name': user.get('name'),
                'ID': user.get('id')
            } for user in events.get('assignee', [])
        ]}


''' COMMANDS '''


@logger
def test_module_command(client: Client, *_) -> Tuple[str, None, None]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'version' in results:
        return 'ok', None, None
    raise DemistoException(f'Test module failed, {results}')


@logger
def fetch_incidents_command(
        client: Client,
        fetch_time: str,
        last_run: Optional[str] = None) -> Tuple[List, str]:
    """Uses to fetch incidents into Demisto
    Documentation: https://github.com/demisto/content/tree/master/docs/fetching_incidents

    Args:
        client: Client object with request
        fetch_time: From when to fetch if first time, e.g. `3 days`
        last_run: Last fetch object occurs.

    Returns:
        incidents, new last_run

    Examples:
        >>> fetch_incidents_command(client, '3 days', '2010-02-01T00:00:00')
    """
    occurred_format = '%Y-%m-%dT%H:%M:%SZ'
    # Get incidents from API
    if not last_run:  # if first time running
        datetime_new_last_run, _ = parse_date_range(fetch_time, date_format=occurred_format)
    else:
        datetime_new_last_run = parse_date_string(last_run)
    new_last_run = datetime_new_last_run.strftime(occurred_format)
    incidents: List = list()
    raw_response = client.list_events(event_created_date_after=datetime_new_last_run)
    events = raw_response.get('event')
    if events:
        for event in events:
            # Creates incident entry
            occurred = event.get('createdAt')
            datetime_occurred = parse_date_string(occurred)
            incidents.append({
                'name': f"{INTEGRATION_NAME}: {event.get('eventId')}",
                'occurred': occurred,
                'rawJSON': json.dumps(event)
            })
            if datetime_occurred > datetime_new_last_run:
                new_last_run = datetime_occurred.strftime(occurred_format)
    # Return results
    return incidents, new_last_run


@logger
def get_incident_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    """ Get incidents by ID

    Args:
        client: Client object with request
        args: demisto.args()

    Returns:
        Outputs
    """
    # Get arguments from user
    query_dict = assign_params(**args)
    # Make request and get raw response
    raw_response = client.query(phish_type='incident',
                                **query_dict)
    # Parse response into context & content entries
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for {INTEGRATION_COMMAND_NAME}-get-incident-by-id query'
        context_entry: dict = {
            "URL": [],
            "File": [],
            "Email": {
                "To": raw_response.get("incidents", {}).get("details", {}).get("emailReportedBy"),
                "From": raw_response.get("incidents", {}).get("details", {}).get("sender"),
                "Body/HTML": raw_response.get("incidents", {}).get("details", {}).get("emailBody"),
                "Subject": raw_response.get("incidents", {}).get("details", {}).get("title"),
                "Attachments": [
                    "entryID"
                ]
            },
            "PhishLabsIOC_v2": {
            }

        }
        context: dict = {

        }
        human_readable = tableToMarkdown(t={},
                                         name=title)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def get_incidents_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    query_dict = assign_params(**args)
    raw_response = client.query(section=query_dict.get('ip_version'),
                                argument=query_dict.get('ip_address'))
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for {query_dict.get("ip_version")} query'
        context_entry: dict = {
            'IP': {
                'Address': raw_response.get('indicator'),
                'ASN': raw_response.get('asn'),
                'Geo': {
                    'Country': raw_response.get('country_code'),
                    'Location': f'{raw_response.get("latitude")},{raw_response.get("longitude")}'
                }
            }
        }
        context: dict = {
            f'IP(val.IP.Address === obj.IP.Address)': context_entry.get('IP'),
            'AlienVaultOTX': {
                'IP': {
                    'Reputation': raw_response.get('reputation'),
                    'IP': query_dict.get('ip_address')
                }
            },
            'DBotScore': {
                'Indicator': raw_response.get('indicator'),
                'Score': calculate_dbot_score(raw_response.get('pulse_info', {})),
                'Type': query_dict.get('ip_version'),
                'Vendor': 'AlienVault OTX v2'
            }
        }

        human_readable = tableToMarkdown(t={**context.get('IP', {}),
                                            'Reputation': context.get('AlienVaultOTX', {}).get('IP', {}).get(
                                                'Reputation')},
                                         name=title)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def get_case_by_id_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    query_dict = assign_params(**args)
    # Make request and get raw response
    raw_response = client.query(phish_type='incident',
                                **query_dict)
    # Parse response into context & content entries
    if raw_response:
        title = f'{INTEGRATION_NAME} - Results for {INTEGRATION_COMMAND_NAME}-get-incident-by-id query'
        context_entry: dict = {

        }
        context: dict = {

        }
        human_readable = tableToMarkdown(t={},
                                         name=title)
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def get_cases_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    pass


def get_cases_attachment_command(client: Client, args: Dict) -> Tuple[str, Dict, Dict]:
    pass


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():  # pragma: no cover
    params = demisto.params()
    base_url = params.get('url')
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(base_url=base_url,
                    verify=verify_ssl,
                    proxy=proxy,
                    auth=(params.get('user'), params.get('password')))
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    # Switch case
    commands = {
        'test-module': test_module_command,
        'fetch-incidents': fetch_incidents_command,
        f'{INTEGRATION_COMMAND_NAME}-get-incident-by-id': get_incident_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-get-incidents': get_incidents_command,
        f'{INTEGRATION_COMMAND_NAME}-get-case-by-id': get_case_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cases': get_cases_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cases-attachment': get_cases_attachment_command,
        # TODO implement create case command
    }
    try:
        if command == 'fetch-incidents':
            incidents, new_last_run = fetch_incidents_command(client, last_run=demisto.getLastRun())
            demisto.incidents(incidents)
            demisto.setLastRun(new_last_run)
        elif command in commands:
            readable_output, outputs, raw_response = commands[command](client, demisto.args())
            return_outputs(readable_output, outputs, raw_response)
    # Log exceptions
    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':  # pragma: no cover
    main()
main()