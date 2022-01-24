import pathlib
from collections import namedtuple

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

Attachment = namedtuple('Attachment', ['name', 'content'])


class Client(BaseClient):
    def __init__(self, base_url: str, use_ssl: bool, use_proxy: bool):
        self.base_url = base_url
        self.verify = use_ssl
        self.proxy = use_proxy
        headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}
        super().__init__(base_url, headers=headers, verify=self.verify, proxy=self.proxy)

    def http_request(self, file_path: str, response_type: str = 'json') -> Union[dict, str, list]:
        try:
            data = self._http_request(
                method='GET',
                url_suffix=file_path,
                resp_type=response_type,
                return_empty_response=True,
            )
            return data
        except Exception as e:
            if '404' in str(e):
                raise DemistoException('The requested file could not be found.')
            else:
                raise e


def test_module(client) -> str:  # pragma: no cover
    """ Getting README file just to see we manage to get a basic file. """
    message: str = ''
    try:
        client.http_request('README.md', 'content')
        message = 'ok'

    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def fetch_incidents_command(client):
    """
    The fetch runs on instance's context, gets the formatted incidents, and add attachments if needed.
    It then clears the context so incident would not be duplicated.
    """
    data = get_integration_context()
    incidents = data.pop('incidents') if 'incidents' in data else []

    for incident in incidents:
        if 'attachment' in incident:
            demisto.debug('Found incident, getting attachments')
            _add_attachments(client, incident)

    # clear the integration contex from already seen incidents
    set_integration_context({'incidents': []})
    return incidents


def _add_attachments(client, incident: dict):
    """
     This function takes a formatted incident and add an attachments in case it has one.
    """
    attachment_paths = incident['attachment']
    incident['attachment'] = []
    for attachment_path in attachment_paths:
        attachment = Attachment(content=client.http_request(file_path=attachment_path, response_type='content'),
                                name=pathlib.Path(attachment_path).name)
        file_result = fileResult(attachment.name, attachment.content)

        incident['attachment'].append({
            'path': file_result['FileID'],
            'name': attachment.name
        })


def create_test_incident_from_file_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    This function will get the incidents and save the formatted incidents to instance context, for the fetch.
    """
    incidents_path = args.get('incidents_path')
    attachment_path = argToList(args.get('attachment_paths'))
    if not incidents_path:
        raise ValueError('Incidents were not specified')

    ready_incidents = get_incidents_from_file(attachment_path=attachment_path, incidents_path=incidents_path,
                                              client=client)
    set_integration_context({'incidents': ready_incidents})
    return CommandResults(readable_output=f'Loaded {len(ready_incidents)} incidents from file.')


def get_incidents_from_file(client: Client, incidents_path: str, attachment_path: List[str] = None):
    """
    This function retrieves the incidents from the file provided using the relevant client,
    handling the case of a single incident, it returns formatted incidents.
    """
    incidents = client.http_request(file_path=incidents_path, response_type='json')

    if not isinstance(incidents, list):
        incidents = [incidents]  # type: ignore

    ready_incidents = parse_incidents(incidents, attachment_path)
    return ready_incidents


def parse_incidents(incidents: List[dict], attachment_path: List[str] = None) -> List[dict]:
    """
    This function will take a list of incidents and make them in the format of XSoar format,
     as a preparation for the fetch command.
     Since fileResult only exists in the scope of the command, we only save the path to the file.
     The actual file is added at the fetch command.
    """
    ready_incidents = []

    for incident in incidents:
        parsed_incident = {
            'name': incident['name'],
            'occurred': incident['created'],
            'rawJSON': json.dumps(incident)
        }
        if incident.get('labels'):
            parsed_incident['labels'] = incident.get('labels')

        if attachment_path:
            parsed_incident['attachment'] = attachment_path

        ready_incidents.append(parsed_incident)
    return ready_incidents


''' MAIN FUNCTION '''


def main() -> None:  # pragma: no cover
    try:
        params = demisto.params()
        command = demisto.command()

        demisto.debug(f'Command being called is {command}')
        client = Client(
            base_url=params.get('url'),
            use_ssl=not params.get('insecure', True),
            use_proxy=params.get('proxy', False)
        )
        if command == 'fetch-incidents':
            incidents = fetch_incidents_command(client)
            demisto.incidents(incidents)

        elif command == 'test-module':
            result = test_module(client)
            return_results(result)

        elif command == 'create-test-incident-from-file':
            return_results(create_test_incident_from_file_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}, {traceback.format_exc()}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
