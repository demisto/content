import pathlib

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

import requests
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class FileLoader():
    def __init__(self, source_path):
        self.source_path = source_path

    def get_file(self, file_path):
        file_path = urljoin(self.source_path, file_path)
        return requests.get(file_path, verify=False)


class GitFileLoader(FileLoader):
    def __init__(self):
        git_master_packs_path = 'https://github.com/demisto/content/blob/master'
        super().__init__(git_master_packs_path)

    def get_json_file(self, file_path):
        res = super().get_file(file_path)
        if res.status_code != 200:
            raise ValueError(f'File could not be retrieved.')

        return res.json()


# def test_module(client: Client) -> str:
#
#     message: str = ''
#     try:
#         # TODO: ADD HERE some code to test connectivity and authentication to your service.
#         # This  should validate all the inputs given in the integration configuration panel,
#         # either manually or by using an API that uses them.
#         message = 'ok'
#     except DemistoException as e:
#         if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
#             message = 'Authorization Error: make sure API Key is correctly set'
#         else:
#             raise e
#     return message


def get_loader(file_path: str, source: str = 'Git'):
    if source == 'Git':
        return GitFileLoader(file_path)

    else:
        'Unauthorized source'


def fetch_incidents_command():
    data = get_integration_context()
    incidents = data.pop('incidents') if 'incidents' in data else []
    return incidents


def create_test_incident_command(args: Dict[str, Any]) -> CommandResults:
    incidents_path = args.get('incidents_path')
    attachment_path = args.get('attachment_path')
    if not incidents_path:
        raise ValueError('Incidents were not specified')

    loader = get_loader(incidents_path)
    incidents = loader.get_json_file(incidents_path)
    if not isinstance(incidents, list):
        incidents = [incidents]
    attachment = None
    if attachment_path:
        attachment = loader.get_json_file(attachment_path).content

    ready_incidents = parse_incidents(attachment, incidents)

    set_integration_context({'incidents': ready_incidents})

    return CommandResults(readable_output=f'Loaded {len(ready_incidents)} incidents from file.')


def parse_incidents(incidents: List[dict], attachment: Optional, attachment_name: Optional[str]):
    ready_incidents = []
    file_result = None
    if attachment:
        file_result = fileResult(attachment_name, attachment)

    for incident in incidents:
        parsed_incident = {
            'name': incident['name'],
            'occurred': timestamp_to_datestring(incident['created']),
            'rawJSON': json.dumps(incident),
            'labels': incident.get('labels'),
        }
        if file_result:
            parsed_incident['attachment'].append({
                'path': file_result['FileID'],
                'name': attachment_name
            })
        ready_incidents.append(parsed_incident)
    return ready_incidents


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # verify_certificate = not demisto.params().get('insecure', False)
    # proxy = demisto.params().get('proxy', False)
    try:

        command = demisto.command()
        demisto.debug(f'Command being called is {command}')

        if command == 'fetch-incidents':
            incidents = fetch_incidents_command()
            demisto.incidents(incidents)

        # elif command == 'test-module':
            # result = test_module()
            # return_results(result)

        elif command == 'create-test-incident':
            return_results(create_test_incident_command(demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
