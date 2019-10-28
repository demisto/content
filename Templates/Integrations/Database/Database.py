from typing import Tuple, Dict, Union

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import json

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
INTEGRATION_NAME = 'Database Integration'
# lowercase with `-` dividers
INTEGRATION_COMMAND_NAME = 'database'
# No dividers
INTEGRATION_CONTEXT_NAME = 'Database'


class Client(BaseClient):
    def query(self, query_string: str) -> Union[Dict, list]:
        """Send query as is to server. note it's unsecured (can drop tables etc.).

        Args:
            query_string: query to send

        Returns:
             List of lines from DB
        """
        params = {'query': query_string}
        return self._http_request('POST', url_suffix='', params=params)


def fetch_incident_command(client: Client, args: dict):
    pass


def query_command(client: Client, args: dict) -> Tuple[str, dict, list]:
    query = args.get('query')
    raw_response = client.query(query)
    context = list()
    if raw_response:
        for row in raw_response:
            context.append({
                "ID": row[0],
                "Timestamp": row[1],
                "Name": row[2],
                "Urgency": row[3]
            })
        readable_output = tableToMarkdown(
            f"Results from {INTEGRATION_NAME}",
            context,
        )
        context = {"Database(var.ID === obj.ID": context}
        return readable_output, context, raw_response
    return f"{INTEGRATION_NAME} - found no results for query", {}, raw_response


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    host = params.get('host')
    # Remove trailing slash to prevent wrong URL path to service
    port = params.get('port')
    server = urljoin(params.get('url') + port, '/api/v2.0/')

    # Should we use SSL
    use_ssl = not params.get('insecure') == 'true'
    use_proxy = params.get('proxy') == 'true'
    # How many time before the first fetch to retrieve incidents
    fetch_time = params.get('fetch_time', '3 days')
    # Service base URL
    # Headers to be sent in requests
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Host': host

    }
    client = Client(server, use_ssl, use_proxy, headers=headers, auth=(username, password))
    # Commands switch case
    command = demisto.command()
    commands = {
        f'{INTEGRATION_COMMAND_NAME}-query': query_command
    }
    if command == 'fetch-incidents':
        fetch_incident_command(client, )
    elif command in commands:
        return_outputs(*commands[command](client, demisto.args()))


''' HELPER FUNCTIONS '''


def item_to_incident(item):
    incident = {}
    # Incident Title
    incident['name'] = 'Example Incident: ' + item.get('name')
    # Incident occurrence time, usually item creation date in service
    incident['occurred'] = item.get('createdDate')
    # The raw response from the service, providing full info regarding the item
    incident['rawJSON'] = json.dumps(item)
    return incident


''' COMMANDS + REQUESTS FUNCTIONS '''
