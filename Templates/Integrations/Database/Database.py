import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import json
import requests
from distutils.util import strtobool

# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def query(self, query_string: str) -> list:
        """Send query as is to server. note it's unsecured (can drop tables etc.).

        Args:
            query_string: query to send

        Returns:
             List of lines from DB
        """
        params = {'query': query_string}
        return self._http_request('POST', url_suffix='', params=params).json()


def fetch_incident_command(client: Client, args: dict):
    pass

def query_command(client: Client, args: dict):
    pass


def main():
    params = demisto.params()
    username = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    host = params.get('host')
    # Remove trailing slash to prevent wrong URL path to service
    port = params.get('port')
    server = urljoin(params.get('url')+port, '/api/v2.0/')

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
        'query': query_command,
        'fetch-incidents': fetch_incident_command,
    }
    if command == 'fetch-incidents':



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
