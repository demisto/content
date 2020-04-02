
import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
import json
import requests
import dateparser
from google.cloud import pubsub_v1


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
RFC3339_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'
DEMISTO_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S'

''' HELPER FUNCTIONS '''


class PubSubClient:
    """Manages pub/sub command requests"""
    def __init__(self, service_account_json, insecure):
        self._sub_client = None
        self._pub_client = None
        self._credentials_file_path = self.create_credentials_file(service_account_json)

        self.init_requests(insecure)

    def get_sub_client(self) -> pubsub_v1.SubscriberClient:
        if self._sub_client is None:
            self._init_sub_client()
        return self._sub_client

    def get_pub_client(self) -> pubsub_v1.PublisherClient:
        if self._pub_client is None:
            self._init_pub_client()
        return self._pub_client

    def _init_pub_client(self):
        """Creates the Python API PublisherClient for Google Cloud Pub"""
        self._pub_client = pubsub_v1.PublisherClient.from_service_account_json(self._credentials_file_path)

    def _init_sub_client(self):
        """Creates the Python API SubscriberClient for Google Cloud Sub"""
        self._sub_client = pubsub_v1.SubscriberClient.from_service_account_json(self._credentials_file_path)

    @staticmethod
    def create_credentials_file(service_account_json):
        """
        Creates the credentials file the Google Cloud API clients expect
        :param service_account_json: Json string of the service_account
        :return: File path
        """
        cur_directory_path = os.getcwd()
        credentials_file_name = demisto.uniqueFile() + '.json'
        credentials_file_path = os.path.join(cur_directory_path, credentials_file_name)
        with open(credentials_file_path, 'w') as creds_file:
            json_object = json.loads(service_account_json)
            json.dump(json_object, creds_file)
        return credentials_file_path

    @staticmethod
    def init_requests(disable_tls_verification):
        """Overrides merge_environment_settings of requests. This accomplishes:
           1. Handling requests proxies
           2. Enabling `insecure` requests
        """
        original_method = requests.Session.merge_environment_settings
        _proxies = handle_proxy()

        def merge_environment_settings(self, url, proxies, stream, verify, cert):
            settings = original_method(self, url, _proxies, stream, verify, cert)
            if disable_tls_verification:
                settings['verify'] = False
            return settings

        # noinspection PyTypeHints
        requests.Session.merge_environment_settings = merge_environment_settings  # type: ignore


def test_module(client: PubSubClient):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    :param client: PubSubClient
    :return: 'ok' if test passed, anything else will fail the test.
    """
    client.get_sub_client()
    client.get_pub_client()
    return 'ok'


def say_hello_command(client, args):
    """
    Returns Hello {somename}

    Args:
        client (Client): HelloWorld client.
        args (dict): all command arguments.

    Returns:
        Hello {someone}

        readable_output (str): This will be presented in the war room - should be in markdown syntax - human readable
        outputs (dict): Dictionary/JSON - saved in the incident context in order to be used as inputs
                        for other tasks in the playbook
        raw_response (dict): Used for debugging/troubleshooting purposes -
                            will be shown only if the command executed with raw-response=true
    """
    name = args.get('name')

    result = client.say_hello(name)

    # readable output will be in markdown format - https://www.markdownguide.org/basic-syntax/
    readable_output = f'## {result}'
    outputs = {
        'hello': result
    }

    return (
        readable_output,
        outputs,
        result  # raw response - the original response
    )


def fetch_incidents(client, last_run, first_fetch_time):
    """
    This function will execute each interval (default is 1 minute).

    Args:
        client (Client): HelloWorld client
        last_run (dateparser.time): The greatest incident created_time we fetched from last fetch
        first_fetch_time (dateparser.time): If last_run is None then fetch all incidents since first_fetch_time

    Returns:
        next_run: This will be last_run in the next fetch-incidents
        incidents: Incidents that will be created in Demisto
    """
    # Get the last fetch time, if exists
    last_fetch = last_run.get('last_fetch')

    # Handle first time fetch
    if last_fetch is None:
        last_fetch, _ = dateparser.parse(first_fetch_time)
    else:
        last_fetch = dateparser.parse(last_fetch)

    latest_created_time = last_fetch
    incidents = []
    items = client.list_incidents()
    for item in items:
        incident_created_time = dateparser.parse(item['created_time'])
        incident = {
            'name': item['description'],
            'occurred': incident_created_time.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'rawJSON': json.dumps(item)
        }

        incidents.append(incident)

        # Update last run and add incident if the incident is newer than last fetch
        if incident_created_time > latest_created_time:
            latest_created_time = incident_created_time

    next_run = {'last_fetch': latest_created_time.strftime(DEMISTO_DATETIME_FORMAT)}
    return next_run, incidents


def main():
    params = demisto.params()
    insecure = not params.get('insecure')
    service_account_json = params.get('service_account_json')
    client = PubSubClient(service_account_json, insecure)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        if demisto.command() == 'test-module':
            demisto.results(test_module(client))

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            first_fetch_time = params.get('fetch_time', '3 days').strip()
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch_time=first_fetch_time)

            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'helloworld-say-hello':
            return_outputs(*say_hello_command(client, demisto.args()))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
