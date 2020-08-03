import urllib3
import datetime
from requests.auth import HTTPBasicAuth

from CommonServerPython import *

# disable insecure warnings
urllib3.disable_warnings()

INTEGRATION_NAME = 'FireEye'
API_URL = 'https://api.intelligence.fireeye.com'


class Client(BaseClient):
    """Client to use in the FireEye Feed integration. Overrides BaseClient.

    Args:
        insecure (bool): False if feed HTTPS server certificate should be verified, True otherwise.
        proxy (bool): False if feed HTTPS server certificate will not use proxies, True otherwise.
    """

    def __init__(self, public_key: str, private_key: str,
                 polling_timeout: int = 20, insecure: bool = False, proxy: bool = False):
        super().__init__(base_url=API_URL, verify=not insecure, proxy=proxy)
        self.public_key = public_key
        self.private_key = private_key
        self._polling_timeout = polling_timeout

    @staticmethod
    def parse_access_token_expiration_time(expires_in: str) -> int:
        try:
            current_time = datetime.datetime.now()
            expiration_time = current_time + datetime.timedelta(seconds=int(expires_in))
            epoch_expiration_time = int(expiration_time.strftime('%s'))
        except ValueError:
            demisto.info('INFO - could not parse expiration time for access token.')
            epoch_expiration_time = 0

        return epoch_expiration_time

    def fetch_new_access_token(self):
        response = self._http_request(
            method='post',
            url_suffix='token',
            data={'grant_type': 'client_credentials'},
            auth=HTTPBasicAuth(self.public_key, self.private_key),
            timeout=self._polling_timeout
        )

        auth_token = response.get('access_token')
        expires_in = response.get('expires_in')
        epoch_expiration_time = self.parse_access_token_expiration_time(expires_in)

        demisto.setIntegrationContext(
            {
                'auth_token': auth_token,
                'expiration_time': epoch_expiration_time
            }
        )

        return auth_token

    def get_access_token(self):
        last_token_fetched_expiration_time = demisto.getIntegrationContext().get('expiration_time')
        current_time = int(datetime.datetime.now().strftime('%s'))

        if last_token_fetched_expiration_time and last_token_fetched_expiration_time > current_time:
            auth_token = demisto.getIntegrationContext().get('auth_token')
        else:
            auth_token = self.fetch_new_access_token()

        return auth_token


def test_module(client: Client):
    client.get_access_token()
    auth_token = demisto.getIntegrationContext().get('auth_token')
    expiration_time = demisto.getIntegrationContext().get('expiration_time')
    return f'{auth_token} - {expiration_time}', {}, {}


def get_indicators_command(client: Client, feedTags: list):
    """Retrieves indicators from the feed to the war-room.

    Args:
        client (Client): Client object configured according to instance arguments.
        feedTags: The indicator tags.

    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. The raw data of the indicators.
    """
    limit = int(demisto.args().get('limit')) if 'limit' in demisto.args() else 10
    indicators, raw_response = fetch_indicators_command(client, feedTags, limit)

    human_readable = tableToMarkdown('Indicators from FireEye Feed:', indicators,
                                     headers=['value', 'type'], removeNull=True)

    return human_readable, {}, {'raw_response': raw_response}


def fetch_indicators_command(client: Client, feedTags: list, limit: int = -1):
    """Fetches indicators from the feed to the indicators tab.
    Args:
        client (Client): Client object configured according to instance arguments.
        limit (int): Maximum number of indicators to return.
        feedTags (list): Indicator tags
    Returns:
        Tuple of:
            str. Information to be printed to war room.
            Dict. Data to be entered to context.
            Dict. The raw data of the indicators.
    """
    iterator = client.build_iterator()
    indicators = []
    raw_response = []

    if limit != -1:
        iterator = iterator[:limit]

    for indicator in iterator:
        indicators.append({
            'value': indicator['value'],
            'type': indicator['type'],
            'rawJSON': indicator
        })

        raw_response.append(indicator)

    return indicators, raw_response


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """

    public_key = demisto.params().get('credentials').get('identifier')
    private_key = demisto.params().get('credentials').get('password')

    feedTags = argToList(demisto.params().get('feedTags'))

    polling_arg = demisto.params().get('polling_timeout', '')
    polling_timeout = int(polling_arg) if polling_arg.isdigit() else 20
    insecure = demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    command = demisto.command()
    try:
        client = Client(public_key, private_key, polling_timeout, insecure, proxy)
        if command == 'test-module':
            return_outputs(*test_module(client))
        elif command == 'fireeye-get-indicators':
            if feedTags:
                feedTags['tags'] = feedTags
            return_outputs(*get_indicators_command(client, feedTags))
        elif command == 'fetch-indicators':
            indicators, _ = fetch_indicators_command(client, feedTags)

            for single_batch in batch(indicators, batch_size=2000):
                demisto.createIndicators(single_batch)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception:
        raise


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
