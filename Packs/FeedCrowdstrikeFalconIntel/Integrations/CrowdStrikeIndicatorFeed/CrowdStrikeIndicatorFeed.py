import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# IMPORTS
from datetime import datetime
import requests
from typing import List, Tuple, Optional

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client(BaseClient):

    def __init__(self, client_id, client_secret, base_url, verify, proxy):
        self._client_id = client_id
        self._client_secret = client_secret
        self._verify_certificate = verify
        super().__init__(base_url=base_url, verify=self._verify_certificate,
                         ok_codes=tuple(), proxy=proxy)
        self._token = self._get_access_token()
        self._headers = {'Authorization': 'Bearer ' + self._token}

    def http_request(self, method, url_suffix, full_url=None, headers=None, json_data=None, params=None, data=None,
                     files=None, timeout=10, ok_codes=None, return_empty_response=False, auth=None):

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     json_data=json_data, params=params, data=data, files=files, timeout=timeout,
                                     ok_codes=ok_codes, return_empty_response=return_empty_response, auth=auth)

    def _get_access_token(self) -> str:
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request('POST', '/oauth2/token', data=body, auth=(self._client_id, self._client_secret))
        return token_res.get('access_token')


def set_last_modified_time():
    current_time = datetime.now()
    current_timestamp = datetime.timestamp(current_time)
    timestamp = str(int(current_timestamp))
    demisto.setIntegrationContext({'last_modified_time': timestamp})


def get_last_modified_time():
    if integration_context := demisto.getIntegrationContext():
        last_modified_time = int(integration_context['last_modified_time'])
        params = f'last_modified_date%3A%3E{last_modified_time}'
        set_last_modified_time()
    else:
        params = ''
        set_last_modified_time()
    return params


def fetch_indicators(client: Client, feed_tags, tlp_color, include_deleted, type, malicious_confidence, filter, q):
    """ fetch indicators from the Crowdstrike Intel

    Args:
        client: Client object
        feed_tags: The indicator tags.
        tlp_color (str): Traffic Light Protocol color.
        include_deleted (bool): include deleted indicators. (send just as parameter)
        type (str): type indicator.
        malicious_confidence: medium, low, high
        filter (str): indicators filter.
        q (str): generic phrase match

    Returns:
        list of indicators(list)
    """
    raise Exception('TODO')


def crowdstrike_indicators_list_command(client: Client, args: dict):
    """ Gets indicator from Crowdstrike Intel to readable output

    Args:
        client: Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    include_deleted = args.get('include_deleted')
    type = args.get('type')
    malicious_confidence = args.get('malicious_confidence')
    filter = args.get('filter')
    q = args.get('generic_phrase_match')
    offset = int(args.get('offset', 0))
    limit = int(args.get('limit', 50))


def test_module(client: Client, args: dict):
    try:
        # TODO
        args.get('TODO')
    except Exception:
        raise Exception("Could not fetch CrowdStrike Indicator Feed\n"
                        "\nCheck your API key and your connection to CrowdStrike.")
    return 'ok', {}, {}


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    client_id = params.get('client_id')
    client_secret = params.get('client_secret')
    proxy = params.get('proxy', False)
    verify_certificate = not demisto.params().get('insecure', False)
    feed_tags = argToList(params.get('feedTags'))
    base_url = "https://api.crowdstrike.com/"
    tlp_color = params.get('tlp_color')
    include_deleted = params.get('include_deleted')
    type = params.get('type')
    malicious_confidence = params.get('malicious_confidence')
    filter = params.get('filter')
    q = params.get('q')
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client, args)
            return_results(result)

        elif command == 'fetch-indicators':
            indicators = fetch_indicators(client, feed_tags, tlp_color, include_deleted, type, malicious_confidence,
                                          filter, q)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == 'crowdstrike-indicators-list':
            crowdstrike_indicators_list_command(client, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
