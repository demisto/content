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


def fetch_indicators(client: Client, feed_tags, tlp_color, include_deleted, _type, malicious_confidence, _filter, q):
    raise Exception('TODO')


def crowdstrike_indicators_list_command(client: Client, args: dict):
    include_deleted = args.get('include_deleted')
    _type = args.get('type')
    malicious_confidence = args.get('malicious_confidence')
    _filter = args.get('filter')
    q = args.get('generic_phrase_match')


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
    _type = params.get('type')
    malicious_confidence = params.get('malicious_confidence')
    _filter = params.get('filter')
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
            indicators = fetch_indicators(client, feed_tags, tlp_color, include_deleted, _type, malicious_confidence,
                                          _filter, q)
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
