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
        self._base_url = base_url
        super().__init__(base_url=base_url, verify=self._verify_certificate,
                         ok_codes=tuple(), proxy=proxy)
        self._token = self._get_access_token()
        self._headers = {'Authorization': 'Bearer ' + self._token}

    def http_request(self, method, url_suffix=None, full_url=None, headers=None, params=None, data=None,
                     timeout=10, auth=None):

        return super()._http_request(method=method, url_suffix=url_suffix, full_url=full_url, headers=headers,
                                     params=params, data=data, timeout=timeout, auth=auth)

    def _get_access_token(self) -> str:
        body = {
            'client_id': self._client_id,
            'client_secret': self._client_secret
        }
        token_res = self.http_request(method='POST', url_suffix='/oauth2/token', data=body,
                                      auth=(self._client_id, self._client_secret))
        return token_res.get('access_token')

    def get_indicators(self, type, malicious_confidence, filter, q, limit=100, offset=0, include_deleted=False,
                       get_indicators_command=False):

        if not get_indicators_command:
            last_run = get_last_run()
            filter += last_run
            set_last_run()

        params = {
            'include_deleted': include_deleted,
            'limit': limit,
            'offset': offset,
            'q': q,
            'filter': filter
        }

        response = self.http_request(method='GET', params=params, headers=self._headers, full_url=self._base_url)


def set_last_run():
    current_time = datetime.now()
    current_timestamp = datetime.timestamp(current_time)
    timestamp = str(int(current_timestamp))
    demisto.setLastRun({'last_modified_time': timestamp})


def get_last_run():
    if last_run := demisto.getLastRun():
        params = f'last_updated%3A%3E{last_run["last_modified_time"]}'
        set_last_run()
    else:
        params = ''
        set_last_run()
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

    indicators_list = client.get_indicators(include_deleted=include_deleted, type=type,
                                            malicious_confidence=malicious_confidence, filter=filter,
                                            q=q, limit=limit, offset=offset, get_indicators_command=True)

    return CommandResults(
        outputs=indicators_list,
        outputs_prefix='CrowdStrikeFalconIntel.Indicators',
        outputs_key_field='id',
        readable_output='indicators_list',
        raw_response=indicators_list
    )


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
            return_results(crowdstrike_indicators_list_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
