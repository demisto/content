from typing import Any, Dict, List, Optional, Tuple, Union, cast

import demistomock as demisto  # noqa: E402 lgtm [py/polluting-import]
import urllib3
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from pycti import OpenCTIApiClient
# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
import logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

XSOHR_TYPES = {
    'user-account': "Account",
    'domain': "Domain",
    'email-address': "Email",
    'file-md5': "File MD5",
    'file-sha1': "File SHA-1",
    'file-sha256': "File SHA-256",
    'hostname': "Host",
    'ipv4-addr': "IP",
    'ipv6-addr': "IPv6",
    'registry-key-value': "Registry Key",
    'url': "URL"
}


def get_indicators(client, indicator_type: [str], limit: int, last_run_id: Optional[bool] = None)\
        -> Tuple[str, list]:
    """ Retrieving indicators from the API

    Args:
        client: OpenCTI Client object.
        indicator_type: List of indicators types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max indicators to fetch

    Returns:
        new_last_run: the id of the last indicator
        indicators: list of indicators
    """
    if 'all' in indicator_type:
        indicator_type = ['user-account', 'domain', 'email-address', 'file-md5', 'file-sha1', 'file-sha256', 'hostname',
                          'ipv4-addr', 'ipv6-addr', 'registry-key-value', 'url']

    observables = client.stix_observable.list(types=indicator_type, first=limit, after=last_run_id, withPagination=True)
    new_last_run = observables.get('pagination').get('endCursor')
    indicators = [
        {
            "value": item['observable_value'],
            "type": XSOHR_TYPES.get(item['entity_type']),
            "rawJSON": item,
            "fields": {
                "tags": [tag.get('value') for tag in item.get('tags')],
                "description": item.get('description')
            }
        }for item in observables.get('entities')
    ]
    return new_last_run, indicators


def fetch_indicators_command(client, indicator_type: list, max_fetch: int) -> list:
    """ fetch indicators from the OpenCTI

    Args:
        client: OpenCTI Client object
        indicator_type(list): List of indicators types to get.
        max_fetch: (int) max indicators to fetch

    Returns:
        list of indicators(list)
    """
    last_run_id = demisto.getIntegrationContext().get('last_run_id')

    new_last_run, indicators_list = get_indicators(client, indicator_type, max_fetch, last_run_id)

    if new_last_run:
        demisto.setIntegrationContext({'last_run_id': new_last_run})

    return indicators_list


def get_indicators_command(client, args: dict) -> CommandResults:
    """ Gets indicator from opencti to readable output

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    indicator_type = args.get("indicator_types")

    last_run_id = args.get('last_id')
    limit = int(args.get('limit', 500))
    last_run_id, indicators_list = get_indicators(client, indicator_type, limit, last_run_id)
    if indicators_list:
        readable_output = tableToMarkdown('Indicators from OpenCTI', indicators_list, headers=["type", "value"])
        return CommandResults(
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(readable_output='No indicators')


def main():
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    base_url = params.get('base_url')
    if base_url.endswith('/'):
        base_url = base_url[:-1]
    indicator_types = params.get('indicator_types')
    max_fetch = params.get('max_indicator_to_fetch')
    if max_fetch:
        max_fetch = int(max_fetch)
    else:
        max_fetch = 500

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'))
        command = demisto.command()
        demisto.info("Command being called is {}".format(command))

        # Switch case
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client, indicator_types, max_fetch)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            return_outputs('ok')

        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

    except Exception as e:
        return_error(
            f"Error [{e}]"
        )

if __name__ == "builtins":
    main()
