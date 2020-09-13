from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import demistomock as demisto  # noqa: E402 lgtm [py/polluting-import]
import urllib3
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
from dateutil.parser import parse
from pycti import OpenCTIApiClient
# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
import logging
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

MAX_INDICATOR_TO_FETCH = demisto.params().get('max_indicator_to_fetch', 500)

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


def get_indicators(client, indicator_type, last_run_id, limit):
    """ Retrieving indicators from the API

    Args:
        client: Client object
        indicator_type: one of ['ip', 'domain', 'all']
        last_run_id:
        limit:

    Returns:

    """
    observables = client.stix_observable.list(types=indicator_type, first=limit, after=last_run_id, withPagination=True)
    new_last_run = observables.get('pagination').get('endCursor')
    indicators = [
        {
            "value": item['observable_value'],
            "type": XSOHR_TYPES.get(item['entity_type']),
            "rawJSON": item,
            "fields": {
                "tags": [tag.get('value') for tag in item.get('tags')],
                "description": item.get('description'),
                "Creation Date": item.get('created_at'),
                "Modified": item.get('updated_at')
            }
        }for item in observables.get('entities')
    ]
    return new_last_run, indicators


def fetch_indicators_command(client, indicator_type):
    """ Retrieving indicators from the API

    Args:
        client: Client object
        indicator_type: one of ['ip', 'domain', 'all']

    Returns:

    """
    if 'all' in indicator_type:
        indicator_type = ['user-account', 'domain', 'email-address', 'file-md5', 'file-sha1', 'file-sha256', 'hostname',
                          'ipv4-addr', 'ipv6-addr', 'registry-key-value', 'url']

    last_run_id = demisto.getIntegrationContext().get('last_run_id')

    new_last_run, indicators_list = get_indicators(client, indicator_type, last_run_id, MAX_INDICATOR_TO_FETCH)

    if new_last_run:
        demisto.setIntegrationContext({'last_run_id': new_last_run})

    return indicators_list


def get_indicators_command(client, args: dict) -> CommandResults:
    """ Gets indicator from opencti to context

    Args:
        client: opencti Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    indicator_type = args.get("indicator_types")
    if 'all' in indicator_type:
        indicator_type = ['user-account', 'domain', 'email-address', 'file-md5', 'file-sha1', 'file-sha256', 'hostname',
                          'ipv4-addr', 'ipv6-addr', 'registry-key-value', 'url']
    last_run_id = args.get('last_id')
    limit = int(args.get('limit', MAX_INDICATOR_TO_FETCH))
    last_run_id, indicators_list = get_indicators(client, indicator_type, last_run_id, limit)
    if indicators_list:
        readable_output = tableToMarkdown('Indicators from OpenCTI', indicators_list, headers=["type", "value"])

        return CommandResults(
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(
            readable_output='No indicators'
        )

def create_last_iocs_query(from_date, to_date):
    return f'modified:>={from_date} and modified:<{to_date})'


def main():
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    base_url = params.get('base_url')
    if base_url.endswith('/'):
        base_url = base_url[:-1]
    indicator_types = params.get('indicator_types')
    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'))
        command = demisto.command()
        demisto.info("Command being called is {}".format(command))
        # Switch case
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client, indicator_types)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif command == "test-module":
            return_outputs('ok')
        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

    except Exception as e:
        return_error(
            f"Error [{e}]"
        )

if __name__ == "builtins":
    main()
