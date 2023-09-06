import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import List, Optional, Tuple
import urllib3
from pycti import OpenCTIApiClient
# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)

XSOHR_TYPES = {
    'user-account': "Account",
    'domain': "Domain",
    'email-address': "Email",
    'file-md5': "File",
    'file-sha1': "File",
    'file-sha256': "File",
    'hostname': "Host",
    'ipv4-addr': "IP",
    'ipv6-addr': "IPv6",
    'registry-key-value': "Registry Key",
    'url': "URL"
}


def build_indicator_list(indicator_list: List[str]) -> List[str]:
    """Builds an indicator list for the query"""
    result = []
    if 'ALL' in indicator_list:
        # Replaces "ALL" for all types supported on XSOAR.
        result = ['user-account', 'domain', 'email-address', 'file-md5', 'file-sha1', 'file-sha256', 'hostname',
                  'ipv4-addr', 'ipv6-addr', 'registry-key-value', 'url']
        # Checks for additional types not supported by XSOAR, and adds them.
        for indicator in indicator_list:
            if not XSOHR_TYPES.get(indicator.lower(), ''):
                result.append(indicator)
    else:
        result = [indicator.lower() for indicator in indicator_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_indicators(client, indicator_type: List[str], limit: int, last_run_id: Optional[str] = None,
                   tlp_color: Optional[str] = None, tags: List[str] = None) -> Tuple[str, list]:
    """ Retrieving indicators from the API

    Args:
        client: OpenCTI Client object.
        indicator_type: List of indicators types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max indicators to fetch
        tlp_color: traffic Light Protocol color
        tags: user tags

    Returns:
        new_last_run: the id of the last indicator
        indicators: list of indicators
    """
    indicator_type = build_indicator_list(indicator_type)

    observables = client.stix_cyber_observable.list(types=indicator_type, first=limit, after=last_run_id, withPagination=True)
    new_last_run = observables.get('pagination').get('endCursor')

    indicators = []
    for item in observables.get('entities'):
        indicator_tags = item.get('tags', [])
        if indicator_tags:
            indicator_tags = [tag.get('value') for tag in item.get('tags')]
        indicator = {
            "value": item['observable_value'],
            "type": XSOHR_TYPES.get(item['entity_type'], item['entity_type']),
            "rawJSON": item,
            "fields": {
                "tags": indicator_tags,
                "description": item.get('description')
            }
        }
        if tags:
            indicator['fields']['tags'] += tags
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        indicators.append(indicator)
    return new_last_run, indicators


def fetch_indicators_command(client, indicator_type: list, max_fetch: int, tlp_color=None, tags=None, is_test=False) -> list:
    """ fetch indicators from the OpenCTI

    Args:
        client: OpenCTI Client object
        indicator_type(list): List of indicators types to get.
        max_fetch: (int) max indicators to fetch.
        tlp_color: (str)
        tags: (list)
        is_test: (bool) Indicates that it's a test and then does not save the last run.
    Returns:
        list of indicators(list)
    """
    last_run_id = demisto.getIntegrationContext().get('last_run_id')

    new_last_run, indicators_list = get_indicators(client, indicator_type, limit=max_fetch, last_run_id=last_run_id,
                                                   tlp_color=tlp_color, tags=tags)

    if new_last_run and not is_test:
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
    indicator_type = argToList(args.get("indicator_types"))

    last_run_id = args.get('last_id')
    limit = int(args.get('limit', 500))
    last_run_id, indicators_list = get_indicators(client, indicator_type, limit=limit, last_run_id=last_run_id)
    if indicators_list:
        output = {'LastRunID': last_run_id,
                  'Indicators': [{'type': indicator['type'], 'value': indicator['value']}
                                 for indicator in indicators_list]}
        readable_output = tableToMarkdown('Indicators from OpenCTI', indicators_list, headers=["type", "value"])
        return CommandResults(
            outputs_prefix='OpenCTI',
            outputs_key_field='LastRunID',
            outputs=output,
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
    tlp_color = params.get('tlp_color')
    tags = argToList(params.get('feedTags'))
    if max_fetch:
        max_fetch = int(max_fetch)
    else:
        max_fetch = 500

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'), log_level='error')
        command = demisto.command()
        demisto.info("Command being called is {}".format(command))

        # Switch case
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client, indicator_types, max_fetch, tlp_color=tlp_color, tags=tags)
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)

        elif command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            fetch_indicators_command(client, indicator_types, max_fetch, is_test=True)
            return_outputs('ok')

        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

        elif command == "opencti-reset-fetch-indicators":
            return_results(reset_last_run())

    except Exception as e:
        return_error(
            f"Error [{e}]"
        )


if __name__ == "builtins":
    main()
