import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from typing import Any
import urllib3
from pycti import OpenCTIApiClient

# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)
OPENCTI_LOGS = "opencti_logs"

XSOAR_TYPES_TO_OPENCTI = {
    'account': "User-Account",
    'domain': "Domain-Name",
    'email': "Email-Addr",
    'file-md5': "StixFile",
    'file-sha1': "StixFile",
    'file-sha256': "StixFile",
    'file': 'StixFile',
    'host': "X-OpenCTI-Hostname",
    'ip': "IPv4-Addr",
    'ipv6': "IPv6-Addr",
    'registry key': "Windows-Registry-Key",
    'url': "Url"
}
OPENCTI_TYPES_TO_XSOAR = {
    "User-Account": 'Account',
    "Domain-Name": 'Domain',
    "Email-Addr": 'Email',
    "StixFile": "File",
    "X-OpenCTI-Hostname": 'Host',
    "IPv4-Addr": 'IP',
    "IPv6-Addr": 'IPv6',
    "Windows-Registry-Key": 'Registry Key',
    "Url": 'URL'
}


def build_indicator_list(indicator_list: list[str]) -> list[str]:
    """Builds an indicator list for the query
    Args:
        indicator_list: List of XSOAR indicators types to return..

    Returns:
        indicators: list of OPENCTI indicators types"""
    result = []
    if 'ALL' in indicator_list:
        # Replaces "ALL" for all types supported on XSOAR.
        result = ['User-Account', 'Domain-Name', 'Email-Addr', 'StixFile', 'X-OpenCTI-Hostname', 'IPv4-Addr',
                  'IPv6-Addr', 'Windows-Registry-Key', 'Url']
    else:
        result = [XSOAR_TYPES_TO_OPENCTI.get(indicator.lower(), indicator) for indicator in indicator_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_indicators(client: OpenCTIApiClient, indicator_types: list[str], score: list[str] = None,
                   limit: int | None = 500, last_run_id: str | None = None,
                   tlp_color: str | None = None, tags: list[str] = None) -> tuple[str, list]:
    """ Retrieving indicators from the API

    Args:
        score: Range of scores to filter by.
        client: OpenCTI Client object.
        indicator_types: List of indicators types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max indicators to fetch
        tlp_color: traffic Light Protocol color
        tags: user tags

    Returns:
        new_last_run: the id of the last indicator
        indicators: list of indicators
    """
    indicator_type = build_indicator_list(indicator_types)
    demisto.debug(f'{OPENCTI_LOGS} - in get_indicators - builded indicator type  : {indicator_type}')
    filters: dict[str, Any] = {
        'mode': 'and',
        'filters': [{
            'key': 'entity_type',
            'values': indicator_type,
            'operator': 'eq',
            'mode': 'or'
        }],
        'filterGroups': []}
    if score:
        filters["filters"].append({
            'key': 'x_opencti_score',
            'values': score,
            'operator': 'eq',
            'mode': 'or'
        })
    demisto.debug(f'{OPENCTI_LOGS} - in get_indicators - {filters=}')
    observables = client.stix_cyber_observable.list(filters=filters, after=last_run_id, first=limit,
                                                    withPagination=True)
    new_last_run = observables.get('pagination').get('endCursor')
    demisto.debug(f'{OPENCTI_LOGS} - in get_indicators - {new_last_run=}')

    indicators = []
    for item in observables.get('entities'):
        indicator = {
            "value": item['observable_value'],
            "type": OPENCTI_TYPES_TO_XSOAR.get(item['entity_type'], item['entity_type']),
            "rawJSON": item,
            "fields": {
                "tags": [tag.get('value') for tag in item.get('objectLabel')],
                "description": item.get('x_opencti_description')
            }
        }
        if tags:
            indicator['fields']['tags'] += tags

        if not tlp_color:
            if object_marking := item.get('objectMarking', []):
                new_tlp_color = object_marking[0].get('definition', '').split(':')
                indicator['fields']['trafficlightprotocol'] = new_tlp_color[1]
        else:
            indicator['fields']['trafficlightprotocol'] = tlp_color

        score = item.get('x_opencti_score')
        if score in [*range(0, 21)]:
            indicator['score'] = 1
        elif score in [*range(21, 71)]:
            indicator['score'] = 2
        elif score in [*range(71, 101)]:
            indicator['score'] = 3

        indicators.append(indicator)
    demisto.debug(f'{OPENCTI_LOGS} - in get_indicators - sum of indicators: {len(indicators)}')
    return new_last_run, indicators


def fetch_indicators_command(client: OpenCTIApiClient, indicator_types: list, max_fetch: int, score: list = None,
                             tlp_color=None, tags=None, is_test=False) -> list:
    """ fetch indicators from the OpenCTI

    Args:
        score: Range of scores to filter by.
        client: OpenCTI Client object
        indicator_types(list): List of indicators types to get.
        max_fetch: (int) max indicators to fetch.
        tlp_color: (str)
        tags: (list)
        is_test: (bool) Indicates that it's a test and then does not save the last run.
    Returns:
        list of indicators(list)
    """
    last_run_id = demisto.getIntegrationContext().get('last_run_id')
    demisto.info(f'{OPENCTI_LOGS} - in fetch_indicators_command - get last run = {last_run_id}')

    new_last_run, indicators_list = get_indicators(client, indicator_types, limit=max_fetch, last_run_id=last_run_id,
                                                   tlp_color=tlp_color, score=score, tags=tags)

    if new_last_run and not is_test:
        demisto.setIntegrationContext({'last_run_id': new_last_run})
        demisto.debug(f'{OPENCTI_LOGS} - in fetch_indicators_command - set last run = {new_last_run}')
        # we submit the indicators in batches
        for b in batch(indicators_list, batch_size=2000):
            demisto.createIndicators(b)
            demisto.debug(f'{OPENCTI_LOGS} - in fetch_indicators_command - indicators created successfully.')

    return indicators_list


def get_indicators_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Gets indicator from opencti to readable output

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    indicator_types = argToList(args.get("indicator_types"))
    last_run_id = args.get("last_run_id")
    limit = arg_to_number(args.get('limit', 50))
    start = arg_to_number(args.get('score_start', 1))
    end = arg_to_number(args.get('score_end', 100)) + 1  # type:ignore
    demisto.debug(f"{OPENCTI_LOGS} - in get_indicators_command - {indicator_types=} {last_run_id=} {limit=} {start=} {end=}")
    score = None
    if start or end:
        score = [str(i) for i in range(start, end)]  # type:ignore
    demisto.debug(f"{OPENCTI_LOGS} - in get_indicators_command -{score=}")
    last_run_id, indicators_list = get_indicators(
        client=client,
        indicator_types=indicator_types,
        limit=limit,
        last_run_id=last_run_id,
        score=score
    )

    if indicators_list:
        indicators = [{'type': indicator['type'],
                       'value': indicator['value'],
                       'id': indicator['rawJSON']['id'],
                       'rawJSON': indicator['rawJSON']}
                      for indicator in indicators_list]
        readable_output = tableToMarkdown('Indicators', indicators,
                                          headers=["type", "value", "id"],
                                          removeNull=True)
        return CommandResults(
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(readable_output='No indicators')


def main():
    params = demisto.params()
    args = demisto.args()

    credentials = params.get('credentials', {})
    api_key = credentials.get('password')
    base_url = params.get('base_url').strip('/')
    indicator_types = params.get('indicator_types', ['ALL'])
    max_fetch = params.get('max_indicator_to_fetch')
    tlp_color = params.get('tlp_color')
    tags = argToList(params.get('feedTags'))

    if max_fetch:
        max_fetch = arg_to_number(max_fetch)
    else:
        max_fetch = 500
    start = arg_to_number(params.get('score_start', 1))
    end = arg_to_number(params.get('score_end', 100)) + 1  # type:ignore
    score = None
    if start or end:
        score = [str(i) for i in range(start, end)]  # type:ignore
    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'), log_level='error',
                                  proxies=handle_proxy())
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "fetch-indicators":
            fetch_indicators_command(client, indicator_types, max_fetch, tlp_color=tlp_color, score=score, tags=tags)

        elif command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            fetch_indicators_command(client, indicator_types, max_fetch, is_test=True)
            return_results('ok')

        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

        elif command == "opencti-reset-fetch-indicators":
            return_results(reset_last_run())

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error:\n [{e}]")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
