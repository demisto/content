import json
import traceback
from typing import Any, Dict, List, Optional, Tuple, Union, cast

import dateparser
import demistomock as demisto  # noqa: E402 lgtm [py/polluting-import]
import urllib3
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]
from dateutil.parser import parse
from pycti import OpenCTIApiClient
from stix2 import TLP_GREEN
# Disable insecure warnings
urllib3.disable_warnings()


DEMISTO_TIME_FORMAT: str = '%Y-%m-%dT%H:%M:%SZ'

OPENCTI_TYPES = {
    'Account': "Account",
    'CVE': "CVE",
    'Domain': "Domain",
    'DomainGlob': "DomainGlob",
    'Email': "Email-Address",
    'File': "File",
    'FQDN': "Domain",
    'MD5': "File MD5",
    'SHA1': "File SHA-1",
    'SHA256': "File SHA-256",
    'Host': "Host",
    'IP': "IPv4-Addr",
    'CIDR': "CIDR",
    'IPv6': "IPv6-Addr",
    'IPv6CIDR': "IPv6CIDR",
    'Registry': "Registry Key",
    'SSDeep': "ssdeep",
    'URL': "URL"
}

XSOHR_TYPES = {
    'Account': "Account",
    'CVE': "CVE",
    'domain': "Domain",
    'DomainGlob': "DomainGlob",
    'email-address': "Email",
    'File': "File",
    'FQDN': "Domain",
    'MD5': "File MD5",
    'SHA1': "File SHA-1",
    'SHA256': "File SHA-256",
    'Host': "Host",
    'ipv4-addr': "IP",
    'CIDR': "CIDR",
    'IPv6': "IPv6",
    'IPv6CIDR': "IPv6CIDR",
    'Registry': "Registry Key",
    'SSDeep': "ssdeep",
    'URL': "URL"
}


def build_indicator_type(type_list):
    if 'all' in type_list:
        return ['ipv4-addr', 'domain', 'url', 'email-address']
    else:
        return_list = []
        for i in type_list:
            return_list.append(OPENCTI_TYPES.get(i))
        return return_list


def fetch_indicators_command(client, indicator_type):
    """ Retrieving indicators from the API

    Args:
        client: Client object
        indicator_type: one of ['ip', 'domain', 'all']

    Returns:

    """
    indicator_type = build_indicator_type(indicator_type)

    observables = client.stix_observable.list(filters=[{'key': 'entity_type', 'values': indicator_type}])

    return [
        {
            "value": item['observable_value'],
            "type": XSOHR_TYPES.get(item['entity_type']),
            "rawJSON": item,
            "score": parse_to_xsohr_score(item.get('markingDefinitions')),
            "fields": {
                "tags": parse_to_xsohr_tags(item.get('tags')),
                "description": item.get('description')
            }
        }for item in observables
    ]


def parse_to_xsohr_tags(tags):
    return [tag.get('value') for tag in tags]


def parse_to_xsohr_score(marking_definition=None):
    if not marking_definition:
        return 0
    else:
        return marking_definition[0].get('level')-1


def parse_to_opencti_score(client, score):
    if not score:
        return None
    else:
        opencti_scores = {
            0: 'TLP:WHITE',
            1: 'TLP:GREEN',
            2: 'TLP:AMBER',
            3: 'TLP:RED',
        }
        return client.marking_definition.read(filters=[{"key": "definition", "values": [opencti_scores[score]]}])['id']


def parse_to_opencti_tags(client, tags):
    if not tags:
        return None
    else:
        tags_list = []
        for tag in tags:
            tags_list.append(client.tag.create(tag_type='xsoar', value=tag, color='#FFFFFF').get('id'))
    return tags_list


def get_indicators_command(client, args: dict) -> CommandResults:
    """ Gets indicator to context

    Args:
        client: opencti Client object
        args: demisto.args()

    Returns:
        readable_output, context, raw_response
    """
    indicator_type = build_indicator_type(args.get("indicator_type"))

    observables = client.stix_observable.list(filters=[{'key': 'entity_type', 'values': indicator_type}])

    indicators_list = [{
        "value": item['observable_value'],
        "type": XSOHR_TYPES.get(item['entity_type']),
        "rawJSON": item,
        "score": parse_to_xsohr_score(item.get('markingDefinitions')),
        "fields": {
            "tags": parse_to_xsohr_tags(item.get('tags'))
        }

    }for item in observables]
    readable_output = tableToMarkdown('Indicators from OpenCTI', indicators_list, headers=["type", "value"])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OpenCTI.Indicators',
        outputs_key_field='value',
        outputs=indicators_list
    )


def create_last_iocs_query(from_date, to_date):
    return f'modified:>={from_date} and modified:<{to_date})'


def update_indicators(client, indicator):
    type = OPENCTI_TYPES.get(indicator.get("indicator_type", None))
    observable_value = indicator.get("value", None)
    description = indicator.get("description", None)
    marking_definitions = parse_to_opencti_score(client, indicator.get('score'))
    tags = parse_to_opencti_tags(client, indicator.get("tags", None))

    object_result = client.stix_observable.read(
        filters=[{"key": "observable_value", "values": [observable_value]}])

    if object_result is None:
        client.stix_observable.create_raw(
            type=type,
            observable_value=observable_value,
            description=description,
            markingDefinitions=marking_definitions,
            tags=tags)
    else:
        if description is not None:
            client.stix_observable.update_field(id=object_result["id"], key="description", value=description)


def update_indicators_command(client, args: dict) -> str:
    from_date = args['from_date']
    current_run: str = datetime.utcnow().strftime(DEMISTO_TIME_FORMAT)
    query = create_last_iocs_query(from_date=from_date, to_date=current_run)

    indicators = demisto.searchIndicators(query=query, page=0, size=0)

    for indicator in indicators.get('iocs', []):
        update_indicators(client, indicator)
    demisto.results(indicators)
    return 'Indicators updated successfully'


def main():
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    base_url = params.get('base_url')

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=True)

        command = demisto.command()
        demisto.info("Command being called is {}".format(command))
        # Switch case
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client, params.get("indicator_type"))
            # we submit the indicators in batches
            for b in batch(indicators, batch_size=2000):
                demisto.createIndicators(b)
        elif command == "test-module":
            return_outputs('ok')
        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))
        elif command == "opencti-update-indicators":
            return_outputs(update_indicators_command(client, args))

    except Exception as e:
        return_error(
            f"Error [{e}]"
        )

if __name__ == "builtins":
    main()