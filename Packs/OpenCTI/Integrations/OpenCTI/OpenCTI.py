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

TYPES = {
    'Domain': 'domain',
    'IP': 'ipv4-addr'
}


def build_indicator_type(type_list):
    if 'all' in type_list:
        return ['ipv4-addr', 'domain']
    else:
        return_list = []
        for i in type_list:
            return_list.append(TYPES.get(i))
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
            "type": item['entity_type'],
            "rawJSON": item
        }for item in observables
    ]


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
            "type": item['entity_type'],
            "rawJSON": item
        }for item in observables
    ]
    readable_output = tableToMarkdown('Indicators from OpenCTI', indicators_list, headers=["type", "value"])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OpenCTI.Indicators',
        outputs_key_field='value',
        outputs=indicators_list
    )


def update_indicators_command(client, args: dict) -> CommandResults:

    indicator = client.stix_observable.create(
        type=args.get("type", None),
        observable_value=args.get("observable_value", None),
        description=args.get("description", None),
        id=args.get("id", None),
        stix_id_key=args.get("stix_id_key", None),
        created_by_ref=args.get("createdByRef", None),
        marking_definitions=args.get("markingDefinitions", None),
        tags=args.get("tags", None),
        create_indicator=args.get("createIndicator", False),
        update=args.get("update", False),
    )

    indicators_list = {
        "value": args.get("observable_value", None),
        "type": indicator['entity_type'],
        "rawJSON": indicator
    }

    readable_output = tableToMarkdown('Indicators from OpenCTI', indicators_list, headers=["type", "value"])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='OpenCTI.CreateIndicators',
        outputs_key_field='value',
        outputs=indicators_list
    )


def main():
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    base_url = params.get('base_url')

    try:
        client = OpenCTIApiClient(base_url, api_key)

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
            return_results(update_indicators_command(client, args))

    except Exception as e:
        return_error(
            f"Error [{e}]"
        )

if __name__ == "builtins":
    main()