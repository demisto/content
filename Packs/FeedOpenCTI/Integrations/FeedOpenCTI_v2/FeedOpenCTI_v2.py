from typing import List, Optional, Tuple
import demistomock as demisto  # noqa: E402 lgtm [py/polluting-import]
import urllib3
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from pycti import OpenCTIApiClient, MarkingDefinition, Label, ExternalReference

# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)

XSOHR_TYPES_TO_OPENCTI = {
    'user-account': "User-Account",
    'domain': "Domain-Name",
    'email-address': "Email-Addr",
    'file-md5': "StixFile",
    'file-sha1': "StixFile",
    'file-sha256': "StixFile",
    'hostname': "X-OpenCTI-Hostname",
    'ipv4-addr': "IPv4-Addr",
    'ipv6-addr': "IPv6-Addr",
    'registry-key-value': "Registry Key",
    'url': "Url"
}
OPENCTI_TYPES_TO_XSOAR = {
    "User-Account": 'User-Account',
    "Domain-Name": 'Domain',
    "Email-Addr": 'Email-Address',
    "StixFile": "File",
    "X-OpenCTI-Hostname": 'HostName',
    "IPv4-Addr": 'IPV4-Addr',
    "IPv6-Addr": 'IPV6-Addr',
    "Registry Key": 'Registry-Key-Value',
    "Url": 'URL'
}
KEY_TO_CTI_NAME = {
    'description': 'x_opencti_description',
    'score': 'x_opencti_score',
    'created_by': 'createdBy',
    'external_references': 'externalReferences',
    'marking': 'objectMarking',
    'label': 'objectLabel'
}


def build_indicator_list(indicator_list: List[str]) -> List[str]:
    """Builds an indicator list for the query"""
    result = []
    if 'ALL' in indicator_list:
        # Replaces "ALL" for all types supported on XSOAR.
        result = ['User-Account', 'Domain-Name', 'Email-Addr', 'StixFile', 'X-OpenCTI-Hostname', 'IPv4-Addr',
                  'IPv6-Addr', 'Registry Key', 'Url']
        # Checks for additional types not supported by XSOAR, and adds them.
        for indicator in indicator_list:
            if not XSOHR_TYPES_TO_OPENCTI.get(indicator.lower(), ''):
                result.append(indicator)
    else:
        result = [XSOHR_TYPES_TO_OPENCTI.get(indicator.lower(), indicator) for indicator in indicator_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_indicators(client, indicator_type: List[str], limit: int, last_run_id: Optional[str] = None,
                   tlp_color: Optional[str] = None) -> Tuple[str, list]:
    """ Retrieving indicators from the API

    Args:
        client: OpenCTI Client object.
        indicator_type: List of indicators types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max indicators to fetch
        tlp_color: traffic Light Protocol color

    Returns:
        new_last_run: the id of the last indicator
        indicators: list of indicators
    """
    indicator_type = build_indicator_list(indicator_type)

    observables = client.stix_cyber_observable.list(types=indicator_type, first=limit, after=last_run_id,
                                                    withPagination=True)
    new_last_run = observables.get('pagination').get('endCursor')

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
        if tlp_color:
            indicator['fields']['trafficlightprotocol'] = tlp_color
        indicators.append(indicator)
    return new_last_run, indicators


def fetch_indicators_command(client, indicator_type: list, max_fetch: int, tlp_color=None, is_test=False) -> list:
    """ fetch indicators from the OpenCTI

    Args:
        client: OpenCTI Client object
        indicator_type(list): List of indicators types to get.
        max_fetch: (int) max indicators to fetch.
        tlp_color: (str)
        is_test: (bool) Indicates that it's a test and then does not save the last run.
    Returns:
        list of indicators(list)
    """
    last_run_id = demisto.getIntegrationContext().get('last_run_id')

    new_last_run, indicators_list = get_indicators(client, indicator_type, limit=max_fetch, last_run_id=last_run_id,
                                                   tlp_color=tlp_color)

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
        indicators = [{'type': indicator['type'], 'value': indicator['value'], 'id':indicator['rawJSON']['id']}
                      for indicator in indicators_list]
        output = {'LastRunID': last_run_id,
                  'Indicators': indicators}
        readable_output = tableToMarkdown('Indicators from OpenCTI', indicators, headers=["type", "value", "id"])
        return CommandResults(
            outputs_prefix='OpenCTI',
            outputs_key_field='LastRunID',
            outputs=output,
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(readable_output='No indicators')


def indicator_delete_command(client, args: dict) -> CommandResults:
    """ Delete indicator from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    indicator_id = args.get("id")
    client.stix_cyber_observable.delete(id=indicator_id)
    return CommandResults(readable_output='Indicator deleted.')


def indicator_field_update_command(client, args: dict) -> CommandResults:
    """ Update indicator field at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    indicator_id = args.get("id")
    # TODO: works only with score and description
    key = KEY_TO_CTI_NAME[args.get("key")]  # type: ignore
    value = args.get("value")
    result = client.stix_cyber_observable.update_field(id=indicator_id, key=key, value=value)

    if result.get('id'):
        readable_output = 'Indicator updated successfully.'
    else:
        return_error("Can't update indicator.")
    return CommandResults(
        outputs_prefix='OpenCTI.Indicator',
        outputs_key_field='id',
        outputs={'id': result.get('id')},
        readable_output=readable_output,
        raw_response=result
    )


def indicator_create_or_update_command(client, args: Dict[str, str]) -> CommandResults:
    """ Create or update indicator at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    indicator_id = args.get("id")
    indicator_type = args.get("type")
    # TODO object - creator id - how to get it ?
    created_by = args.get("created_by")

    marking = None
    if marking_name := args.get("marking"):
        mark_obj = MarkingDefinition(client)
        marking = mark_obj.create(definition=marking_name, definition_type='TLP').get('id')

    label = None
    if label_name := args.get("label"):
        label_obj = Label(client)
        label = label_obj.create(value=label_name).get('id')

    external_references = None
    external_references_source_name = args.get('external_references_source_name')
    external_references_url = args.get('external_references_url')
    if external_references_url and external_references_source_name:
        external_references_object = ExternalReference(client)
        external_references = external_references_object.create(source_name=external_references_source_name,
                                                                url=external_references_url).get('id')
    elif external_references_url or external_references_source_name:
        return_error("Missing argument. In order to use external references, "
                     "external_references_url and external_references_source_name are mandatory.")

    description = args.get("description")
    score = int(args.get("score", '50'))
    # TODO: update is not working
    update = argToBoolean(args.get("update", False))
    # TODO: how user will know what to write at data - add documentation
    data = {}
    try:
        data = json.loads(args.get("data")) if args.get("data") else {}  # type: ignore
    except Exception:
        return_error("Data argument type should be json")

    data['type'] = XSOHR_TYPES_TO_OPENCTI.get(indicator_type.lower(), indicator_type)  # type: ignore
    result = client.stix_cyber_observable.create(simple_observable_id=indicator_id, type=indicator_type,
                                                 createdBy=created_by, objectMarking=marking,
                                                 objectLabel=label, externalReferences=external_references,
                                                 simple_observable_description=description,
                                                 x_opencti_score=score, update=update, observableData=data,
                                                 )
    if id := result.get('id'):
        readable_output = f'Indicator created successfully. New Indicator id: {id}'
    else:
        return_error("Can't create indicator.")

    return CommandResults(
        outputs_prefix='OpenCTI.Indicator',
        outputs_key_field='id',
        outputs={'id': result.get('id')},
        readable_output=readable_output,
        raw_response=result
    )


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
    if max_fetch:
        max_fetch = int(max_fetch)
    else:
        max_fetch = 500

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'), log_level='error')
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "fetch-indicators":
            indicators = fetch_indicators_command(client, indicator_types, max_fetch, tlp_color=tlp_color)
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

        elif command == "opencti-indicator-delete":
            return_results(indicator_delete_command(client, args))

        elif command == "opencti-indicator-field-update":
            return_results(indicator_field_update_command(client, args))

        elif command == "opencti-indicator-create-update":
            return_results(indicator_create_or_update_command(client, args))

    except Exception as e:
        return_error(f"Error [{e}]")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
