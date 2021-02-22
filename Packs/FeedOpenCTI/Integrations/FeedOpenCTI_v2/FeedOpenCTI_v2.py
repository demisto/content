from typing import List, Optional, Tuple
from io import StringIO
import sys
import demistomock as demisto  # noqa: E402 lgtm [py/polluting-import]
import urllib3
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from pycti import OpenCTIApiClient, MarkingDefinition, Label, ExternalReference, Identity

# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)

XSOHR_TYPES_TO_OPENCTI = {
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
KEY_TO_CTI_NAME = {
    'description': 'x_opencti_description',
    'score': 'x_opencti_score'
}
FILE_TYPES = {
    'file-md5': "file.hashes.md5",
    'file-sha1': "file.hashes.sha-1",
    'file-sha256': "file.hashes.sha-256"
}


def label_create(client, label_name: str):
    """ Create label at opencti

        Args:
            client: OpenCTI Client object
            label_name(str): label name to create

        Returns:
            readable_output, raw_response
        """
    try:
        label = client.label.create(value=label_name)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't create label.")
    return label


def marking_create(client, definition: str):
    """ Create marking at opencti

        Args:
            client: OpenCTI Client object
            definition(str): marking name to create

        Returns:
            readable_output, raw_response
        """
    try:
        marking = client.marking_definition.create(definition=definition, definition_type='TLP')
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't create marking.")
    return marking


def build_indicator_list(indicator_list: List[str]) -> List[str]:
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
        result = [XSOHR_TYPES_TO_OPENCTI.get(indicator.lower(), indicator) for indicator in indicator_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_indicators(client, indicator_types: List[str], limit: Optional[int] = 500, last_run_id: Optional[str] = None,
                   tlp_color: Optional[str] = None) -> Tuple[str, list]:
    """ Retrieving indicators from the API

    Args:
        client: OpenCTI Client object.
        indicator_types: List of indicators types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max indicators to fetch
        tlp_color: traffic Light Protocol color

    Returns:
        new_last_run: the id of the last indicator
        indicators: list of indicators
    """
    indicator_type = build_indicator_list(indicator_types)

    observables = client.stix_cyber_observable.list(types=indicator_type, after=last_run_id, first=limit,
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


def fetch_indicators_command(client, indicator_types: list, max_fetch: int, tlp_color=None, is_test=False) -> list:
    """ fetch indicators from the OpenCTI

    Args:
        client: OpenCTI Client object
        indicator_types(list): List of indicators types to get.
        max_fetch: (int) max indicators to fetch.
        tlp_color: (str)
        is_test: (bool) Indicates that it's a test and then does not save the last run.
    Returns:
        list of indicators(list)
    """
    last_run_id = demisto.getIntegrationContext().get('last_run_id')

    new_last_run, indicators_list = get_indicators(client, indicator_types, limit=max_fetch, last_run_id=last_run_id,
                                                   tlp_color=tlp_color)

    if new_last_run and not is_test:
        demisto.setIntegrationContext({'last_run_id': new_last_run})
        # we submit the indicators in batches
        for b in batch(indicators_list, batch_size=2000):
            demisto.createIndicators(b)

    return indicators_list


def get_indicators_command(client, args: dict) -> CommandResults:
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
    last_run_id, indicators_list = get_indicators(
        client=client,
        indicator_types=indicator_types,
        limit=limit,
        last_run_id=last_run_id
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
        outputs = {
            'lastRunID': last_run_id,
            'Indicators': indicators
        }
        return CommandResults(
            outputs_prefix='OpenCTI',
            outputs_key_field='Indicators.id',
            outputs=outputs,
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
    try:
        client.stix_cyber_observable.delete(id=indicator_id)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't delete indicator.")
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
    # works only with score and description
    key = KEY_TO_CTI_NAME[args.get("field")]  # type: ignore
    value = args.get("value")
    try:
        result = client.stix_cyber_observable.update_field(id=indicator_id, key=key, value=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't update indicator.")

    return CommandResults(
        outputs_prefix='OpenCTI.Indicator',
        outputs_key_field='id',
        outputs={'id': result.get('id')},
        readable_output=f'Indicator {indicator_id} updated successfully.',
        raw_response=result
    )


def indicator_create_command(client, args: Dict[str, str]) -> CommandResults:
    """ Create indicator at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    indicator_type = args.get("type")
    created_by = args.get("created_by")
    marking_id = args.get("marking_id")
    label_id = args.get("label_id")
    external_references_id = args.get("external_references_id")
    description = args.get("description")
    score = arg_to_number(args.get("score", '50'))
    data = {}
    try:
        data = json.loads(args.get("data")) if args.get("data") else {}  # type: ignore
    except Exception:
        raise DemistoException("Data argument type should be json")

    data['type'] = XSOHR_TYPES_TO_OPENCTI.get(indicator_type.lower(), indicator_type)  # type: ignore
    simple_observable_key = None
    simple_observable_value = None
    if 'file' in indicator_type.lower():  # type: ignore
        simple_observable_key = FILE_TYPES.get(indicator_type.lower(), indicator_type)  # type: ignore
        simple_observable_value = data.get('hash')
        if not simple_observable_value:
            raise DemistoException("Missing argument in data: hash")
    try:
        # cti code prints to stdout so we need to catch it.
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        result = client.stix_cyber_observable.create(
            simple_observable_key=simple_observable_key,
            simple_observable_value=simple_observable_value,
            type=indicator_type,
            createdBy=created_by, objectMarking=marking_id,
            objectLabel=label_id, externalReferences=external_references_id,
            simple_observable_description=description,
            x_opencti_score=score, observableData=data
        )
        sys.stdout = old_stdout
    except KeyError as e:
        raise DemistoException(f'Missing argument at data {e}')

    if id := result.get('id'):
        readable_output = f'Indicator created successfully. New Indicator id: {id}'
        outputs = {
            'id': result.get('id'),
            'data': data
        }
    else:
        raise DemistoException("Can't create indicator.")

    return CommandResults(
        outputs_prefix='OpenCTI.Indicator',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def indicator_add_marking(client, id: Optional[str], value: Optional[str]):
    """ Add indicator marking to opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): marking name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.add_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't add marking to indicator.")
    return result


def indicator_add_label(client, id: Optional[str], value: Optional[str]):
    """ Add indicator label to opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): label name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.add_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't add label to indicator.")
    return result


def indicator_field_add_command(client, args: Dict[str, str]) -> CommandResults:
    """ Add indicator marking or label to opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    indicator_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = indicator_add_marking(client=client, id=indicator_id, value=value)

    elif key == 'label':
        result = indicator_add_label(client=client, id=indicator_id, value=value)
    if result:
        return CommandResults(readable_output=f'Added {key} successfully.')
    else:
        return CommandResults(readable_output=f'Cant add {key} to indicator.')


def indicator_remove_label(client, id: Optional[str], value: Optional[str]):
    """ Remove indicator label from opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): label name to remove

        Returns:
            true if removed successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.remove_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't remove label from indicator.")
    return result


def indicator_remove_marking(client, id: Optional[str], value: Optional[str]):
    """ Remove indicator marking from opencti
        Args:
            client: OpenCTI Client object
            id(str): indicator id to update
            value(str): marking name to remove

        Returns:
            true if removed successfully, else false.
        """

    try:
        result = client.stix_cyber_observable.remove_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't remove marking from indicator.")
    return result


def indicator_field_remove_command(client, args: Dict[str, str]) -> CommandResults:
    """ Remove indicator marking or label from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    indicator_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = indicator_remove_marking(client=client, id=indicator_id, value=value)

    elif key == 'label':
        result = indicator_remove_label(client=client, id=indicator_id, value=value)

    if result:
        readable_output = f'{key}: {value} was removed successfully from indicator: {indicator_id}.'
    else:
        raise DemistoException(f"Can't remove {key}.")
    return CommandResults(readable_output=readable_output)


def organization_list_command(client, args: Dict[str, str]) -> CommandResults:
    """ Get organizations list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    organizations_list = client.identity.list(types='Organization', first=limit, after=last_run_id, withPagination=True)

    if organizations_list:
        new_last_run = organizations_list.get('pagination').get('endCursor')
        organizations = [
            {'name': organization.get('name'), 'id': organization.get('id')}
            for organization in organizations_list.get('entities')]
        readable_output = tableToMarkdown('Organizations', organizations, headerTransform=pascalToSpace)
        outputs = {
            'organizationsLastRun': new_last_run,
            'Organizations': organizations
        }
        return CommandResults(
            outputs_prefix='OpenCTI',
            outputs_key_field='Organizations.id',
            outputs=outputs,
            readable_output=readable_output,
            raw_response=organizations_list
        )
    else:
        return CommandResults(readable_output='No organizations')


def organization_create_command(client, args: Dict[str, str]) -> CommandResults:
    """ Create organization at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    name = args.get("name")
    description = args.get("description")
    reliability = args.get('reliability')
    try:
        identity = Identity(client)
        result = identity.create(name=name, type='Organization', x_opencti_reliability=reliability,
                                 description=description)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't remove label from indicator.")

    if organization_id := result.get('id'):
        readable_output = f'Organization {name} was created successfully with id: {organization_id}.'
        return CommandResults(outputs_prefix='OpenCTI.Organization',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create organization.")


def label_list_command(client, args: Dict[str, str]) -> CommandResults:
    """ Get label list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    label_list = client.label.list(first=limit, after=last_run_id, withPagination=True)

    if label_list:
        new_last_run = label_list.get('pagination').get('endCursor')
        labels = [
            {'value': label.get('value'), 'id': label.get('id')}
            for label in label_list.get('entities')]
        readable_output = tableToMarkdown('Labels', labels, headerTransform=pascalToSpace)
        outputs = {
            'labelsLastRun': new_last_run,
            'Labels': labels
        }
        return CommandResults(
            outputs_prefix='OpenCTI',
            outputs_key_field='Labels.id',
            outputs=outputs,
            readable_output=readable_output,
            raw_response=label_list
        )
    else:
        return CommandResults(readable_output='No labels')


def label_create_command(client, args: Dict[str, str]) -> CommandResults:
    """ Create label at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    name = args.get("name")
    result = label_create(client=client, label_name=name)

    if label_id := result.get('id'):
        readable_output = f'Label {name} was created successfully with id: {label_id}.'
        return CommandResults(outputs_prefix='OpenCTI.Label',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create label.")


def external_reference_create_command(client, args: Dict[str, str]) -> CommandResults:
    """ Create external reference at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    external_references_source_name = args.get('source_name')
    external_references_url = args.get('url')

    result = client.external_reference.create(
        source_name=external_references_source_name,
        url=external_references_url
    )

    if external_reference_id := result.get('id'):
        readable_output = f'Reference {external_references_source_name} was created successfully with id: ' \
                          f'{external_reference_id}.'
        return CommandResults(outputs_prefix='OpenCTI.externalReference',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create external reference.")


def marking_list_command(client, args: Dict[str, str]) -> CommandResults:
    """ Get marking list from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    limit = arg_to_number(args.get('limit', '50'))
    last_run_id = args.get('last_run_id')
    marking_list = client.marking_definition.list(first=limit, after=last_run_id, withPagination=True)

    if marking_list:
        new_last_run = marking_list.get('pagination').get('endCursor')
        markings = [
            {'value': mark.get('definition'), 'id': mark.get('id')}
            for mark in marking_list.get('entities')]

        readable_output = tableToMarkdown('Markings', markings, headerTransform=pascalToSpace)

        outputs = {
            'markingsLastRun': new_last_run,
            'MarkingDefinitions': markings
        }

        return CommandResults(
            outputs_prefix='OpenCTI',
            outputs_key_field='MarkingDefinitions.id',
            outputs=outputs,
            readable_output=readable_output,
            raw_response=marking_list
        )
    else:
        return CommandResults(readable_output='No markings')


def marking_create_command(client, args: Dict[str, str]) -> CommandResults:
    """ Create marking defenition at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    marking = args.get("marking")
    result = marking_create(client=client, definition=marking)

    if marking_id := result.get('id'):
        readable_output = f'Marking {marking} was created successfully with id: {marking_id}.'
        return CommandResults(outputs_prefix='OpenCTI.MarkingDefinition',
                              outputs_key_field='id',
                              outputs={'id': result.get('id')},
                              readable_output=readable_output,
                              raw_response=result)
    else:
        raise DemistoException("Can't create marking.")


def main():
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    base_url = params.get('base_url').strip('/')
    indicator_types = params.get('indicator_types', ['ALL'])
    max_fetch = params.get('max_indicator_to_fetch')
    tlp_color = params.get('tlp_color')
    if max_fetch:
        max_fetch = arg_to_number(max_fetch)
    else:
        max_fetch = 500

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'), log_level='error')
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "fetch-indicators":
            fetch_indicators_command(client, indicator_types, max_fetch, tlp_color=tlp_color)

        elif command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            fetch_indicators_command(client, indicator_types, max_fetch, is_test=True)
            return_results(CommandResults(readable_output='ok'))

        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

        elif command == "opencti-reset-fetch-indicators":
            return_results(reset_last_run())

        elif command == "opencti-indicator-delete":
            return_results(indicator_delete_command(client, args))

        elif command == "opencti-indicator-field-update":
            return_results(indicator_field_update_command(client, args))

        elif command == "opencti-indicator-create":
            return_results(indicator_create_command(client, args))

        elif command == "opencti-indicator-field-add":
            return_results(indicator_field_add_command(client, args))

        elif command == "opencti-indicator-field-remove":
            return_results(indicator_field_remove_command(client, args))

        elif command == "opencti-organization-list":
            return_results(organization_list_command(client, args))

        elif command == "opencti-organization-create":
            return_results(organization_create_command(client, args))

        elif command == "opencti-label-list":
            return_results(label_list_command(client, args))

        elif command == "opencti-label-create":
            return_results(label_create_command(client, args))

        elif command == "opencti-external-reference-create":
            return_results(external_reference_create_command(client, args))

        elif command == "opencti-marking-definition-list":
            return_results(marking_list_command(client, args))

        elif command == "opencti-marking-definition-create":
            return_results(marking_create_command(client, args))

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error:\n [{e}]")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
