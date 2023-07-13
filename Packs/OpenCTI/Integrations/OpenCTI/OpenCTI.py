import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
from typing import List, Optional
from io import StringIO
import sys
import urllib3
from pycti import OpenCTIApiClient, Identity

# Disable insecure warnings
urllib3.disable_warnings()

# Disable info logging from the api
logging.getLogger().setLevel(logging.ERROR)

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
KEY_TO_CTI_NAME = {
    'description': 'x_opencti_description',
    'score': 'x_opencti_score'
}
FILE_TYPES = {
    'file-md5': "file.hashes.md5",
    'file-sha1': "file.hashes.sha-1",
    'file-sha256': "file.hashes.sha-256"
}


def label_create(client: OpenCTIApiClient, label_name: Optional[str]):
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
        result = [XSOAR_TYPES_TO_OPENCTI.get(indicator.lower(), indicator) for indicator in indicator_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_indicators(client: OpenCTIApiClient, indicator_types: List[str], score: List[str] = None,
                   limit: Optional[int] = 500, last_run_id: Optional[str] = None, search: str = "") -> dict:
    """ Retrieving indicators from the API

    Args:
        score: Range of scores to filter by.
        client: OpenCTI Client object.
        indicator_types: List of indicators types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max indicators to fetch
        search: The indicator's value to filter by.

    Returns:
        indicators: dict of indicators
    """
    indicator_type = build_indicator_list(indicator_types)
    filters = [{
        'key': 'entity_type',
        'values': indicator_type
    }]
    if score:
        filters.append({
            'key': 'x_opencti_score',
            'values': score
        })

    indicators = client.stix_cyber_observable.list(after=last_run_id, first=limit,
                                                   withPagination=True, filters=filters,
                                                   search=search)
    return indicators


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
    search = args.get("search", "")
    score = None
    if start or end:
        score = [str(i) for i in range(start, end)]  # type:ignore

    raw_response = get_indicators(
        client=client,
        indicator_types=indicator_types,
        limit=limit,
        last_run_id=last_run_id,
        score=score,
        search=search
    )

    last_run = raw_response.get('pagination', {}).get('endCursor')  # type: ignore

    if indicators_list := copy.deepcopy(raw_response.get('entities')):
        indicators = [{'type': OPENCTI_TYPES_TO_XSOAR.get(indicator['entity_type'], indicator['entity_type']),
                       'value': indicator.get('observable_value'),
                       'id': indicator.get('id'),
                       'createdBy': indicator.get('createdBy').get('id')
                       if indicator.get('createdBy') else None,
                       'score': indicator.get('x_opencti_score'),
                       'description': indicator.get('x_opencti_description'),
                       'labels': [label.get('value') for label in indicator.get('objectLabel')],
                       'marking': [mark.get('definition') for mark in indicator.get('objectMarking')],
                       'externalReferences': indicator.get('externalReferences')
                       }
                      for indicator in indicators_list]

        readable_output = tableToMarkdown('Indicators', indicators,
                                          headers=["type", "value", "id"],
                                          removeNull=True)

        outputs = {
            'OpenCTI.Indicators(val.lastRunID)': {'lastRunID': last_run},
            'OpenCTI.Indicators.IndicatorsList(val.id === obj.id)': indicators
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=indicators_list
        )
    else:
        return CommandResults(readable_output='No indicators')


def indicator_delete_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
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


def indicator_field_update_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
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
        raise DemistoException(f"Can't update indicator with field: {key}.")

    return CommandResults(
        outputs_prefix='OpenCTI.Indicator',
        outputs_key_field='id',
        outputs={'id': result.get('id')},
        readable_output=f'Indicator {indicator_id} updated successfully.',
        raw_response=result
    )


def indicator_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create indicator at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    redirect_std_out = argToBoolean(demisto.params().get('redirect_std_out', 'false'))
    indicator_type = args.get("type")
    created_by = args.get("created_by")
    marking_id = args.get("marking_id")
    label_id = args.get("label_id")
    external_references_id = args.get("external_references_id")
    description = args.get("description")
    score = arg_to_number(args.get("score", '50'))
    value = args.get("value")
    data = {'type': XSOAR_TYPES_TO_OPENCTI.get(indicator_type.lower(), indicator_type),  # type:ignore
            'value': value}
    if indicator_type == 'Registry Key':
        data['key'] = value
    if indicator_type == 'Account':
        data['account_login'] = value

    simple_observable_key = None
    simple_observable_value = None
    if 'file' in indicator_type.lower():  # type: ignore
        simple_observable_key = FILE_TYPES.get(indicator_type.lower(), indicator_type)  # type: ignore
        simple_observable_value = value
    try:
        # cti code prints to stdout so we need to catch it.
        if redirect_std_out:
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
        if redirect_std_out:
            sys.stdout = sys.__stdout__
    except KeyError as e:
        raise DemistoException(f'Missing argument at data {e}')

    if id := result.get('id'):
        readable_output = f'Indicator created successfully. New Indicator id: {id}'
        outputs = {
            'id': result.get('id'),
            'value': value,
            'type': indicator_type
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


def indicator_add_marking(client: OpenCTIApiClient, id: Optional[str], value: Optional[str]):
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


def indicator_add_label(client: OpenCTIApiClient, id: Optional[str], value: Optional[str]):
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


def indicator_field_add_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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


def indicator_remove_label(client: OpenCTIApiClient, id: Optional[str], value: Optional[str]):
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


def indicator_remove_marking(client: OpenCTIApiClient, id: Optional[str], value: Optional[str]):
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


def indicator_field_remove_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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


def organization_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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
        readable_output = tableToMarkdown('Organizations', organizations, headers=['name', 'id'],
                                          headerTransform=pascalToSpace)
        outputs = {
            'OpenCTI.Organizations(val.organizationsLastRun)': {'organizationsLastRun': new_last_run},
            'OpenCTI.Organizations.OrganizationsList(val.id === obj.id)': organizations
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=organizations_list
        )
    else:
        return CommandResults(readable_output='No organizations')


def organization_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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


def label_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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
        readable_output = tableToMarkdown('Labels', labels, headers=['value', 'id'],
                                          headerTransform=pascalToSpace)

        outputs = {
            'OpenCTI.Labels(val.labelsLastRun)': {'labelsLastRun': new_last_run},
            'OpenCTI.Labels.LabelsList(val.id === obj.id)': labels
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=label_list
        )
    else:
        return CommandResults(readable_output='No labels')


def label_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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


def external_reference_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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


def marking_list_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
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

        readable_output = tableToMarkdown('Markings', markings, headers=['value', 'id'],
                                          headerTransform=pascalToSpace)
        outputs = {
            'OpenCTI.MarkingDefinitions(val.markingsLastRun)': {'markingsLastRun': new_last_run},
            'OpenCTI.MarkingDefinitions.MarkingDefinitionsList(val.id === obj.id)': markings
        }

        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=marking_list
        )
    else:
        return CommandResults(readable_output='No markings')


def main():
    params = demisto.params()
    args = demisto.args()

    credentials = params.get('credentials', {})
    api_key = credentials.get('password')
    base_url = params.get('base_url').strip('/')

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=params.get('insecure'), log_level='error',
                                  proxies=handle_proxy())
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            get_indicators_command(client, args)
            return_results('ok')

        elif command == "opencti-get-indicators":
            return_results(get_indicators_command(client, args))

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

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Error:\n [{e}]")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
