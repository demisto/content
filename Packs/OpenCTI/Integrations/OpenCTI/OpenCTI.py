import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
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


def label_create(client: OpenCTIApiClient, label_name: str | None):
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


def build_observable_list(observable_list: list[str]) -> list[str]:
    """Builds an observable list for the query
    Args:
        observable_list: List of XSOAR observables types to return..

    Returns:
        observables: list of OPENCTI observables types"""
    result = []
    if 'ALL' in observable_list:
        # Replaces "ALL" for all types supported on XSOAR.
        result = ['User-Account', 'Domain-Name', 'Email-Addr', 'StixFile', 'X-OpenCTI-Hostname', 'IPv4-Addr',
                  'IPv6-Addr', 'Windows-Registry-Key', 'Url']
    else:
        result = [XSOAR_TYPES_TO_OPENCTI.get(observable.lower(), observable) for observable in observable_list]
    return result


def reset_last_run():
    """
    Reset the last run from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def get_observables(
    client: OpenCTIApiClient,
    observable_types: list[str],
    score=None,
    limit: int | None = 500,
    last_run_id: str | None = None,
    search: str = ""
) -> dict:
    """ Retrieving observables from the API

    Args:
        score: Range of scores to filter by.
        client: OpenCTI Client object.
        observable_types: List of observables types to return.
        last_run_id: The last id from the previous call to use pagination.
        limit: the max observables to fetch
        search: The observable's value to filter by.

    Returns:
        observables: dict of observables
    """
    observable_type = build_observable_list(observable_types)
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

    observables = client.stix_cyber_observable.list(
        after=last_run_id,
        first=limit,
        withPagination=True,
        filters=filters,
        search=search
    )
    return observables


def get_observables_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Gets observable from opencti to readable output

    Args:
        client: OpenCTI Client object
        args: demisto.args()

    Returns:
        readable_output, raw_response
    """
    observable_types = argToList(args.get("observable_types"))
    last_run_id = args.get("last_run_id")
    limit = arg_to_number(args.get('limit', 50))
    start = arg_to_number(args.get('score_start', 0))
    end = arg_to_number(args.get('score_end', 100))  # type:ignore
    score = args.get('score')
    search = args.get("search", "")
    scores = None
    if score:
        if score.lower() == "unknown":
            scores = [None]
        elif score.isdigit():
            scores = [score]
        else:
            raise DemistoException("Invalid score was provided.")

    elif start or end:
        scores = [str(i) for i in range(start, end + 1)]  # type:ignore

    raw_response = get_observables(
        client=client,
        observable_types=observable_types,
        limit=limit,
        last_run_id=last_run_id,
        score=scores,
        search=search
    )

    last_run = raw_response.get('pagination', {}).get('endCursor')  # type: ignore

    if observables_list := copy.deepcopy(raw_response.get('entities')):
        observables = [{'type': OPENCTI_TYPES_TO_XSOAR.get(observable['entity_type'], observable['entity_type']),
                       'value': observable.get('observable_value'),
                        'id': observable.get('id'),
                        'createdBy': observable.get('createdBy').get('id')
                        if observable.get('createdBy') else None,
                        'score': observable.get('x_opencti_score'),
                        'description': observable.get('x_opencti_description'),
                        'labels': [label.get('value') for label in observable.get('objectLabel')],
                        'marking': [mark.get('definition') for mark in observable.get('objectMarking')],
                        'externalReferences': observable.get('externalReferences')
                        }
                       for observable in observables_list]

        readable_output = tableToMarkdown('Observables', observables,
                                          headers=["type", "value", "id"],
                                          removeNull=True)

        outputs = {
            'OpenCTI.Observables(val.lastRunID)': {'lastRunID': last_run},
            'OpenCTI.Observables.ObservablesList(val.id === obj.id)': observables
        }
        return CommandResults(
            outputs=outputs,
            readable_output=readable_output,
            raw_response=observables_list
        )
    else:
        return CommandResults(readable_output='No observables')


def observable_delete_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Delete observable from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    observable_id = args.get("id")
    try:
        client.stix_cyber_observable.delete(id=observable_id)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't delete observable.")
    return CommandResults(readable_output='Observable deleted.')


def observable_field_update_command(client: OpenCTIApiClient, args: dict) -> CommandResults:
    """ Update observable field at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    observable_id = args.get("id")
    # works only with score and description
    key = KEY_TO_CTI_NAME[args.get("field")]  # type: ignore
    value = args.get("value")
    try:
        result = client.stix_cyber_observable.update_field(id=observable_id, key=key, value=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException(f"Can't update observable with field: {key}.")

    return CommandResults(
        outputs_prefix='OpenCTI.Observable',
        outputs_key_field='id',
        outputs={'id': result.get('id')},
        readable_output=f'Observable {observable_id} updated successfully.',
        raw_response=result
    )


def observable_create_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Create observable at opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output, raw_response
        """
    redirect_std_out = argToBoolean(demisto.params().get('redirect_std_out', 'false'))
    observable_type = args.get("type")
    created_by = args.get("created_by")
    marking_id = args.get("marking_id")
    label_id = args.get("label_id")
    external_references_id = args.get("external_references_id")
    description = args.get("description")
    score = arg_to_number(args.get("score", '50'))
    value = args.get("value")
    data = {'type': XSOAR_TYPES_TO_OPENCTI.get(observable_type.lower(), observable_type),  # type:ignore
            'value': value}
    if observable_type == 'Registry Key':
        data['key'] = value
    if observable_type == 'Account':
        data['account_login'] = value

    simple_observable_key = None
    simple_observable_value = None
    if 'file' in observable_type.lower():  # type: ignore
        simple_observable_key = FILE_TYPES.get(observable_type.lower(), observable_type)  # type: ignore
        simple_observable_value = value
    try:
        # cti code prints to stdout so we need to catch it.
        if redirect_std_out:
            sys.stdout = StringIO()
        result = client.stix_cyber_observable.create(
            simple_observable_key=simple_observable_key,
            simple_observable_value=simple_observable_value,
            type=observable_type,
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
        readable_output = f'Observable created successfully. New Observable id: {id}'
        outputs = {
            'id': result.get('id'),
            'value': value,
            'type': observable_type
        }
    else:
        raise DemistoException("Can't create observable.")

    return CommandResults(
        outputs_prefix='OpenCTI.Observable',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=readable_output,
        raw_response=result
    )


def observable_add_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Add observable marking to opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): marking name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.add_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't add marking to observable.")
    return result


def observable_add_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Add observable label to opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): label name to add

        Returns:
            true if added successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.add_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't add label to observable.")
    return result


def observable_field_add_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Add observable marking or label to opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    observable_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = observable_add_marking(client=client, id=observable_id, value=value)

    elif key == 'label':
        result = observable_add_label(client=client, id=observable_id, value=value)
    if result:
        return CommandResults(readable_output=f'Added {key} successfully.')
    else:
        return CommandResults(readable_output=f'Cant add {key} to observable.')


def observable_remove_label(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Remove observable label from opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): label name to remove

        Returns:
            true if removed successfully, else false.
        """
    try:
        result = client.stix_cyber_observable.remove_label(id=id, label_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't remove label from observable.")
    return result


def observable_remove_marking(client: OpenCTIApiClient, id: str | None, value: str | None):
    """ Remove observable marking from opencti
        Args:
            client: OpenCTI Client object
            id(str): observable id to update
            value(str): marking name to remove

        Returns:
            true if removed successfully, else false.
        """

    try:
        result = client.stix_cyber_observable.remove_marking_definition(id=id, marking_definition_id=value)
    except Exception as e:
        demisto.error(str(e))
        raise DemistoException("Can't remove marking from observable.")
    return result


def observable_field_remove_command(client: OpenCTIApiClient, args: Dict[str, str]) -> CommandResults:
    """ Remove observable marking or label from opencti

        Args:
            client: OpenCTI Client object
            args: demisto.args()

        Returns:
            readable_output
        """
    observable_id = args.get("id")
    # works only with marking and label
    key = args.get("field")
    value = args.get("value")
    result = {}

    if key == 'marking':
        result = observable_remove_marking(client=client, id=observable_id, value=value)

    elif key == 'label':
        result = observable_remove_label(client=client, id=observable_id, value=value)

    if result:
        readable_output = f'{key}: {value} was removed successfully from observable: {observable_id}.'
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
        raise DemistoException("Can't remove label from observable.")

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
    verify = not argToBoolean(params.get('insecure'))

    try:
        client = OpenCTIApiClient(base_url, api_key, ssl_verify=verify, log_level='error',
                                  proxies=handle_proxy())
        command = demisto.command()
        demisto.info(f"Command being called is {command}")

        # Switch case
        if command == "test-module":
            '''When setting up an OpenCTI Client it is checked that it is valid and allows requests to be sent.
            and if not he immediately sends an error'''
            get_observables_command(client, args)
            return_results('ok')

        elif command == "opencti-get-observables":
            return_results(get_observables_command(client, args))

        elif command == "opencti-observable-delete":
            return_results(observable_delete_command(client, args))

        elif command == "opencti-observable-field-update":
            return_results(observable_field_update_command(client, args))

        elif command == "opencti-observable-create":
            return_results(observable_create_command(client, args))

        elif command == "opencti-observable-field-add":
            return_results(observable_field_add_command(client, args))

        elif command == "opencti-observable-field-remove":
            return_results(observable_field_remove_command(client, args))

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
