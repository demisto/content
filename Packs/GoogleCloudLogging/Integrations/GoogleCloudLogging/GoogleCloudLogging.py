import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Dict, Any
from GSuiteApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SCOPES = ['https://www.googleapis.com/auth/logging.read']
MAX_LIMIT = 1000


''' HELPER FUNCTIONS '''


def prepare_gsuite_client() -> GSuiteClient:
    """
    Creates a client.

    Args:
        request_body (dict): The request body.
        client (GSuiteClient): GSuiteClient client.

    Returns:
        A gsuite client.
    """
    credentials_json = demisto.params().get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    headers = {'Content-Type': 'application/json'}
    try:
        service_account_json = GSuiteClient.safe_load_non_strict_json(credentials_json)
        client = GSuiteClient(service_account_json,
                              base_url='https://logging.googleapis.com/', verify=verify_certificate, proxy=proxy,
                              headers=headers)
    except Exception as e:
        raise e
    return client


def get_entries_request(client: GSuiteClient, request_body: dict) -> dict:
    """
    Gets a request body and execute the request.

    Args:
        request_body (dict): The request body.
        client (GSuiteClient): GSuiteClient client.

    Returns:
        The request response.
    """
    client.set_authorized_http(scopes=SCOPES)
    return client.http_request(
        url_suffix='v2/entries:list', method='POST', body=request_body
    )


''' COMMAND FUNCTIONS '''


def test_module(params: dict) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    try:
        prepare_gsuite_client()
    except ValueError as e:
        raise e
    return 'ok'


def get_all_results(client: GSuiteClient, limit: int, request_body: dict) -> dict:
    """
    Gets lists log entries when limit is bigger then 1000.

    Args:
        client (GSuiteClient): GSuiteClient client.
        limit (int): limit argument from XSOAR.
        request_body (dict): The request body.

    Returns:
        CommandResults containing the lists log entries.
    """
    request_body.update({'pageSize': MAX_LIMIT})
    demisto.debug(f'Request body: {request_body}')
    response = get_entries_request(client, request_body)
    entries = response.get('entries', [])
    next_page = response.get('nextPageToken')
    next_response = {}
    limit -= MAX_LIMIT
    number_of_results_to_retrieve = limit
    page_size = MAX_LIMIT
    while number_of_results_to_retrieve != 0 and next_page:
        if number_of_results_to_retrieve >= MAX_LIMIT:
            request_body |= {'pageSize': page_size, 'pageToken': next_page}
            number_of_results_to_retrieve -= MAX_LIMIT
        else:
            request_body |= ({'pageSize': number_of_results_to_retrieve, 'pageToken': next_page})
            number_of_results_to_retrieve -= number_of_results_to_retrieve
        demisto.debug(f'Request body: {request_body}')
        next_response = get_entries_request(client, request_body)
        next_page = next_response.get('nextPageToken')
        entries.extend(next_response.get('entries', []))
        next_response.update({'entries': entries})
    return next_response


def create_readable_output(response: list[dict]) -> str:
    """
    Gets readable output.

    Args:
        response (list[dict]): A List of logs entries.

    Returns:
        readable output string.
    """
    hr = [
        {
            'TimeStamp': entry.get('timestamp'),
            'Log Name': entry.get('logName'),
            'Insert ID': entry.get('insertId'),
            'Principal Email': entry.get('protoPayload', {})
            .get('authenticationInfo', {})
            .get('principalEmail'),
            'Type': entry.get('resource', {}).get('type', {}),
            'Project ID': entry.get('resource', {})
            .get('labels', {})
            .get('project_id'),
            'Cluster Name': entry.get('resource', {})
            .get('labels', {})
            .get('cluster_name'),
            'Service Name': entry.get('serviceName'),
        }
        for entry in response
    ]
    return tableToMarkdown('Lists log entries', t=hr,
                           headers=['TimeStamp', 'Log Name', 'Insert ID', 'Principal Email',
                                    'Type', 'Project ID', 'Cluster Name', 'Service Name'],
                           removeNull=True)


def log_entries_list_command(client: GSuiteClient, args: Dict[str, Any]) -> CommandResults:
    """
    Gets lists log entries. Use this method to retrieve log entries that originated from a
       project/folder/organization/billing account.

    Args:
        client (GSuiteClient): GSuiteClient client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults containing the lists log entries.
    """
    resource_project_name = argToList(args.get('project_name', []))
    resource_organization_name = argToList(args.get('organization_name', []))
    resource_billing_account_name = argToList(args.get('billing_account_name', []))
    resource_folders_names = argToList(args.get('folder_name', []))

    if not (resource_project_name or resource_organization_name or resource_billing_account_name or resource_folders_names):
        raise DemistoException('At least one of the following resources must be provided: '
                               'project_name, organization_name, billing_account_name, or folder_name.')
    resources = []
    resources.extend([f'projects/{project_name}' for project_name in resource_project_name if resource_project_name])
    resources.extend([f'organizations/{organization_name}' for organization_name in resource_organization_name
                      if resource_organization_name])
    resources.extend([f'billingAccounts/{billing_account_name}'
                      for billing_account_name in resource_billing_account_name if resource_billing_account_name])
    resources.extend([f'folders/{folders_names}' for folders_names in resource_folders_names if resource_folders_names])

    limit = arg_to_number(args.get('limit'))
    page_size = arg_to_number(args.get('page_size')) or 50
    request_body = {'resourceNames': resources,
                    'filter': args.get('filter'),
                    'orderBy': args.get('order_by')}
    if limit:
        request_body['pageSize'] = limit or 50
    elif args.get('next_token'):
        request_body['pageSize'] = page_size
        request_body['pageToken'] = args.get('next_token')
    else:
        request_body['pageSize'] = limit or 50
    response = {}
    try:
        if limit and limit > 1000:
            # If the pageSize value is negative or exceeds 1000, the request is rejected.
            request_body['pageSize'] = 1000
            response = get_all_results(client, limit, request_body)
        else:
            demisto.debug(f'Request body: {request_body}')
            response = get_entries_request(client, request_body)
    except ValueError as e:
        raise ValueError(e) from e
    return CommandResults(
        outputs_key_field='insertId',
        outputs={'GoogleCloudLogging(true)': {'nextPageToken': response.get('nextPageToken')},
                 'GoogleCloudLogging.LogsEntry(val.insertId === obj.insertId)': response.get('entries')},
        readable_output=create_readable_output(response.get('entries', []))
        + tableToMarkdown('Next page token', t={'nextPageToken': response.get('nextPageToken', '').replace('--', '\--')},
                          headers=['nextPageToken'],
                          removeNull=True))


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions"""
    command = demisto.command()
    try:
        client = prepare_gsuite_client()
        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(demisto.params())
            return_results(result)

        elif command == 'gcp-logging-log-entries-list':
            return_results(log_entries_list_command(client, demisto.args()))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
