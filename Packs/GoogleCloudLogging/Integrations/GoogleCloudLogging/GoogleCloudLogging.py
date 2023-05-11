import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import httplib2
import urllib3
from typing import Dict, Any
from google.oauth2 import service_account
from apiclient import discovery
import google_auth_httplib2

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
SCOPES = ['https://www.googleapis.com/auth/logging.read',
          'https://www.googleapis.com/auth/logging.admin',
          'https://www.googleapis.com/auth/cloud-platform.read-only',
          'https://www.googleapis.com/auth/cloud-platform',
          ]

''' CLIENT CLASS '''


class GoogleCloudLoggingClient(BaseClient):
    """
    A Client class to wrap the google cloud api library.
    """

    def __init__(self, client_secret: str, proxy: bool,
                 insecure: bool):
        """
        :param client_secret: A string of the credentials.json generated
        :param proxy:
        :param insecure:
        """
        try:
            credentials = service_account.Credentials.from_service_account_info(info=client_secret, scopes=SCOPES)
            if proxy or insecure:
                http_client = google_auth_httplib2.AuthorizedHttp(
                    credentials, http=self.get_http_client_with_proxy(proxy, insecure))
                self.service = discovery.build('logging', 'v2', http=http_client)
            else:
                self.service = discovery.build('logging', 'v2', credentials=credentials)
        except Exception as e:
            raise e

    # disable-secrets-detection-start

    @staticmethod
    def get_http_client_with_proxy(proxy, insecure):
        """
        Create an http client with proxy with whom to use when using a proxy.
        :param proxy: Whether to use a proxy.
        :param insecure: Whether to disable ssl and use an insecure connection.
        :return:
        """
        if proxy:
            proxies = handle_proxy()
            https_proxy = proxies.get('https')
            http_proxy = proxies.get('http')
            proxy_conf = https_proxy if https_proxy else http_proxy
            # if no proxy_conf - ignore proxy
            if proxy_conf:
                if not proxy_conf.startswith('https') and not proxy_conf.startswith('http'):
                    proxy_conf = 'https://' + proxy_conf
                parsed_proxy = urllib.parse.urlparse(proxy_conf)
                proxy_info = httplib2.ProxyInfo(
                    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                    proxy_host=parsed_proxy.hostname,
                    proxy_port=parsed_proxy.port,
                    proxy_user=parsed_proxy.username,
                    proxy_pass=parsed_proxy.password)
                return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=insecure)
        return httplib2.Http(disable_ssl_certificate_validation=insecure)

    def get_entries_request(self, request_body: dict) -> dict:
        """
        Gets a request body and execute the request.

        Args:
            request_body (dict): The request body.

        Returns:
            The request response.
        """
        return self.service.entries().list(body=request_body).execute()

        # disable-secrets-detection-end


''' COMMAND FUNCTIONS '''


def test_module(client: GoogleCloudLoggingClient) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        message = 'ok'
    except Exception as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def get_all_results(client: GoogleCloudLoggingClient, limit: int, request_body: dict) -> dict:
    """
    Gets lists log entries when limit is bigger then 1000.

    Args:
        client (Client): A Client class to wrap the google cloud api library.
        limit (int): limit argument from XSOAR.
        request_body (dict): The request body.

    Returns:
        CommandResults containing the lists log entries.
    """
    request_body.update({'pageSize': 1000})
    demisto.debug(f'Request body: {request_body}')
    response = client.get_entries_request(request_body)
    entries = response.get('entries', [])
    next_page = response.get('nextPageToken')
    max_limit = 1000
    next_response = {}
    limit -= max_limit
    number_of_results_to_retrieve = limit
    page_size = max_limit
    while number_of_results_to_retrieve != 0 and next_page:
        if number_of_results_to_retrieve >= max_limit:
            request_body |= {'pageSize': page_size, 'pageToken': next_page}
            number_of_results_to_retrieve -= max_limit
        else:
            request_body |= ({'pageSize': number_of_results_to_retrieve, 'pageToken': next_page})
            number_of_results_to_retrieve -= number_of_results_to_retrieve
        demisto.debug(f'Request body: {request_body}')
        next_response = client.get_entries_request(request_body)
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


def log_entries_list_command(client: GoogleCloudLoggingClient, args: Dict[str, Any]) -> CommandResults:
    """
    Gets lists log entries. Use this method to retrieve log entries that originated from a
       project/folder/organization/billing account.

    Args:
        client (Client): A Client class to wrap the google cloud api library.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults containing the lists log entries.
    """
    resource_project_name = argToList(args.get('resource_project_name', []))
    resource_organization_name = argToList(args.get('resource_organization_name', []))
    resource_billing_account_name = argToList(args.get('resource_billing_account_name', []))
    resource_folders_names = argToList(args.get('resource_folders_names', []))
    if not (resource_project_name or resource_organization_name or resource_billing_account_name or resource_folders_names):
        raise DemistoException('At least one resource is required.')
    resources = []
    for project_name in resource_project_name:
        resources.append(f'projects/{project_name}')
    for organization_name in resource_organization_name:
        resources.append(f'organizations/{organization_name}')
    for billing_account_name in resource_billing_account_name:
        resources.append(f'billingAccounts/{billing_account_name}')
    for folders_names in resource_folders_names:
        resources.append(f'folders/{folders_names}')
    limit = arg_to_number(args.get('limit')) or 50
    page_size = arg_to_number(args.get('page_size')) or limit
    request_body = {'resourceNames': resources,
                    'filter': args.get('filter'),
                    'orderBy': args.get('order_by'),
                    'pageSize': page_size if page_size else limit,
                    'pageToken': args.get('next_token')}
    response = {}
    try:
        if limit > 1000:
            # If the pageSize value is negative or exceeds 1000, the request is rejected.
            request_body['pageSize'] = 1000
            response = get_all_results(client, limit, request_body)
        else:
            response = client.get_entries_request(request_body)
    except ValueError as e:
        raise ValueError(e)
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

    credentials_json = demisto.params().get('credentials', {}).get('password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        credentials_json = json.loads(credentials_json)
        client = GoogleCloudLoggingClient(credentials_json, proxy, verify_certificate)
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'gcp-logging-log-entries-list':
            return_results(log_entries_list_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
