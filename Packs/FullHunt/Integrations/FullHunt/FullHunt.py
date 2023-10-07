import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
FullHunt.io API integration
"""

''' IMPORTS '''


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API
    This Client implements API calls, and does not contain any Demisto logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this HelloWorld implementation, no special attributes defined
    """

    def get_account_status(self) -> dict:
        """
        Get the account status with email, credits, etc. with the /auth/status API endpoint.
        """
        return self._http_request(
            method='GET',
            url_suffix='/auth/status',
        )

    def get_host(self, host: str) -> Dict[str, Any]:
        """
        Gets the host details using the '/host' API endpoint.

        """

        return self._http_request(
            method='GET',
            url_suffix=f'/host/{host}'
        )

    def get_domain_details(self, domain: str) -> Dict[str, Any]:
        """
        Get domain details using the '/domain/<domain>/details' API endpoint

        """

        return self._http_request(
            method='GET',
            url_suffix=f'/domain/{domain}/details'
        )

    def get_subdomain(self, domain: str) -> Dict[str, Any]:
        """
        Get all subdomains from a given domain using the '/domain/<domain>/subdomains' API endpoint

        """

        return self._http_request(
            method='GET',
            url_suffix=f'/domain/{domain}/subdomains'
        )


''' STANDALONE FUNCTION '''


''' COMMAND FUNCTION '''


def test_module(client: Client, params: Dict[str, Any]) -> str:
    """
    Tests API connectivity and authentication by using the get_account_status() function
    """

    try:
        client.get_account_status()
        return 'ok'

    except DemistoException as e:
        if 'Unauthorized' in str(e):
            return 'Authorization error 401: Probably the API key is not set correctly'
        else:
            raise e


def get_account_status_command(client: Client, params: Dict[str, Any]) -> CommandResults:
    """
    Get the information about the user and user credit
    """
    try:
        response = client.get_account_status()
        user_info = tableToMarkdown("User Info", response.get('user', ''))
        credit_info = tableToMarkdown("Credit Info", response.get('user_credits', ''))
        readable_output = f"{user_info}\n{credit_info}"

        return CommandResults(
            outputs_prefix='FullHunt.UserInfo',
            outputs_key_field='',
            outputs=response,
            readable_output=readable_output)

    except DemistoException as e:
        raise e


def get_host_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:

    hosts = argToList(args.get('host'))
    if len(hosts) == 0:
        raise ValueError('host(s) not specified')

    command_results: List[CommandResults] = []

    for host in hosts:
        host_data = client.get_host(host)
        host_data['host'] = host

        readable_output = tableToMarkdown('Domain', host_data)

        command_results.append(CommandResults(
            readable_output=readable_output,
            outputs_prefix='FullHunt.Host',
            outputs_key_field='host',
            outputs=host_data
        ))

    return command_results


def get_domain_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    domain = args.get('domain')
    if not domain:
        raise ValueError('domain not specified')
    elif ',' in domain:
        raise ValueError('Several domains provided, please provide one unique domain')

    domain_data = client.get_domain_details(domain)

    readable_output = tableToMarkdown('Domain information', domain_data)

    return CommandResults(
        outputs_prefix='FullHunt.Domain',
        outputs_key_field='',
        outputs=domain_data,
        readable_output=readable_output
    )


def get_subdomain_command(client: Client, args: Dict[str, Any]) -> CommandResults:

    domain = args.get('domain')
    if not domain:
        raise ValueError('domain not specified')
    elif ',' in domain:
        raise ValueError('Several domains provided, please provide one unique domain')

    subdomain_data = client.get_subdomain(domain)

    readable_output = tableToMarkdown('Subdomains information', subdomain_data)

    return CommandResults(
        outputs_prefix='FullHunt.Subdomain',
        outputs_key_field='',
        outputs=subdomain_data,
        readable_output=readable_output
    )


''' MAIN FUNCTION '''


def main() -> None:
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('credentials', {}).get('password')

    # Get the service API url
    base_url = urljoin(params.get('url'), '/api/v1')

    # if your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    verify_certificate = not params.get('insecure', False)

    # if your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'X-API-KEY': f'{api_key}'
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=handle_proxy("proxy", proxy).get("http", ""))

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))

        elif command == 'fullhunt-get-account-status':
            # Get user account information and credit.
            return_results(get_account_status_command(client, params))

        elif command == 'fullhunt-get-host':
            # Get host details
            return_results(get_host_command(client, args))

        elif command == 'fullhunt-get-subdomain':
            # Get subdomain from a given domain
            return_results(get_subdomain_command(client, args))

        elif command == 'fullhunt-domain':
            # Get details about the specified domain
            return_results(get_domain_command(client, args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
