from CommonServerPython import *

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

ERROR_DICT = {
    '404': 'Invalid URL.',
    '408': 'Invalid URL.',
    '409': 'Invalid message or missing parameters.',
    '500': 'Internal error.',
    '503': 'Rate limit exceeded.'
}

class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient
    """

    def __init__(self, base_url: str, api_key: str, verify: bool):
        super().__init__(base_url=base_url, verify=verify)
        self._headers = {'api_key': api_key, 'Accept': 'application/json'}
        self._proxies = handle_proxy()

    def users_search_request(self, query: str, size: str, page: str) -> dict:
        """Search users by sending a GET request.

        Args:
            query: users search query.
            size: response size.
            page: response page.
        Returns:
            Response from API.
        """
        params = {
            'rsql': query,
            'size': size,
            'page': page,
        }
        return self._http_request(method='GET', url_suffix='/users/public/search', headers=self._headers, params=params)


def users_search(client: Client, args: Dict) -> CommandResults:
    """Search users

    Args:
        client: Client object with request.
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    email = str(args.get('email', ''))
    query = str(args.get('query', ''))
    size = str(args.get('size', '10'))
    page = str(args.get('page', '0'))

    if email and query:
        raise Exception('Provide either the email or the query arguments.')
    elif email:
        search_query = f'email=={email}'
    elif query:
        search_query = query
    else:
        search_query = 'objectId==*'

    users = client.users_search_request(search_query, size, page)

    users_data = users.get('content')
    total_elements = users.get('totalElements', '0')
    table_name = ''
    if not users.get('last'):
        table_name = ' More users are available in the next page.'
    headers = ['objectId', 'alias', 'firstName', 'middleName', 'lastName', 'email']
    readable_output = tableToMarkdown(name=f"Number of users found: {total_elements}. {table_name}",
                                      t=users_data, headers=headers, removeNull=True)

    command_results = CommandResults(
        outputs_prefix='Zimperium.Users',
        outputs_key_field='objectId',
        outputs=users_data,
        readable_output=readable_output,
        raw_response=users
    )

    return command_results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    api_key = params.get('api_key')
    verify = not params.get('insecure', False)

    try:
        command = demisto.command()
        LOG(f'Command being called is {demisto.command()}')
        client = Client(api_key=api_key, verify=verify)
        commands: Dict[str, Callable[[Client, Dict[str, str]], CommandResults]] = {
            'zimperium-users-search': users_search(),
        }
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
