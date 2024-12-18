import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *

from urllib.parse import urlparse
from urllib.parse import parse_qs
from typing import Any
from MicrosoftApiModule import *  # noqa: E402
import urllib3

CLIENT_CREDENTIALS_FLOW = 'Client Credentials'
DEVICE_FLOW = 'Device Code'
MAX_ITEMS_PER_REQUEST = 500


class Client:
    """
    API Client to communicate with AzureRiskyUsers.
    """

    def __init__(self, client_id: str, verify: bool, proxy: bool, authentication_type: str,
                 tenant_id: str = None, client_secret: str = None,
                 managed_identities_client_id: str = None):

        if '@' in client_id:  # for use in test-playbook
            client_id, refresh_token = client_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        self.authentication_type = authentication_type
        client_args = assign_params(
            self_deployed=True,
            auth_id=client_id,
            grant_type=self.get_grant_by_auth_type(authentication_type),
            base_url='https://graph.microsoft.com/v1.0',
            verify=verify,
            proxy=proxy,
            scope=self.get_scope_by_auth_type(authentication_type),
            # used for device code flow
            token_retrieval_url=self.get_token_retrieval_url_by_auth_type(authentication_type),
            # used for client credentials flow
            tenant_id=tenant_id,
            enc_key=client_secret,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.graph,
            command_prefix="azure-risky-users",

        )
        self.ms_client = MicrosoftClient(**client_args)

    @staticmethod
    def get_grant_by_auth_type(authentication_type: str) -> str:
        """
        Gets the grant type by the given authentication type.
        Args:
            authentication_type: desirable authentication type, could be Client credentials or Device Code.

        Returns: the grant type.
        """
        if authentication_type == CLIENT_CREDENTIALS_FLOW:  # Client credentials flow
            return CLIENT_CREDENTIALS

        else:  # Device Code Flow
            return DEVICE_CODE

    @staticmethod
    def get_scope_by_auth_type(authentication_type: str) -> str:
        """
        Gets the scope by the given authentication type.
        Args:
            authentication_type: desirable authentication type, could be Client credentials or Device Code.

        Returns: the scope.
        """
        if authentication_type == CLIENT_CREDENTIALS_FLOW:  # Client credentials flow
            return Scopes.graph

        else:  # Device Code Flow
            return ('https://graph.microsoft.com/IdentityRiskyUser.Read.All'
                    ' IdentityRiskEvent.ReadWrite.All IdentityRiskyUser.Read.All'
                    ' IdentityRiskyUser.ReadWrite.All offline_access')

    @staticmethod
    def get_token_retrieval_url_by_auth_type(authentication_type: str) -> None | str:
        """
        Gets the token retrieval url by the given authentication type.
        Args:
            authentication_type: desirable authentication type, could be Client credentials or Device Code.

        Returns: the token retrieval url.
        """
        if authentication_type == CLIENT_CREDENTIALS_FLOW:  # Client credentials flow
            return None

        else:  # Device Code Flow
            return 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'

    def risky_users_list_request(self, limit: int = None,
                                 risk_state: str | None = None,
                                 risk_level: str | None = None,
                                 skip_token: str | None = None,
                                 order_by: str | None = None,
                                 update_before: str | None = None,
                                 updated_after: str | None = None) -> dict:
        """
        List risky users.

        Args:
            risk_state (str): Risk State to retrieve.
            risk_level (str): Specify to get only results with the same Risk Level.
            limit (int): Limit of results to retrieve.
            order_by (str): Order results by this attribute.
            update_before (str): Filter events by updated before.
            updated_after (str): Filter events by updated after.
            skip_token (str): Skip token.

        Returns:
            response (dict): API response from AzureRiskyUsers.
        """
        if skip_token:
            return self.ms_client.http_request(method='GET', full_url=skip_token)

        params = remove_empty_elements({'$top': limit,
                                        '$orderby': order_by,
                                        '$filter': build_query_filter(risk_state=risk_state, risk_level=risk_level,
                                                                      updated_date_time_after=updated_after,
                                                                      updated_date_time_before=update_before)})
        return self.ms_client.http_request(method='GET',
                                           url_suffix="identityProtection/riskyUsers",
                                           params=params)

    def risky_user_get_request(self, id: str) -> dict:
        """
        Get risky user by ID.

        Args:
            id (str): Risky user ID to get.

        return:
            Response (dict): API response from AzureRiskyUsers.
        """
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'identityProtection/riskyUsers/{id}')

    def risk_detections_list_request(self, risk_state: str | None, risk_level: str | None,
                                     detected_date_time_before: str | None, detected_date_time_after: str | None,
                                     limit: int, order_by: str, skip_token: str | None = None) -> dict:
        """
        Get a list of the Risk Detection objects and their properties.

        Args:
            risk_state (str): Risk State to retrieve.
            risk_level (str): Specify to get only results with the same Risk Level.
            detected_date_time_before (str): Filter events by created before.
            detected_date_time_after (str): Filter events by created after.
            limit (int): Limit of results to retrieve.
            order_by (str): Order results by this attribute.
            skip_token (int): Skip token.

        return:
            Response (dict): API response from AzureRiskyUsers.
        """
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$orderby': order_by,
                                        '$filter': build_query_filter(risk_state=risk_state,
                                                                      risk_level=risk_level,
                                                                      detected_date_time_before=detected_date_time_before,
                                                                      detected_date_time_after=detected_date_time_after)})

        return self.ms_client.http_request(method='GET',
                                           url_suffix="/identityProtection/riskDetections",
                                           params=params)

    def risk_detection_get_request(self, id: str) -> dict:
        """
        Read the properties and relationships of a riskDetection object.

        Args:
            id (str): ID of risk detection to retrieve.

        Return:
            Response (dict): API response from AzureRiskyUsers.
        """
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'/identityProtection/riskDetections/{id}')


def update_query(query: str, filter_name: str, filter_value: str | None, filter_operator: str):
    if not filter_value:
        return query

    if filter_operator == 'eq':
        filter_value = f"'{filter_value}'"

    filter_str = f'{filter_name} {filter_operator} {filter_value}'
    if query:
        return f'{query} and {filter_str}'
    else:
        return filter_str


def build_query_filter(risk_state=None, risk_level=None,
                       detected_date_time_before=None,
                       detected_date_time_after=None,
                       updated_date_time_before=None,
                       updated_date_time_after=None) -> str | None:
    """
    Build query filter for API call, in order to get filtered results.
    API query syntax reference: https://docs.microsoft.com/en-us/graph/query-parameters.

    Args:
        risk_state (str): Wanted risk state for filter.
        risk_level (str): Wanted risk level for filter.
        detected_date_time_before (str): Filter events by created before.
        detected_date_time_after (str): Filter events by created after.
        updated_date_time_before (str): Filter events by updated before.
        updated_date_time_after (str): Filter events by updated after.

    Returns:
        str: Query filter string for API call.
    """
    query = ''
    query = update_query(query, 'riskState', risk_state, 'eq')
    query = update_query(query, 'riskLevel', risk_level, 'eq')
    query = update_query(query, 'detectedDateTime', detected_date_time_before, 'le')
    query = update_query(query, 'detectedDateTime', detected_date_time_after, 'ge')
    query = update_query(query, 'riskLastUpdatedDateTime', updated_date_time_before, 'le')
    query = update_query(query, 'riskLastUpdatedDateTime', updated_date_time_after, 'ge')
    return query


def get_skip_token(next_link: str | None, outputs_prefix: str, outputs_key_field: str,
                   readable_output: str) -> CommandResults | str:
    if not next_link:
        return CommandResults(outputs_prefix=outputs_prefix,
                              outputs_key_field=outputs_key_field,
                              outputs=[],
                              readable_output=readable_output,
                              raw_response=[])
    else:
        parsed_url = urlparse(next_link)
        return parse_qs(parsed_url.query)['$skiptoken'][0]


def do_pagination(client: Client, response: dict[str, Any], limit: int = 1) -> dict:
    """
    Retrieves a limited number of pages by repeatedly making requests to the API using the nextLink URL
    until it has reached the specified limit or there are no more pages to retrieve,
    :param response: response body, contains collection of chat/message objects
    :param limit: the requested limit
    :return: dict of the limited response_data and the last nextLink URL.
    """

    response_data = response.get('value') or []
    next_link = response.get('@odata.nextLink')
    while (next_link := response.get('@odata.nextLink')) and len(response_data) < limit:
        response = client.risky_users_list_request(skip_token=next_link)
        response_data.extend(response.get('value') or [])
    demisto.debug(f'The limited response contains: {len(response_data[:limit])}')
    return {'value': response_data[:limit], "@odata.context": response.get('@odata.context'), '@odata.nextLink': next_link}


def get_user_human_readable(users: list) -> Any:
    """Creates the human readable fo the command_results object.

    Args:
        users (list): A list of users from the response.

    Returns:
        Any: tableToMarkdown function output.
    """
    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']
    table_outputs = [{key: user.get(key) for key in user if key in table_headers}
                     for user in users]
    return tableToMarkdown(name='Risky Users List:',
                           t=table_outputs,
                           headers=table_headers,
                           removeNull=True,
                           headerTransform=pascalToSpace)


def risky_users_list_command(client: Client, args: dict[str, str]) -> List[CommandResults]:
    """
    List all risky users.
    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    page = args.get('page')
    if page:
        raise DemistoException("Page argument is deprecated, please use next_token and page_size instead.")
    next_token = args.get('next_token')
    limit = arg_to_number(args.get('limit')) or 50
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    order_by = args.get('order_by', 'riskLastUpdatedDateTime desc')

    if args.get('updated_before'):
        fmt_updated_before = dateparser.parse(str(args.get('updated_before')), settings={'TIMEZONE': 'UTC'})
        if fmt_updated_before is not None:
            updated_before = datetime.strftime(fmt_updated_before, '%Y-%m-%dT%H:%M:%S.%f') + '0Z'
        else:
            updated_before = None
            demisto.debug(f"{fmt_updated_before=} -> {updated_before}")
    else:
        updated_before = None

    if args.get('updated_after'):
        fmt_updated_after = dateparser.parse(str(args.get('updated_after')), settings={'TIMEZONE': 'UTC'})
        if fmt_updated_after is not None:
            updated_after = datetime.strftime(fmt_updated_after, '%Y-%m-%dT%H:%M:%S.%f') + '0Z'
        else:
            updated_after = None
            demisto.debug(f"{fmt_updated_after=} -> {updated_after=}")
    else:
        updated_after = None

    page_size = arg_to_number(args.get('page_size'))
    if page_size and (page_size < 1 or page_size > 500):
        raise DemistoException("Page size must be between 1 and 500.")

    if next_token:
        # the page_size already defined the in the token.
        raw_response = client.risky_users_list_request(skip_token=next_token, order_by=order_by, update_before=updated_before,
                                                       updated_after=updated_after)
    elif page_size:
        raw_response = client.risky_users_list_request(risk_state=risk_state, risk_level=risk_level, limit=page_size,
                                                       order_by=order_by, update_before=updated_before,
                                                       updated_after=updated_after)
    else:  # there is only a limit
        top = MAX_ITEMS_PER_REQUEST if limit >= MAX_ITEMS_PER_REQUEST else limit
        raw_response = client.risky_users_list_request(risk_state=risk_state, risk_level=risk_level, limit=top,
                                                       order_by=order_by, update_before=updated_before,
                                                       updated_after=updated_after)
        raw_response = do_pagination(client, raw_response, limit)

    list_users = raw_response.get('value') or []
    next_token_from_request = raw_response.get('@odata.nextLink') or ""

    command_results = []
    command_results.append(CommandResults(
        outputs_prefix='AzureRiskyUsers.RiskyUser',
        outputs_key_field='id',
        outputs=list_users,
        readable_output=get_user_human_readable(list_users),
        raw_response=raw_response))

    # We won't display the next_token if the user does not choose to use pagination.
    if next_token_from_request and (next_token or page_size):
        command_results.append(CommandResults(
            outputs={'AzureRiskyUsers(true)': {'RiskyUserListNextToken': next_token_from_request}},
            readable_output=tableToMarkdown("Risky Users List Token:", {'next_token': next_token_from_request},
                                            headers=['next_token'], removeNull=False),
        ))
    return command_results


def risky_user_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get a risky user by ID.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    raw_response = client.risky_user_get_request(args['id'])

    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']

    outputs = {key: raw_response.get(key) for key in raw_response if key in table_headers}

    readable_output = tableToMarkdown(name=f'Found Risky User With ID: {raw_response.get("id")}',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskyUser',
                          outputs_key_field='id',
                          outputs=raw_response,
                          readable_output=readable_output,
                          raw_response=raw_response)


def risk_detections_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Retrieve a list of the Risk-Detection objects and their properties.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    page = arg_to_number(args.get('page')) or 1
    limit = arg_to_number(args.get('limit')) or 50
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    detected_date_time_before = args.get('detected_date_time_before', '')
    detected_date_time_after = args.get('detected_date_time_after', '')
    order_by = args.get('order_by', 'detectedDateTime desc')
    skip_token: CommandResults | str | None = None

    if page > 1:
        offset = limit * (page - 1)
        raw_response = client.risk_detections_list_request(risk_state,
                                                           risk_level,
                                                           detected_date_time_before,
                                                           detected_date_time_after,
                                                           offset,
                                                           order_by)

        next_link = raw_response.get('@odata.nextLink')
        skip_token = get_skip_token(next_link=next_link,
                                    outputs_prefix='AzureRiskyUsers.RiskDetection',
                                    outputs_key_field='id',
                                    readable_output=f'Risk Detections List\nCurrent page size: '
                                    f'{limit}\nShowing page {page} out others that may exist')
        if isinstance(skip_token, CommandResults):
            return skip_token

    raw_response = client.risk_detections_list_request(risk_state,
                                                       risk_level,
                                                       detected_date_time_before,
                                                       detected_date_time_after,
                                                       limit,
                                                       order_by,
                                                       skip_token)  # type: ignore[arg-type]

    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'riskDetail', 'lastUpdatedDateTime',
                     'ipAddress']

    outputs = raw_response.get('value', {})

    table_outputs = [{key: item.get(key) for key in item if key in table_headers}
                     for item in outputs]

    readable_output = tableToMarkdown(name=f'Risk Detections List\n'
                                           f'Current page size: {args["limit"]}\n'
                                           f'Showing page {args["page"]} out others that may exist',
                                      t=table_outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskDetection',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=raw_response)


def risk_detection_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Read the properties and relationships of a riskDetection object.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    raw_response = client.risk_detection_get_request(args['id'])

    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'ipAddress',
                     'detectionTimingType', 'lastUpdatedDateTime', 'location']

    outputs = {key: raw_response.get(key) for key in raw_response if key in table_headers}

    readable_output = tableToMarkdown(name=f'Found Risk Detection with ID: '
                                           f'{raw_response.get("id")}',
                                      t=outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskDetection',
                          outputs_key_field='id',
                          outputs=raw_response,
                          readable_output=readable_output,
                          raw_response=raw_response)


def test_module(client: Client):
    """Tests API connectivity and authentication'
    The test module is not functional for Device Code flow authentication, it raises the suitable exception instead.

    Args:
        client (Client): Azure Risky Users API client.

    Returns: None
    """
    if client.authentication_type == DEVICE_FLOW:  # Device Code flow
        raise DemistoException('When using device code flow configuration, please enable the integration and run '
                               'the `azure-risky-users-auth-start` command. Follow the instructions that will be printed'
                               ' as the output of the command.\n '
                               'You can validate the connection by running `!azure-risky-users-auth-test`.\n')

    test_connection(client)
    return "ok"


# Authentication Functions


def start_auth(client: Client) -> CommandResults:
    result = client.ms_client.start_auth('!azure-risky-users-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return 'Success!'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    client_id = params.get('client_id', {}).get('password', '')
    auth_type = params.get('authentication_type', 'Device Code')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    managed_identities_client_id = get_azure_managed_identities_client_id(params)

    # Params for Client Credentials flow only:
    tenant_id = params.get('tenant_id')
    client_secret = params.get('client_secret', {}).get('password', '')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        urllib3.disable_warnings()
        client = Client(
            client_id=client_id,
            verify=verify_certificate,
            proxy=proxy,
            authentication_type=auth_type,
            tenant_id=tenant_id,
            client_secret=client_secret,
            managed_identities_client_id=managed_identities_client_id
        )

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'azure-risky-users-auth-reset':
            return_results(reset_auth())
        elif command == 'azure-risky-users-auth-start':
            return_results(start_auth(client))
        elif command == 'azure-risky-users-auth-complete':
            return_results(complete_auth(client))
        elif command == 'azure-risky-users-auth-test':
            return_results(test_connection(client))
        elif command == 'azure-risky-users-list':
            return_results(risky_users_list_command(client, args))
        elif command == 'azure-risky-user-get':
            return_results(risky_user_get_command(client, args))
        elif command == 'azure-risky-users-risk-detections-list':
            return_results(risk_detections_list_command(client, args))
        elif command == 'azure-risky-users-risk-detection-get':
            return_results(risk_detection_get_command(client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
