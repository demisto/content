from typing import Any, Dict, Optional, Union
from urllib.parse import parse_qs, urlparse

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

# type: ignore


CLIENT_CREDENTIALS_FLOW = 'Client Credentials'
DEVICE_FLOW = 'Device Code'


class Client:
    """
    API Client to communicate with AzureRiskyUsers.
    """

    def __init__(self, client_id: str, verify: bool, proxy: bool, authentication_type: str,
                 tenant_id: str = None, client_secret: str = None):

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
            enc_key=client_secret
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
    def get_token_retrieval_url_by_auth_type(authentication_type: str) -> Union[None, str]:
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

    def risky_users_list_request(self, risk_state: Optional[str], risk_level: Optional[str],
                                 limit: int, skip_token: str = None) -> dict:
        """
        List risky users.

        Args:
            risk_state (str): Risk State to retrieve.
            risk_level (str): Specify to get only results with the same Risk Level.
            limit (int): Limit of results to retrieve.
            skip_token (str): Skip token.

        Returns:
            response (dict): API response from AzureRiskyUsers.
        """
        detectedDateTimeBefore = None
        detectedDateTimeAfter = None
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$filter': build_query_filter(risk_state, risk_level,
                                                                      detectedDateTimeBefore,
                                                                      detectedDateTimeAfter)})

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

    def risk_detections_list_request(self, limit: int, risk_state: Optional[str], risk_level: Optional[str], orderBy: Optional[str],
                                     detectedDateTimeBefore: Optional[str],
                                     detectedDateTimeAfter: Optional[str],
                                     skip_token: str = None) -> dict:
        """
        Get a list of the Risk Detection objects and their properties.

        Args:
            risk_state (str): Risk State to retrieve.
            risk_level (str): Specify to get only results with the same Risk Level.
            limit (int): Limit of results to retrieve.
            skip_token (int): Skip token.

        return:
            Response (dict): API response from AzureRiskyUsers.
        """
        LOG(f'VIPUL: PARAM BEFORE EMPTY  limit= {limit}, risk_state = {risk_state}, risk_level= {risk_level}, orderBy= {orderBy}, detectedDateTimeBefore= {detectedDateTimeBefore}, detectedDateTimeAfter= {detectedDateTimeAfter}, skip_token= {skip_token}')
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$orderby': orderBy,
                                        '$filter': build_query_filter(risk_state, risk_level,
                                                                      detectedDateTimeBefore,
                                                                      detectedDateTimeAfter)
                                        })
        LOG(f'VIPUL: remove_empty_elements params = {params}')
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


def build_query_filter(risk_state: Optional[str], risk_level: Optional[str], detectedDateTimeBefore: Optional[str], detectedDateTimeAfter: Optional[str]) -> Optional[str]:
    """
    Build query filter for API call, in order to get filtered results.
    API query syntax reference: https://docs.microsoft.com/en-us/graph/query-parameters.

    Args:
        risk_state (str): Wanted risk state for filter.
        risk_level (str): Wanted risk level for filter.

    Returns:
        str: Query filter string for API call.
    """
    if risk_state and risk_level and detectedDateTimeBefore and detectedDateTimeAfter:
        return f"riskState eq '{risk_state}' and riskLevel ge '{risk_level}' and detectedDateTime ge {detectedDateTimeAfter} and detectedDateTime le {detectedDateTimeBefore}"
    elif risk_state and detectedDateTimeBefore and detectedDateTimeAfter:
        return f"riskState eq '{risk_state}' and detectedDateTime ge {detectedDateTimeAfter} and detectedDateTime le {detectedDateTimeBefore}"
    elif risk_state and risk_level and detectedDateTimeAfter:
        return f"riskState eq '{risk_state}' and riskLevel ge '{risk_level}' and detectedDateTime ge {detectedDateTimeAfter}"
    elif risk_state and detectedDateTimeBefore:
        return f"riskState eq '{risk_state}' and detectedDateTime le {detectedDateTimeBefore}"
    elif risk_state and detectedDateTimeAfter:
        return f"riskState eq '{risk_state}' and detectedDateTime ge {detectedDateTimeAfter}"
    elif risk_level and detectedDateTimeBefore and detectedDateTimeAfter:
        return f"riskLevel ge '{risk_level}' and detectedDateTime ge {detectedDateTimeAfter} and detectedDateTime le {detectedDateTimeBefore}"
    elif risk_level and detectedDateTimeBefore:
        return f"riskLevel ge '{risk_level}' and detectedDateTime le {detectedDateTimeBefore}"
    elif risk_level and detectedDateTimeAfter:
        return f"riskLevel ge '{risk_level}' and detectedDateTime ge {detectedDateTimeAfter}"
    elif detectedDateTimeBefore and detectedDateTimeAfter:
        return f"detectedDateTime ge {detectedDateTimeAfter} and detectedDateTime le {detectedDateTimeBefore}"
    elif detectedDateTimeBefore:
        return f"detectedDateTime le {detectedDateTimeBefore}"
    elif detectedDateTimeAfter:
        return f"detectedDateTime ge {detectedDateTimeAfter}"
    elif risk_state:
        return f"riskState eq '{risk_state}'"
    elif risk_level:
        return f"riskLevel ge '{risk_level}'"
    else:
        return None


def get_skip_token(next_link: Optional[str], outputs_prefix: str, outputs_key_field: str,
                   readable_output: str) -> Union[CommandResults, str]:
    if not next_link:
        return CommandResults(outputs_prefix=outputs_prefix,
                              outputs_key_field=outputs_key_field,
                              outputs=[],
                              readable_output=readable_output,
                              raw_response=[])
    else:
        parsed_url = urlparse(next_link)
        return parse_qs(parsed_url.query)['$skiptoken'][0]


def risky_users_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    List all risky users.
    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit = arg_to_number(args.get('limit', 50))
    page = arg_to_number(args.get('page', 1))
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    # added by Vipul Kaneriya
    # orderBy = args.get('orderBy')
    # riskLastUpdatedDateTimeStart = args.get('riskLastUpdatedDateTimeStart')
    # riskLastUpdatedDateTimeEnd = args.get('riskLastUpdatedDateTimeEnd')
    # End
    skip_token = None

    if page > 1:
        offset = limit * (page - 1)

        raw_response = client.risky_users_list_request(risk_state,
                                                       risk_level,
                                                       #    orderBy,
                                                       #    riskLastUpdatedDateTimeStart,
                                                       #    riskLastUpdatedDateTimeEnd,
                                                       offset)
        next_link = raw_response.get('@odata.nextLink')
        skip_token = get_skip_token(next_link=next_link,
                                    outputs_prefix='AzureRiskyUsers.RiskyUser',
                                    outputs_key_field='id',
                                    readable_output=f'Risky Users List\nCurrent page size: {limit}\n'
                                                    f'Showing page {page} out others that may exist')
        if type(skip_token) != str:
            return skip_token

    raw_response = client.risky_users_list_request(risk_state,
                                                   risk_level,
                                                   limit,
                                                   #    orderBy,
                                                   #    riskLastUpdatedDateTimeStart,
                                                   #    riskLastUpdatedDateTimeEnd,
                                                   skip_token)

    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']

    outputs = raw_response.get('value', {})

    table_outputs = [{key: item.get(key) for key in item if key in table_headers}
                     for item in outputs]

    readable_output = tableToMarkdown(name=f'Risky Users List\n'
                                           f'Current page size: {args["limit"]}\n'
                                           f'Showing page {args["page"]} out others that may exist',
                                      t=table_outputs,
                                      headers=table_headers,
                                      removeNull=True,
                                      headerTransform=pascalToSpace)

    return CommandResults(outputs_prefix='AzureRiskyUsers.RiskyUser',
                          outputs_key_field='id',
                          outputs=outputs,
                          readable_output=readable_output,
                          raw_response=raw_response)


def risky_user_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    outputs = {key: raw_response.get(key)
               for key in raw_response if key in table_headers}

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


def risk_detections_list_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve a list of the Risk-Detection objects and their properties.

    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit = arg_to_number(args.get('limit', 50))
    page = arg_to_number(args.get('page', 1))
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    # added by Vipul Kaneriya
    orderBy = args.get('orderBy')
    detectedDateTimeBefore = args.get('detectedDateTimeBefore')
    detectedDateTimeAfter = args.get('detectedDateTimeAfter')
    LOG(f'VIPUL: GET ARGS  limit= {limit}, page= {page}, risk_state = {risk_state}, risk_level= {risk_level}, orderBy= {orderBy}, detectedDateTimeBefore= {detectedDateTimeBefore}, detectedDateTimeAfter= {detectedDateTimeAfter}')
    # End
    skip_token = None

    if page > 1:
        offset = limit * (page - 1)

        LOG(f'VIPUL: IN page > 1 risk_detections_list_command limit= {limit}, page= {page}, risk_state = {risk_state}, risk_level= {risk_level}, offset= {offset} orderBy= {orderBy}, detectedDateTimeBefore= {detectedDateTimeBefore}, detectedDateTimeAfter= {detectedDateTimeAfter}, offset= {offset}')

        raw_response = client.risk_detections_list_request(limit,
                                                           risk_state,
                                                           risk_level,
                                                           orderBy,
                                                           detectedDateTimeBefore,
                                                           detectedDateTimeAfter,
                                                           offset)

        # LOG(f'VIPUL: risk_detections_list_command.raw_response  {raw_response}')

        next_link = raw_response.get('@odata.nextLink')
        skip_token = get_skip_token(next_link=next_link,
                                    outputs_prefix='AzureRiskyUsers.RiskDetection',
                                    outputs_key_field='id',
                                    readable_output=f'Risk Detections List\nCurrent page size: '
                                    f'{limit}\nShowing page {page} out others that may exist')
        if type(skip_token) != str:
            return skip_token

    LOG(f'VIPUL: OUT risk_detections_list_command. limit= {limit}, page= {page}, risk_state = {risk_state}, risk_level= {risk_level}, orderBy= {orderBy}, detectedDateTimeBefore= {detectedDateTimeBefore}, detectedDateTimeAfter= {detectedDateTimeAfter}, skip_token= {skip_token}')

    raw_response = client.risk_detections_list_request(limit,
                                                       risk_state,
                                                       risk_level,
                                                       orderBy,
                                                       detectedDateTimeBefore,
                                                       detectedDateTimeAfter,
                                                       skip_token)
    # LOG(f'VIPUL: 2 risk_detections_list_command.raw_response  {raw_response}')

    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'riskDetail', 'lastUpdatedDateTime',
                     'detectedDateTime', 'ipAddress']

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


def risk_detection_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
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

    outputs = {key: raw_response.get(key)
               for key in raw_response if key in table_headers}

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
                               'the azure-risky-users-auth-start command. Follow the instructions that will be printed'
                               ' as the output of the command.')

    else:  # Client credentials flow
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


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-risky-users-auth-start** to start ' \
           'the authentication process.'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    client_id = params.get('client_id').get('password', '')
    auth_type = params.get('authentication_type', 'Device Code')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    # Params for Client Credentials flow only:
    tenant_id = params.get('tenant_id')
    client_secret = params.get('client_secret', {}).get('password', '')

    command = demisto.command()
    demisto.info(f'Command being called is {command}')
    try:
        requests.packages.urllib3.disable_warnings()
        client = Client(
            client_id=client_id,
            verify=verify_certificate,
            proxy=proxy,
            authentication_type=auth_type,
            tenant_id=tenant_id,
            client_secret=client_secret
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


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('AzureRiskyUsers', 'end', __line__())
