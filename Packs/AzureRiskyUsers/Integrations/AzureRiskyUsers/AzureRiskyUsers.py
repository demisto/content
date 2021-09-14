import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import requests
from urllib.parse import urlparse
from urllib.parse import parse_qs
from typing import Dict, List, Optional, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


class Client:
    """
    API Client to communicate with AzureRiskyUsers.
    """

    def __init__(self, client_id: str, verify: bool, proxy: bool):
        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=client_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url='https://graph.microsoft.com/v1.0',
            verify=verify,
            proxy=proxy,
            scope='https://graph.microsoft.com/IdentityRiskyUser.Read.All '
                  'IdentityRiskEvent.ReadWrite.All IdentityRiskyUser.Read.All '
                  'IdentityRiskyUser.ReadWrite.All offline_access')

    def risky_users_list(self, risk_state: Optional[str], risk_level: Optional[str], limit: int,
                         skip_token: str = None) -> dict:
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
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$filter': build_query_filter(risk_state, risk_level)})

        return self.ms_client.http_request(method='GET',
                                           url_suffix="identityProtection/riskyUsers",
                                           params=params)

    def risky_user_get(self, id: str) -> dict:
        """
        Get risky user by ID.

        Args:
            id (str): Risky user ID to get.

        return:
            Response (dict): API response from AzureRiskyUsers.
        """
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'identityProtection/riskyUsers/{id}')

    def risk_detections_list(self, risk_state: Optional[str], risk_level: Optional[str], limit: int,
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
        params = remove_empty_elements({'$top': limit,
                                        '$skiptoken': skip_token,
                                        '$filter': build_query_filter(risk_state, risk_level)})

        return self.ms_client.http_request(method='GET',
                                           url_suffix="/identityProtection/riskDetections",
                                           params=params)

    def risk_detection_get(self, id: str) -> dict:
        """
        Read the properties and relationships of a riskDetection object.

        Args:
            id (str): ID of risk detection to retrieve.

        Return:
            Response (dict): API response from AzureRiskyUsers.
        """
        return self.ms_client.http_request(method='GET',
                                           url_suffix=f'/identityProtection/riskDetections/{id}')


def build_query_filter(risk_state: Optional[str], risk_level: Optional[str]) -> Optional[str]:
    """
    Build query filter for API call, in order to get filtered results.

    Args:
        risk_state (str): Wanted risk state for filter.
        risk_level (str): Wanted risk level for filter.

    Returns:
        str: Query filter string for API call.
    """
    if risk_state and risk_level:
        return f"riskState eq '{risk_state}' and riskLevel eq '{risk_level}'"
    elif risk_state:
        return f"riskState eq '{risk_state}'"
    elif risk_level:
        return f"riskLevel eq '{risk_level}'"
    else:
        return None


def create_event_or_incident_output(item: Dict,
                                    table_headers: List[str]) -> Dict[str, Optional[Any]]:
    """
    Create the complete output dictionary for events or incidents.

    Args:
        item (dict): A source dictionary from the API response.
        table_headers (list(str)): The table headers to be used when creating initial data.

    Returns:
        object_data (dict(str)): The output dictionary.
    """
    return remove_empty_elements({field: item.get(field) for field in table_headers})


def risky_users_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """
    List all risky users.
    Args:
        client (Client): Azure Risky Users API client.
        args (dict): Arguments for API call.
    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.
    """
    limit = int(args['limit'])
    page = int(args['page'])
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    skip_token = None
    readable_message = f'Risky Users List\nCurrent page size: {limit}\nShowing page {page} out others that may exist'

    if page > 1:
        offset = limit * (page - 1)
        raw_response = client.risky_users_list(risk_state,
                                               risk_level,
                                               offset)

        next_link = raw_response.get('@odata.nextLink')
        if not next_link:
            return CommandResults(outputs_prefix='AzureRiskyUsers.RiskyUser',
                                  outputs_key_field='id',
                                  outputs=[],
                                  readable_output=readable_message,
                                  raw_response=[])
        else:
            parsed_url = urlparse(next_link)
            skip_token = parse_qs(parsed_url.query)['$skiptoken'][0]

    raw_response = client.risky_users_list(risk_state,
                                           risk_level,
                                           limit,
                                           skip_token)

    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']

    outputs = raw_response.get('value', {})

    table_outputs = [create_event_or_incident_output(item, table_headers)
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
    raw_response = client.risky_user_get(args['id'])

    table_headers = ['id', 'userDisplayName', 'userPrincipalName', 'riskLevel',
                     'riskState', 'riskDetail', 'riskLastUpdatedDateTime']

    outputs = create_event_or_incident_output(raw_response, table_headers)

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
    limit = int(args['limit'])
    page = int(args['page'])
    risk_state = args.get('risk_state')
    risk_level = args.get('risk_level')
    skip_token = None
    readable_message = f'Risk Detections List\nCurrent page size: {limit}\nShowing page {page} out others that may exist'

    if page > 1:
        offset = int(limit) * (page - 1)
        raw_response = client.risk_detections_list(risk_state,
                                                   risk_level,
                                                   offset)

        next_link = raw_response.get('@odata.nextLink')
        if not next_link:
            return CommandResults(outputs_prefix='AzureRiskyUsers.RiskDetection',
                                  outputs_key_field='id',
                                  outputs=[],
                                  readable_output=readable_message,
                                  raw_response=[])
        else:
            parsed_url = urlparse(next_link)
            skip_token = parse_qs(parsed_url.query)['$skiptoken'][0]

    raw_response = client.risk_detections_list(risk_state,
                                               risk_level,
                                               limit,
                                               skip_token)

    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'riskDetail', 'lastUpdatedDateTime',
                     'ipAddress']

    outputs = raw_response.get('value', {})
    table_outputs = [create_event_or_incident_output(item, table_headers)
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
    raw_response = client.risk_detection_get(args['id'])
    table_headers = ['id', 'userId', 'userDisplayName', 'userPrincipalName', 'riskDetail',
                     'riskEventType', 'riskLevel', 'riskState', 'ipAddress',
                     'detectionTimingType', 'lastUpdatedDateTime', 'location']
    outputs = create_event_or_incident_output(raw_response, table_headers)

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


# Authentication Functions


def start_auth(client) -> CommandResults:
    result = client.ms_client.start_auth('!azure-risky-users-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client) -> str:
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_connection(client) -> str:
    client.ms_client.get_access_token()
    return 'Success!'


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-risky-users-auth-start** to start' \
           ' the authentication process.'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    args = demisto.args()
    client_id = params.get('client_id')

    verify_certificate = not params.get('insecure', False)

    proxy = params.get('proxy', False)
    command = demisto.command()
    LOG(f'Command being called is {command}')
    try:
        client = Client(
            client_id=client_id,
            verify=verify_certificate,
            proxy=proxy)

        if command == 'test-module':
            return_results('The test module is not functional, '
                           'run the azure-risky-users-auth-start command instead.')
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
        elif command == 'azure-risky-users-auth-start':
            return_results(risky_user_get_command(client, args))
        elif command == 'azure-risky-users-risk-detections-list':
            return_results(risk_detections_list_command(client, args))
        elif command == 'azure-risky-users-risk-detection-get':
            return_results(risk_detection_get_command(client, args))

    except Exception as e:
        return_error(f'Failed to execute {command} command. Error: {str(e)}')


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
