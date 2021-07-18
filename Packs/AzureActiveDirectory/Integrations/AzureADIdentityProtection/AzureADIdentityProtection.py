from CommonServerPython import *

import urllib3

LIMIT_DEFAULT = 50

urllib3.disable_warnings()

OUTPUTS_PREFIX = "AZURE_AD_IP"
BASE_URL = 'https://graph.microsoft.com/beta'
NEXT_LINK_DESCRIPTION = 'next_link value for listing commands'
RISKS_HEADERS = ['activity', 'activityDateTime', 'additionalInfo', 'correlationId', 'detectedDateTime',
                 'detectionTimingType', 'id', 'ipAddress', 'lastUpdatedDateTime', 'location', 'requestId',
                 'riskDetail', 'riskEventType', 'riskLevel', 'riskState', 'riskType', 'source', 'tokenIssuerType',
                 'userDisplayName', 'userId', 'userPrincipalName']


class AzureADClient:
    def __init__(self, app_id: str, subscription_id: str, resource_group_name: str, verify: bool, proxy: bool,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com'):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=app_id,
            grant_type=DEVICE_CODE,
            base_url=BASE_URL,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            verify=verify,
            proxy=proxy,
            resource=f'{BASE_URL}/{resource_group_name}',
            scope=' '.join(('offline_access',
                            'IdentityRiskEvent.Read.All',
                            'IdentityRiskyUser.ReadWrite.All'
                            )
                           ),
            azure_ad_endpoint=azure_ad_endpoint
        )
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name

    def http_request(self, **kwargs):
        return self.ms_client.http_request(**kwargs)

    def azure_ad_identity_protection_risk_detection_list(self,
                                                         limit: int = LIMIT_DEFAULT,
                                                         filter_expression: Optional[str] = None,
                                                         next_link: Optional[str] = None,
                                                         user_id: Optional[str] = None,
                                                         user_principal_name: Optional[str] = None,
                                                         country: Optional[str] = None) -> CommandResults:
        if next_link:
            next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
            raw_response = self.http_request(method='GET', full_url=next_link)

        else:
            params: Dict[str, Any] = {'$top': limit}

            if filter_expression is None:
                filter_expression = ' and '.join([f'{key} eq \'{value}\'' for key, value in {
                    'userId': user_id,
                    'userPrincipalName': user_principal_name,
                    'location/countryOrRegion': country
                }.items() if value is not None])

            params['$filter'] = filter_expression
            remove_nulls_from_dictionary(params)
            raw_response = self.http_request(method='GET', url_suffix='riskDetections', params=params)

        risks = raw_response.get('value', [])
        readable_output = tableToMarkdown(f'Risk List ({len(risks)} results)',
                                          risks,
                                          headers=RISKS_HEADERS,
                                          headerTransform=pascalToSpace)
        outputs = {'risks': risks}

        # removing whitespaces so they aren't mistakenly considered as argument separators in CLI
        next_link = raw_response.get('nextLink', '').replace(' ', '%20')
        if next_link:
            next_link_key = f'{OUTPUTS_PREFIX}.NextLink(val.Description == "{NEXT_LINK_DESCRIPTION}")'
            next_link_value = {'Description': NEXT_LINK_DESCRIPTION, 'URL': next_link}
            outputs[next_link_key] = next_link_value  # type: ignore

        return CommandResults(outputs_prefix=OUTPUTS_PREFIX,
                              outputs=outputs,
                              readable_output=readable_output,
                              raw_response=raw_response)

    def query_list(self,
                   url_suffix: str,
                   filter_arguments: Dict[str, Optional[Any]],
                   human_readable_header: str,
                   headers: List[str],
                   limit: int = LIMIT_DEFAULT,
                   filter_expression: Optional[str] = None,
                   next_link: Optional[str] = None):
        if next_link:
            next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
            raw_response = self.http_request(method='GET', full_url=next_link)

        else:
            params: Dict[str, Optional[Any]] = {'$top': limit}

            if filter_expression is None:
                filter_expression = ' and '.join([f'{key} eq \'{value}\''
                                                  for key, value in filter_arguments.items()
                                                  if value is not None])

            params['$filter'] = filter_expression
            remove_nulls_from_dictionary(params)
            raw_response = self.http_request(method='GET', url_suffix=url_suffix, params=params)

        values = raw_response.get('value', [])
        readable_output = tableToMarkdown(f'{human_readable_header.title()} ({len(values)} results)',
                                          values,
                                          headers=headers,
                                          headerTransform=pascalToSpace)
        outputs = {'values': values}

        # removing whitespaces so they aren't mistakenly considered as argument separators in CLI
        next_link = raw_response.get('nextLink', '').replace(' ', '%20')
        if next_link:
            next_link_key = f'{OUTPUTS_PREFIX}.NextLink(val.Description == "{NEXT_LINK_DESCRIPTION}")'
            next_link_value = {'Description': NEXT_LINK_DESCRIPTION, 'URL': next_link}
            outputs[next_link_key] = next_link_value

        return CommandResults(outputs_prefix=OUTPUTS_PREFIX,
                              outputs=outputs,
                              readable_output=readable_output,
                              raw_response=raw_response)

    def azure_ad_identity_protection_risky_users_list(self,
                                                      limit: int = LIMIT_DEFAULT,
                                                      filter_expression: Optional[str] = None,
                                                      next_link: Optional[str] = None,
                                                      updated_time: Optional[str] = None,
                                                      risk_level: Optional[str] = None,
                                                      risk_state: Optional[str] = None,
                                                      risk_detail: Optional[str] = None,
                                                      user_principal_name: Optional[str] = None) -> CommandResults:

        headers = [
            'id', 'requestId', 'correlationId', 'riskEventType', 'riskState', 'riskLevel', 'riskDetail',
            'source', 'detectionTimingType', 'activity', 'tokenIssuerType', 'ipAddress', 'location',
            'activityDateTime', 'detectedDateTime', 'lastUpdatedDateTime', 'userId', 'userDisplayName',
            'userPrincipalName', 'additionalInfo'
        ]

        filter_arguments = {
            'riskLastUpdatedDateTime': updated_time,
            'riskLevel': risk_level,
            'riskState': risk_state,
            'riskDetail': risk_detail,
            'userPrincipalName': user_principal_name
        }
        return self.query_list(headers=headers,
                               limit=limit,
                               filter_expression=filter_expression,
                               next_link=next_link,
                               human_readable_header='Risky Users',
                               url_suffix='RiskyUsers',
                               filter_arguments=filter_arguments)

    def azure_ad_identity_protection_risky_users_history_list(self,
                                                              limit: int = LIMIT_DEFAULT,
                                                              risky_user_id: Optional[str] = None,
                                                              filter_expression: Optional[str] = None,
                                                              next_link: Optional[str] = None) -> CommandResults:

        headers = [
            'id', 'idDeleted', 'isGuest', 'isProcessing',
            'riskLevel', 'riskState', 'riskDetail', 'riskLastUpdatedDateTime',
            'userDisplayName', 'userPrincipalName', 'userId',
            'initiatedBy', 'activity'
        ]

        filter_arguments = {}
        return self.query_list(headers=headers, limit=limit, filter_expression=filter_expression,
                               next_link=next_link, human_readable_header=f'Risky user history for {risky_user_id}',
                               url_suffix=f'RiskyUsers/{risky_user_id}/history',
                               filter_arguments=filter_arguments)

    def azure_ad_identity_protection_risky_users_confirm_compromised(self, user_ids: Union[str, List[str]]):
        self.http_request(method='POST',
                          resp_type='text',  # default json causes error, as the response is empty bytecode.
                          url_suffix='riskyUsers/confirmCompromised',
                          json_data={'userIds': argToList(user_ids)},
                          ok_codes=(204,))
        return '✅ Confirmed successfully.'  # raises exception if not successful

    def azure_ad_identity_protection_risky_users_dismiss(self, user_ids: Union[str, List[str]]):
        self.http_request(method='POST',
                          resp_type='text',  # default json causes error, as the response is empty bytecode.
                          url_suffix='riskyUsers/dismiss',
                          json_data={'userIds': argToList(user_ids)},
                          ok_codes=(204,))
        return '✅ Dismissed successfully.'  # raises exception if not successful


def azure_ad_identity_protection_risk_detection_list_command(client: AzureADClient, **kwargs):
    return client.azure_ad_identity_protection_risk_detection_list(**kwargs)


def azure_ad_identity_protection_risky_users_list_command(client: AzureADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_list(**kwargs)


def azure_ad_identity_protection_risky_users_history_list_command(client: AzureADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_history_list(**kwargs)


def azure_ad_identity_protection_risky_users_confirm_compromised_command(client: AzureADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_confirm_compromised(**kwargs)


def azure_ad_identity_protection_risky_users_dismiss_command(client: AzureADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_dismiss(**kwargs)


def start_auth(client: AzureADClient) -> CommandResults:
    result = client.ms_client.start_auth('!azure-ad-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: AzureADClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: AzureADClient) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> str:
    set_integration_context({})
    return 'Authorization was reset successfully. Run **!azure-ad-auth-start** to start the authentication process.'


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = AzureADClient(
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com'
        )

        # auth commands
        if command == 'test-module':
            return_results('The test module is not functional, run the azure-ad-auth-start command instead.')
        elif command == 'azure-ad-auth-start':
            return_results(start_auth(client))
        elif command == 'azure-ad-auth-complete':
            return_results(complete_auth(client))
        elif command == 'azure-ad-auth-test':
            return_results(test_connection(client))
        elif command == 'azure-ad-reset':
            return_results(reset_auth())

        # actual commands
        elif command == 'azure-ad-identity-protection-risks-list':
            return_results(azure_ad_identity_protection_risk_detection_list_command(client, **args))
        elif command == 'azure-ad-identity-protection-risky-user-list':
            return_results(azure_ad_identity_protection_risky_users_list_command(client, **args))
        elif command == 'azure-ad-identity-protection-risky-user-history-list':
            return_results(azure_ad_identity_protection_risky_users_history_list_command(client, **args))
        elif command == 'azure-ad-identity-protection-risky-user-confirm-compromised':
            return_results(azure_ad_identity_protection_risky_users_confirm_compromised_command(client, **args))
        elif command == 'azure-ad-identity-protection-risky-user-dismiss':
            return_results(azure_ad_identity_protection_risky_users_dismiss_command(client, **args))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', e)


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
