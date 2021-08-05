import demistomock as demisto

import urllib3
from MicrosoftApiModule import *

urllib3.disable_warnings()

''' GLOBAL VARS '''

OUTPUTS_PREFIX = "AADIdentityProtection"
BASE_URL = 'https://graph.microsoft.com/beta'
REQUIRED_PERMISSIONS = (
    'offline_access',  # allows device-flow login
    'IdentityRiskEvent.Read.All',
    'IdentityRiskyUser.ReadWrite.All'
)
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

params = demisto.params()
FETCH_TIME = params.get('fetch_time', '1 days')


def __reorder_first_headers(headers: List[str], first_headers: List[str]) -> None:
    """
    brings given headers to the head of the list, while preserving their order
    used for showing important content first.
    """
    for h in reversed(first_headers):
        if h in headers:
            headers.insert(0, headers.pop(headers.index(h)))


def __json_list_to_headers(value_list: List[Dict[str, Any]]) -> List[str]:
    headers: List[str] = []
    seen: Set[str] = set()
    for value in value_list:
        headers.extend((k for k in value if k not in seen))  # to preserve order
        seen.update(value.keys())
    return headers


def get_next_link_url(raw_response: dict) -> str:
    return raw_response.get('@odata.nextLink', '').replace(' ', '%20')


def parse_list(raw_response: dict, human_readable_title: str, context_path: str) -> CommandResults:
    """
    converts a response of Microsoft's graph search into a CommandResult object
    """
    values = raw_response.get('value', [])
    headers = __json_list_to_headers(values)
    __reorder_first_headers(headers,
                            ['Id', 'userId', 'userPrincipalName', 'userDisplayName', 'ipAddress', 'detectedDateTime'])
    readable_output = tableToMarkdown(f'{human_readable_title.title()} '
                                      f'({len(values)} {"result" if len(values) == 1 else "results"})',
                                      values,
                                      removeNull=True,
                                      headers=headers,
                                      headerTransform=pascalToSpace)
    outputs = {f'{OUTPUTS_PREFIX}.{context_path}(val.id === obj.id)': values}

    # removing whitespaces so they aren't mistakenly considered as argument separators in CLI
    next_link = get_next_link_url(raw_response)
    if next_link:
        next_link_key = f'{OUTPUTS_PREFIX}.NextLink(obj.Description === "{context_path}")'
        next_link_value = {'Description': context_path, 'URL': next_link}
        outputs[next_link_key] = next_link_value

    return CommandResults(outputs=outputs,
                          readable_output=readable_output,
                          raw_response=raw_response)


class AADClient(MicrosoftClient):
    def __init__(self, app_id: str, subscription_id: str, verify: bool, proxy: bool, azure_ad_endpoint: str):
        if '@' in app_id:  # for use in test-playbook
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        super().__init__(azure_ad_endpoint=azure_ad_endpoint,
                         self_deployed=True,
                         auth_id=app_id,
                         grant_type=DEVICE_CODE,
                         base_url=BASE_URL,
                         token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
                         verify=verify,
                         proxy=proxy,
                         scope=' '.join(REQUIRED_PERMISSIONS))

        self.subscription_id = subscription_id

    def http_request(self, **kwargs):
        return super().http_request(**kwargs)

    def query_list(self,
                   url_suffix: str,
                   limit: int,
                   filter_arguments: Optional[List[str]] = None,
                   filter_expression: Optional[str] = None,
                   next_link: Optional[str] = None) -> Dict:
        """
        Used for querying when the result is a collection (list) of items, for example RiskyUsers.
        filter_arguments is a list of the form ['foo eq \'bar\'] to be joined with a `' and '` separator.
        """
        if next_link:
            next_link = next_link.replace('%20', ' ')  # OData syntax can't handle '%' character
            return self.http_request(method='GET', full_url=next_link)

        else:
            params: Dict[str, Optional[Any]] = {'$top': limit}

            if filter_expression is None and filter_arguments is not None:
                filter_expression = ' and '.join(filter_arguments)

            params['$filter'] = filter_expression
            remove_nulls_from_dictionary(params)
            return self.http_request(method='GET', url_suffix=url_suffix, params=params)

    def azure_ad_identity_protection_risk_detection_list_raw(self,
                                                             limit: int,
                                                             filter_expression: Optional[str] = None,
                                                             next_link: Optional[str] = None,
                                                             user_id: Optional[str] = None,
                                                             user_principal_name: Optional[str] = None,
                                                             country: Optional[str] = None) -> Dict:
        filter_arguments = []

        if user_id:
            filter_arguments.append(f"userId eq '{user_id}'")
        if user_principal_name:
            filter_arguments.append(f"userPrincipalName eq '{user_principal_name}'")
        if country:
            filter_arguments.append(f"location/countryOrRegion eq '{country}'")

        demisto.info('\n\n*** azure_ad_identity_protection_risk_detection_list_raw, filter_arguments: ' + str(filter_arguments) + '\n\n')
        return self.query_list(url_suffix='riskDetections',
                               filter_arguments=filter_arguments,
                               limit=limit,
                               filter_expression=filter_expression,
                               next_link=next_link)

    def azure_ad_identity_protection_risk_detection_list(self,
                                                         limit: int,
                                                         filter_expression: Optional[str] = None,
                                                         next_link: Optional[str] = None,
                                                         user_id: Optional[str] = None,
                                                         user_principal_name: Optional[str] = None,
                                                         country: Optional[str] = None) -> CommandResults:
        raw_response = self.azure_ad_identity_protection_risk_detection_list_raw(limit=limit,
                                                                                 filter_expression=filter_expression,
                                                                                 next_link=next_link,
                                                                                 user_id=user_id,
                                                                                 user_principal_name=user_principal_name,
                                                                                 country=country)

        return parse_list(raw_response, human_readable_title="Risks", context_path="Risks")

    def azure_ad_identity_protection_risky_users_list(self,
                                                      limit: int,
                                                      filter_expression: Optional[str] = None,
                                                      next_link: Optional[str] = None,
                                                      updated_time: Optional[str] = None,
                                                      risk_level: Optional[str] = None,
                                                      risk_state: Optional[str] = None,
                                                      risk_detail: Optional[str] = None,
                                                      user_principal_name: Optional[str] = None) -> CommandResults:

        filter_arguments = []

        if risk_level:
            filter_arguments.append(f"riskLevel eq '{risk_level}'")
        if risk_state:
            filter_arguments.append(f"riskState eq '{risk_state}'")
        if risk_detail:
            filter_arguments.append(f"riskDetail eq '{risk_level}'")
        if user_principal_name:
            filter_arguments.append(f"userPrincipalName eq '{user_principal_name}'")

        updated_time = arg_to_datetime(updated_time)  # None input to arg_to_datetime stays None
        if updated_time:
            filter_arguments.append(
                f"riskLastUpdatedDateTime gt {updated_time.strftime(DATE_FORMAT)}")  # '' wrap only required for strings

        raw_response = self.query_list(
            url_suffix='RiskyUsers',
            filter_arguments=filter_arguments,
            limit=limit,
            filter_expression=filter_expression,
            next_link=next_link,
        )
        return parse_list(raw_response, human_readable_title='Risky Users', context_path='RiskyUsers')

    def azure_ad_identity_protection_risky_users_history_list(self,
                                                              limit: int,
                                                              user_id: Optional[str] = None,
                                                              filter_expression: Optional[str] = None,
                                                              next_link: Optional[str] = None) -> CommandResults:
        raw_response = self.query_list(limit=limit, filter_expression=filter_expression,
                                       next_link=next_link, url_suffix=f'RiskyUsers/{user_id}/history')

        return parse_list(raw_response,
                          context_path="RiskyUserHistory",
                          human_readable_title=f'Risky user history for {user_id}')

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


def azure_ad_identity_protection_risk_detection_list_command(client: AADClient, **kwargs):
    return client.azure_ad_identity_protection_risk_detection_list(**kwargs)


def azure_ad_identity_protection_risky_users_list_command(client: AADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_list(**kwargs)


def azure_ad_identity_protection_risky_users_history_list_command(client: AADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_history_list(**kwargs)


def azure_ad_identity_protection_risky_users_confirm_compromised_command(client: AADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_confirm_compromised(**kwargs)


def azure_ad_identity_protection_risky_users_dismiss_command(client: AADClient, **kwargs):
    return client.azure_ad_identity_protection_risky_users_dismiss(**kwargs)


def fetch_incidents(client: AADClient, params: Dict[str, str]):
    demisto.info('\n\n*** fetch_incidents, params: ' + str(params) + '\n\n')

    last_run: Dict[str, str] = demisto.getLastRun()
    demisto.info('\n\n*** fetch_incidents, last_run: ' + str(last_run) + '\n\n')
    demisto.debug(f'last run: {last_run}')

    last_fetch = last_run.get('last_item_time', '')
    if not last_fetch:
        # handle first time fetch
        default_fetch_datetime, _ = parse_date_range(date_range=FETCH_TIME, utc=True, to_timestamp=False)
        last_fetch = str(default_fetch_datetime.isoformat(timespec='seconds')) + 'Z'

    # use replace(tzinfo) to make the datetime aware of the timezone as all other dates we use are aware
    last_fetch_datetime: datetime = datetime.strptime(last_fetch, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    demisto.debug(f'last_fetch_datetime: {last_fetch_datetime}')

    risk_detection_list_raw: Dict = client.azure_ad_identity_protection_risk_detection_list_raw(
        limit=int(params.get('fetch_limit', '50')),
        filter_expression=params.get('fetch_filter_expression', ''),
        next_link=params.get('', ''),
        user_id=params.get('fetch_user_id', ''),
        user_principal_name=params.get('fetch_user_principal_name', ''),
        country=params.get('', ''),
    )
    values: list = risk_detection_list_raw.get('value', [])
    # demisto.info('\n\n*** fetch_incidents, values: ' + str(values) + '\n\n')
    demisto.debug('len(values): ' + str(len(values)))

    incidents: List = []
    # {'id': 'b7d9b782ed160b3000a9906be230ce91d1702949ddb49d326f3c2510576bdf13', 'requestId': 'e7a62d3b-8367-414b-8fd2-95fff3563801', 'correlationId': '1618d4b2-4a02-4f7a-a1e7-033b10b5313b', 'riskType': 'NewCountry', 'riskEventType': 'newCountry', 'riskState': 'dismissed', 'riskLevel': 'medium', 'riskDetail': 'adminDismissedAllRiskForUser', 'source': 'MicrosoftCloudAppSecurity', 'detectionTimingType': 'offline', 'activity': 'signin', 'tokenIssuerType': 'AzureAD', 'ipAddress': '84.207.227.14', 'activityDateTime': '2021-07-15T11:02:54Z', 'detectedDateTime': '2021-07-15T11:08:54Z', 'lastUpdatedDateTime': '2021-07-20T13:56:42.4023143Z', 'userId': '3fa9f28b-eb0e-463a-ba7b-8089fe9991e2', 'userDisplayName': 'Avishai Brandeis', 'userPrincipalName': 'avishai@demistodev.onmicrosoft.com', 'additionalInfo': '[{"Key":"userAgent","Value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"},{"Key":"alertUrl","Value":"https://demistodev.portal.cloudappsecurity.com/#/alerts/60f01746cdbeaf0b87f69a30"}]', 'location': {'city': 'Amsterdam', 'state': 'Noord-Holland', 'countryOrRegion': None, 'geoCoordinates': {'latitude': 52.30905, 'longitude': 4.94019}}}

    for current_value in values:
        demisto.info('\n\n*** , current_value: ' + str(current_value) + '\n\n')

    # TODO Implement
    # if error_fetching:
    #     finished_fetch_ok = False

    if len(incidents) > 0:
        demisto.incidents(incidents)
        demisto.setLastRun({
            'last_item_time': timestamp_to_datestring(incidents[-1]['time'])
        })


def start_auth(client: AADClient) -> CommandResults:
    result = client.start_auth('!azure-ad-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: AADClient) -> str:
    client.get_access_token()  # exception on failure
    return '✅ Authorization completed successfully.'


def test_connection(client: AADClient) -> str:
    client.get_access_token()  # exception on failure
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
        client = AADClient(
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_ad_endpoint=params.get('azure_ad_endpoint', 'https://login.microsoftonline.com')
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
        elif command == 'azure-ad-auth-reset':
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
        elif command == 'fetch-incidents':
            return_results(fetch_incidents(client, params))

        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error("\n".join((f'Failed to execute command "{demisto.command()}".',
                                f'Error:{str(e)}',
                                f'Traceback: {traceback.format_exc()}'
                                )), e)


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


# !azure-ad-identity-protection-risky-user-list limit=3 filter_expression="riskLastUpdatedDateTime gt 2017-07-01T08:00:00.000Z"
