import demistomock as demisto

import dateparser
import urllib3
from MicrosoftApiModule import *

urllib3.disable_warnings()

''' GLOBAL VARS '''

INTEGRATION_NAME = 'Azure Active Directory Identity and Access'

OUTPUTS_PREFIX = "AADIdentityProtection"
BASE_URL = 'https://graph.microsoft.com/beta'
REQUIRED_PERMISSIONS = (
    'offline_access',  # allows device-flow login
    'IdentityRiskEvent.Read.All',
    'IdentityRiskyUser.ReadWrite.All'
)

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S.%f'


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
            # This could raise:
            #  {
            #    "error": {
            #       "code": "TooManyRequests",
            #       "message": "Too many requests.",
            #       "innerError": {
            #         "date": "2021-08-18T05:56:15",
            #         "request-id": "some-request-id",
            #         "client-request-id": "some-client-request-id"
            #       }
            #    }
            #  }
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


def detection_to_incident(detection, detection_date):
    detection_id: str = detection.get('id', '')
    detection_type: str = detection.get('riskEventType', '')
    detection_detail: str = detection.get('riskDetail', '')
    incident = {
        'name': f'Azure AD:'
                f' {detection_id} {detection_type} {detection_detail}',
        'occurred': f'{detection_date}Z',
        'rawJSON': json.dumps(detection)
    }
    return incident


def detections_to_incidents(detections: List[Dict[str, str]], last_fetch_datetime: datetime) -> \
        Tuple[List[Dict[str, str]], datetime]:
    """
    Given the detections retrieved from Azure Identity Protection, transforms their data to incidents format.
    """
    incidents: List[Dict[str, str]] = []
    latest_incident_time = last_fetch_datetime

    for detection in detections:
        # 'activityDateTime': '2021-07-15T11:02:54Z' / 'activityDateTime': '2021-07-15T11:02:54.12345Z'
        detection_date = date_str_to_azure_format(detection.get('detectedDateTime', ''))
        incident = detection_to_incident(detection, detection_date)
        incidents.append(incident)

        detection_datetime = datetime.strptime(detection_date, DATE_FORMAT)
        if detection_datetime > latest_incident_time:
            latest_incident_time = detection_datetime

    return incidents, latest_incident_time


def get_last_fetch_time(last_run, params):
    last_fetch = last_run.get('latest_detection_found')
    if not last_fetch:
        demisto.debug('[AzureADIdentityProtection] First run')
        # handle first time fetch
        first_fetch = f"{params.get('first_fetch') or '1 days'} ago"
        default_fetch_datetime = dateparser.parse(date_string=first_fetch, date_formats=[DATE_FORMAT])
        last_fetch = str(default_fetch_datetime.isoformat(timespec='milliseconds'))

    last_fetch = date_str_to_azure_format(last_fetch)
    last_fetch_datetime: datetime = datetime.strptime(last_fetch, DATE_FORMAT)
    demisto.debug(f'[AzureADIdentityProtection] last_fetch: {last_fetch}, last_fetch_datetime: {last_fetch_datetime}')
    return last_fetch, last_fetch_datetime


def build_filter(last_fetch, params):
    start_time_enforcing_filter = f"detectedDateTime gt {last_fetch}Z"
    user_supplied_filter = params.get('fetch_filter_expression', '')
    query_filter = f'{user_supplied_filter} and {start_time_enforcing_filter}' if user_supplied_filter \
        else start_time_enforcing_filter
    demisto.debug(f'[AzureADIdentityProtection] query_filter: {query_filter}Z')
    return query_filter


def date_str_to_azure_format(date_str):
    """
    Given a string representing a date in some general format, modifies the date to Azure format.
    That means removing the Z at the end and adding nanoseconds if they don't exist.
    Moreover, sometimes the date has too many digits for
    """
    date_str = date_str[:-1] if date_str[-1].lower() == 'z' else date_str
    if '.' not in date_str:
        date_str = f'{date_str}.000'
    else:
        date_without_ns, ns = date_str.split('.')
        ns = ns[:6]
        date_str = f'{date_without_ns}.{ns}'

    return date_str


def fetch_incidents(client: AADClient, params: Dict[str, str]):
    last_run: Dict[str, str] = demisto.getLastRun()
    demisto.debug(f'[AzureIdentityProtection] last run: {last_run}')

    last_fetch, last_fetch_datetime = get_last_fetch_time(last_run, params)
    query_filter = build_filter(last_fetch, params)
    demisto.debug(f'[AzureIdentityProtection] last fetch is: {last_fetch}, filter is: {query_filter}')

    risk_detection_list_raw: Dict = client.azure_ad_identity_protection_risk_detection_list_raw(
        limit=int(params.get('max_fetch', '50')),
        filter_expression=query_filter,
        user_id=params.get('fetch_user_id', ''),
        user_principal_name=params.get('fetch_user_principal_name', ''),
    )

    detections: list = risk_detection_list_raw.get('value', [])

    incidents, latest_detection_time = detections_to_incidents(detections, last_fetch_datetime=last_fetch_datetime)
    demisto.debug(f'[AzureIdentityProtection] Fetched {len(incidents)} incidents')

    latest_detection_time = latest_detection_time.strftime(DATE_FORMAT)
    demisto.debug(f'[AzureIdentityProtection] next run latest_detection_found: {latest_detection_time}')
    last_run = {
        'latest_detection_found': latest_detection_time
    }

    return incidents, last_run


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
            incidents, last_run = fetch_incidents(client, params)
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)

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
