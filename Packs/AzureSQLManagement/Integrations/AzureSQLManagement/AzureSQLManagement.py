import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3

import traceback
import copy

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2019-06-01-preview'
''' CLIENT CLASS '''


class Client:
    """Client class to interact with the service API
    """

    @logger
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy):
        self.resource_group_name = resource_group_name
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}'
        client_args = {
            'self_deployed': True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.
            'auth_id': app_id,
            'token_retrieval_url': 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'grant_type': DEVICE_CODE,  # disable-secrets-detection
            'base_url': base_url,
            'verify': verify,
            'proxy': proxy,
            'resource': 'https://management.core.windows.net',  # disable-secrets-detection
            'scope': 'https://management.azure.com/user_impersonation offline_access user.read',
            'ok_codes': (200, 201, 202, 204),
        }
        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = {},
                     data: dict = None, resp_type: str = 'json') -> requests.Response:
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type)

    @logger
    def azure_sql_servers_list(self):
        return self.http_request('GET', '/providers/Microsoft.Sql/servers')

    @logger
    def azure_sql_db_list(self, server_name: str):
        return self.http_request('GET', f'resourceGroups/{self.resource_group_name}/providers/Microsoft.Sql/servers/'
                                        f'{server_name}/databases')

    @logger
    def azure_sql_db_audit_policy_list(self, server_name: str, db_name: str):
        return self.http_request('GET', f'resourceGroups/{self.resource_group_name}/providers/Microsoft.Sql/servers/'
                                        f'{server_name}/databases/{db_name}/auditingSettings')

    @logger
    def azure_sql_db_threat_policy_get(self, server_name: str, db_name: str):
        return self.http_request('GET', f'resourceGroups/{self.resource_group_name}/providers/Microsoft.Sql/servers/'
                                        f'{server_name}/databases/{db_name}/securityAlertPolicies/default')

    @logger
    def azure_sql_db_audit_policy_create_update(self, server_name: str, db_name: str,
                                                state: str, audit_actions_groups: List[str],
                                                is_azure_monitor_target_enabled: bool,
                                                is_storage_secondary_key_in_use: bool,
                                                queue_delay_ms: str, retention_days: str,
                                                storage_account_access_key: str,
                                                storage_account_subscription_id: str,
                                                storage_endpoint: str):
        properties = assign_params(state=state, auditActionsAndGroups=audit_actions_groups,
                                   isAzureMonitorTargetEnabled=is_azure_monitor_target_enabled,
                                   isStorageSecondaryKeyInUse=is_storage_secondary_key_in_use,
                                   queueDelayMs=queue_delay_ms,
                                   retentionDays=retention_days,
                                   storageAccountAccessKey=storage_account_access_key,
                                   storageAccountSubscriptionId=storage_account_subscription_id,
                                   storageEndpoint=storage_endpoint)

        request_body = {'properties': properties} if properties else {}

        return self.http_request(method='PUT', url_suffix=f'resourceGroups/{self.resource_group_name}/providers'
                                                          f'/Microsoft.Sql/servers/{server_name}/databases/'
                                                          f'{db_name}/auditingSettings/default',
                                 data=request_body)

    def azure_sql_db_threat_policy_create_update(self, server_name: str, db_name: str, state: str,
                                                 disabled_alerts: List[str], email_account_admins: str,
                                                 email_addresses: List[str], retention_days: str,
                                                 storage_account_access_key: str,
                                                 use_server_default: str, storage_endpoint: str):
        properties = assign_params(state=state,
                                   retentionDays=retention_days,
                                   storageAccountAccessKey=storage_account_access_key,
                                   storageEndpoint=storage_endpoint,
                                   disabledAlerts=disabled_alerts,
                                   emailAccountAdmins=email_account_admins,
                                   emailAddresses=email_addresses,
                                   useServerDefault=use_server_default)

        request_body = {'properties': properties} if properties else {}

        return self.http_request(method='PUT', url_suffix=f'resourceGroups/{self.resource_group_name}/providers'
                                                          f'/Microsoft.Sql/servers/{server_name}/databases/'
                                                          f'{db_name}/securityAlertPolicies/default',
                                 data=request_body)


@logger
def azure_sql_servers_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """azure-sql-servers-list command returns a list of all servers

    Args:
        client: AzureSQLManagement Client to use
        limit: The maximum number of servers returned to the War Room. Default is 50.
        offset: Offset in the data set. Default is 0.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a list of all servers
    """
    offset_int = int(args.get('offset', '0'))
    limit_int = int(args.get('limit', '50'))

    server_list_raw = client.azure_sql_servers_list()

    server_list_fixed = copy.deepcopy(server_list_raw.get('value', '')[offset_int:(offset_int + limit_int)])
    for server in server_list_fixed:
        # properties = server.get('properties', {})
        if properties := server.get('properties', {}):
            server.update(properties)
            del server['properties']

    human_readable = tableToMarkdown(name='Servers List', t=server_list_fixed,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.Server',
        outputs_key_field='id',
        outputs=server_list_fixed,
        raw_response=server_list_raw
    )


@logger
def azure_sql_db_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """azure-sql-db-list command returns a list of all databases for server

    Args:
        client: AzureSQLManagement Client to use
        server_name: server name for which we want to receive list of databases
        limit: The maximum number of databases returned to the War Room. Default
        is 50.
        offset: Offset in the data set. Default is 0.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a list of all databases for server
    """

    offset_int = int(args.get('offset', '0'))
    limit_int = int(args.get('limit', '50'))

    database_list_raw = client.azure_sql_db_list(args.get('server_name'))
    database_list_fixed = copy.deepcopy(database_list_raw.get('value', '')[offset_int:(offset_int + limit_int)])

    for db in database_list_fixed:
        properties = db.get('properties', {})
        if properties:
            db.update(properties)
            del db['properties']

    human_readable = tableToMarkdown(name='Database List', t=database_list_fixed,
                                     headers=['id', 'databaseId', 'name', 'location', 'status', 'managedBy'],
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DB',
        outputs_key_field='id',
        outputs=database_list_fixed,
        raw_response=database_list_raw
    )


@logger
def azure_sql_db_audit_policy_list_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """azure_sql_db_audit_policy_list command returns a list of auditing settings of a database

    Args:
        client: AzureSQLManagement Client to use
        server_name: server name for which we want to receive list of auditing settings
        db_name: database for which we want to receive list of auditing settings
        limit: The maximum number of audit policies returned to the War Room. Default
        is 50.
        offset: Offset in the data set. Default is 0.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a list of auditing settings of a database

    """
    server_name = args.get('server_name')
    db_name = args.get('db_name')
    offset_int = int(args.get('offset', '0'))
    limit_int = int(args.get('limit', '50'))
    audit_list_raw = client.azure_sql_db_audit_policy_list(server_name, db_name)
    audit_list_fixed = copy.deepcopy(audit_list_raw.get('value', '')[offset_int:(offset_int + limit_int)])
    for db in audit_list_fixed:
        if properties := db.get('properties', {}):
            db.update(properties)
            del db['properties']

    human_readable = tableToMarkdown(name='Database Audit Settings', t=audit_list_fixed,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DbAuditPolicy',
        outputs_key_field='id',
        outputs=audit_list_fixed,
        raw_response=audit_list_raw
    )


@logger
def azure_sql_db_audit_policy_create_update_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """azure_sql_db_audit_policy_create_update command upadates and creates audit policies related to the server
    and database

    Args:
        client: AzureSQLManagement Client to use
        server_name: server name for which we want to create or update auditing settings
        db_name: database for which we want to create or update auditing settings
        state: state of the policy
        audit_actions_groups: Comma-separated Actions-Groups and Actions to audit.
        is_azure_monitor_target_enabled: Is audit events are sent to Azure Monitor
        is_storage_secondary_key_in_use: Is storageAccountAccessKey value is the storage's secondary key
        queue_delay_ms: Time in milliseconds that can elapse before audit actions are forced
        to be processed.
        retention_days: Number of days to keep the policy in the audit logs.
        storage_account_access_key: identifier key of the auditing storage account
        storage_account_subscription_id: storage subscription Id
        storage_endpoint: Storage endpoint.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an updated audit policy

    """

    server_name = args.get('server_name')
    db_name = args.get('db_name')
    state = args.get('state')
    audit_actions_groups = argToList(args.get('audit_actions_groups', ''))
    is_azure_monitor_target_enabled = args.get('is_azure_monitor_target_enabled', '')
    is_storage_secondary_key_in_use = args.get('is_storage_secondary_key_in_use', '')
    queue_delay_ms = args.get('queue_delay_ms', '')
    retention_days = args.get('retention_days', '')
    storage_account_access_key = args.get('storage_account_access_key', '')
    storage_account_subscription_id = args.get('storage_account_subscription_id', '')
    storage_endpoint = args.get('storage_endpoint', '')

    raw_response = client.azure_sql_db_audit_policy_create_update(server_name=server_name, db_name=db_name, state=state,
                                                                  audit_actions_groups=audit_actions_groups,
                                                                  is_azure_monitor_target_enabled=is_azure_monitor_target_enabled,
                                                                  is_storage_secondary_key_in_use=is_storage_secondary_key_in_use,
                                                                  queue_delay_ms=queue_delay_ms,
                                                                  retention_days=retention_days,
                                                                  storage_account_access_key=storage_account_access_key,
                                                                  storage_account_subscription_id=storage_account_subscription_id,
                                                                  storage_endpoint=storage_endpoint)
    fixed_response = copy.deepcopy(raw_response)
    if properties := fixed_response.get('properties', {}):
        fixed_response.update(properties)
        del fixed_response['properties']

    human_readable = tableToMarkdown(name='Create Or Update Database Auditing Settings', t=fixed_response,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DbAuditPolicy',
        outputs_key_field='id',
        outputs=fixed_response,
        raw_response=raw_response
    )


@logger
def azure_sql_db_threat_policy_get_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """azure_sql_db_threat_policy_get command returns a threat detection policy of a database

    Args:
        client: AzureSQLManagement Client to use
        server_name: server name for which we want to receive threat detection policies
        db_name: database for which we want to receive threat detection policies

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a threat detection policy of a database
    """
    server_name = args.get('server_name')
    db_name = args.get('db_name')
    threat_raw = client.azure_sql_db_threat_policy_get(server_name, db_name)
    threat_fixed = copy.deepcopy(threat_raw)

    if properties := threat_fixed.get('properties', {}):
        threat_fixed.update(properties)
        del threat_fixed['properties']

    human_readable = tableToMarkdown(name='Database Threat Detection Policies', t=threat_fixed,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBThreatPolicy',
        outputs_key_field='id',
        outputs=threat_fixed,
        raw_response=threat_raw
    )


@logger
def azure_sql_db_threat_policy_create_update_command(client: Client, args: Dict[str, str]) -> CommandResults:
    """azure_sql_db_audit_policy_create_update command upadates and creates threat policy related to the server
        and database

        Args:
            client: AzureSQLManagement Client to use
            server_name: server name for which we want to create or update auditing settings
            db_name: database for which we want to create or update auditing settings
            state: satate of the policy
            disabled_alerts: Comma-separated list of alerts that are disabled, or "none" to
            disable no alerts.
            email_account_admins: The alert is sent to the account administrators.
            email_addresses: Comma-separated list of e-mail addresses to which the alert is
            sent.
            retention_days: Number of days to keep the policy in the audit logs.
            storage_account_access_key: identifier key of the auditing storage account
            use_server_default: Whether to use the default server policy or not.
            storage_endpoint: Storage endpoint.

        Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains an updated threat policy

        """
    server_name = args['server_name']
    db_name = args['db_name']
    state = args['state']
    retention_days = args.get('retention_days', '')
    email_account_admins = args.get('email_account_admins', '')
    email_addresses = argToList(args.get('email_addresses', ''))
    storage_account_access_key = args.get('storage_account_access_key', '')
    use_server_default = args.get('use_server_default', '')
    storage_endpoint = args.get('storage_endpoint', '')
    disabled_alerts = [""] if 'None' in argToList(args.get('disabled_alerts', '')) \
        else argToList(args.get('disabled_alerts', ''))

    raw_response = client.azure_sql_db_threat_policy_create_update(server_name=server_name, db_name=db_name,
                                                                   state=state,
                                                                   retention_days=retention_days,
                                                                   disabled_alerts=disabled_alerts,
                                                                   email_account_admins=email_account_admins,
                                                                   email_addresses=email_addresses,
                                                                   storage_account_access_key=storage_account_access_key,
                                                                   use_server_default=use_server_default,
                                                                   storage_endpoint=storage_endpoint)
    fixed_response = copy.deepcopy(raw_response)
    if properties := fixed_response.get('properties', {}):
        fixed_response.update(properties)
        del fixed_response['properties']

    human_readable = tableToMarkdown(name='Create Or Update Database Threat Detection Policies', t=fixed_response,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBThreatPolicy',
        outputs_key_field='id',
        outputs=fixed_response,
        raw_response=raw_response
    )


@logger
def test_connection(client: Client) -> CommandResults:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


@logger
def start_auth(client: Client) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!azure-sql-auth-complete** command in the War Room.""")


@logger
def complete_auth(client: Client) -> CommandResults:
    client.ms_client.get_access_token()
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def reset_auth(client: Client) -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. You can now run '
                                          '**!azure-sql-auth-start** and **!azure-sql-auth-complete**.')


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        if command == 'test-module':
            return_error(
                'Please run `!azure-sql-auth-start` and `!azure-sql-auth-complete` to log in. '
                'You can validate the connection by running `!azure-sql-auth-test`\n '
                'For more details press the (?) button.')

        elif command == 'azure-sql-servers-list':
            return_results(azure_sql_servers_list_command(client, args))

        elif command == 'azure-sql-db-list':
            return_results(azure_sql_db_list_command(client, args))

        elif command == 'azure-sql-db-audit-policy-list':
            return_results(azure_sql_db_audit_policy_list_command(client, args))

        elif command == 'azure-sql-db-audit-policy-create-update':
            return_results(azure_sql_db_audit_policy_create_update_command(client, args))

        elif command == 'azure-sql-db-threat-policy-get':
            return_results(azure_sql_db_threat_policy_get_command(client, args))

        elif command == 'azure-sql-db-threat-policy-create-update':
            return_results(azure_sql_db_threat_policy_create_update_command(client, args))

        elif command == 'azure-sql-auth-start':
            return_results(start_auth(client))

        elif command == 'azure-sql-auth-complete':
            return_results(complete_auth(client))

        elif command == 'azure-sql-auth-reset':
            return_results(reset_auth(client))

        elif command == 'azure-sql-auth-test':
            return_results(test_connection(client))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from MicrosoftApiModule import *  # noqa: E402

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
