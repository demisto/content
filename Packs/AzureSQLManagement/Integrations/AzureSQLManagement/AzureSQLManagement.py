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
        arg_list = {
            "state": state,
            "auditActionsAndGroups": audit_actions_groups,
            "isAzureMonitorTargetEnabled": is_azure_monitor_target_enabled,
            "isStorageSecondaryKeyInUse": is_storage_secondary_key_in_use,
            "queueDelayMs": queue_delay_ms,
            "retentionDays": retention_days,
            "storageAccountAccessKey": storage_account_access_key,
            "storageAccountSubscriptionId": storage_account_subscription_id,
            "storageEndpoint": storage_endpoint
        }
        properties = {}
        for arg_key, arg_val in arg_list.items():
            if arg_val:
                properties[arg_key] = arg_val

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
        arg_list = {
            "state": state,
            "retentionDays": retention_days,
            "storageAccountAccessKey": storage_account_access_key,
            "storageEndpoint": storage_endpoint,
            "disabledAlerts": disabled_alerts,
            "emailAccountAdmins": email_account_admins,
            "emailAddresses": email_addresses,
            "useServerDefault": use_server_default
        }
        properties = {}
        for arg_key, arg_val in arg_list.items():
            if arg_val:
                properties[arg_key] = arg_val

        request_body = {'properties': properties} if properties else {}

        return self.http_request(method='PUT', url_suffix=f'resourceGroups/{self.resource_group_name}/providers'
                                                          f'/Microsoft.Sql/servers/{server_name}/databases/'
                                                          f'{db_name}/securityAlertPolicies/default',
                                 data=request_body)


@logger
def azure_sql_servers_list_command(client: Client) -> CommandResults:
    """azure-sql-servers-list command: Returns a list of all servers

    :type client: ``Client``
    :param client: AzureSQLManagement client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``
    """

    server_list = client.azure_sql_servers_list()
    server_list_values = copy.deepcopy(server_list.get('value', ''))
    for server in server_list_values:
        properties = server.get('properties', {})
        if properties:
            server.update(properties)
            del server['properties']

    human_readable = tableToMarkdown(name='Servers List', t=server_list_values,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.Server',
        outputs_key_field='id',
        outputs=server_list_values,
        raw_response=server_list
    )


@logger
def azure_sql_db_list_command(client: Client, server_name: str) -> CommandResults:
    """azure-sql-db-list command: Returns a list of all databases for server

    :type client: ``Client``
    :param client: AzureSQLManagement client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``

    Args:
        server_name: server name for which we want to receive list of databases
    """

    database_list = client.azure_sql_db_list(server_name)
    database_list_values = copy.deepcopy(database_list.get('value', ''))
    for db in database_list_values:
        properties = db.get('properties', {})
        if properties:
            db.update(properties)
            del db['properties']

    human_readable = tableToMarkdown(name='Database List', t=database_list_values,
                                     headers=[key for key in database_list_values[0] if key != 'sku' and key != 'currentSku'],
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DB',
        outputs_key_field='id',
        outputs=database_list_values,
        raw_response=database_list
    )


@logger
def azure_sql_db_audit_policy_list_command(client: Client, server_name: str, db_name: str) -> CommandResults:
    """azure_sql_db_audit_policy_list command: Returns a list of auditing settings of a database

    :type client: ``Client``
    :param client: AzureSQLManagement client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``

    Args:
        server_name: server name for which we want to receive list of auditing settings
        db_name: database for which we want to receive list of auditing settings
    """

    audit_list = client.azure_sql_db_audit_policy_list(server_name, db_name)
    audit_list_values = copy.deepcopy(audit_list.get('value', ''))
    for db in audit_list_values:
        properties = db.get('properties', {})
        if properties:
            db.update(properties)
            del db['properties']

    human_readable = tableToMarkdown(name='Database Audit Settings', t=audit_list_values,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DbAuditPolicy',
        outputs_key_field='id',
        outputs=audit_list_values,
        raw_response=audit_list
    )


@logger
def azure_sql_db_audit_policy_create_update_command(client: Client, server_name: str, db_name: str,
                                                    state: str, audit_actions_groups: str = None,
                                                    is_azure_monitor_target_enabled: str = None,
                                                    is_storage_secondary_key_in_use: str = None,
                                                    queue_delay_ms: str = None,
                                                    retention_days: str = None, storage_account_access_key: str = None,
                                                    storage_account_subscription_id: str = None,
                                                    storage_endpoint: str = None) -> CommandResults:
    """azure_sql_db_audit_policy_create_update command: Upadate and create audit policies related to the server
    and database

    :type client: ``Client``
    :param client: AzureSQLManagement client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``

    Args:
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

    """

    audit_actions_groups = audit_actions_groups if not audit_actions_groups else argToList(audit_actions_groups)
    is_azure_monitor_target_enabled = is_azure_monitor_target_enabled if not is_azure_monitor_target_enabled \
        else argToBoolean(is_azure_monitor_target_enabled)
    is_storage_secondary_key_in_use = is_storage_secondary_key_in_use if not is_storage_secondary_key_in_use \
        else argToBoolean(is_storage_secondary_key_in_use)

    response = client.azure_sql_db_audit_policy_create_update(server_name=server_name, db_name=db_name, state=state,
                                                              audit_actions_groups=audit_actions_groups,
                                                              is_azure_monitor_target_enabled=is_azure_monitor_target_enabled,
                                                              is_storage_secondary_key_in_use=is_storage_secondary_key_in_use,
                                                              queue_delay_ms=queue_delay_ms,
                                                              retention_days=retention_days,
                                                              storage_account_access_key=storage_account_access_key,
                                                              storage_account_subscription_id=storage_account_subscription_id,
                                                              storage_endpoint=storage_endpoint)
    response_hr = copy.deepcopy(response)
    properties = response_hr.get('properties', {})
    if properties:
        response_hr.update(properties)
        del response_hr['properties']

    human_readable = tableToMarkdown(name='Create Or Update Database Auditing Settings', t=response_hr,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DbAuditPolicy',
        outputs_key_field='id',
        outputs=response_hr,
        raw_response=response
    )


@logger
def azure_sql_db_threat_policy_get_command(client: Client, server_name: str, db_name: str) -> CommandResults:
    """azure_sql_db_threat_policy_get command: Returns a threat detection policies of a database

    :type client: ``Client``
    :param client: AzureSQLManagement client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``

    Args:
        server_name: server name for which we want to receive threat detection policies
        db_name: database for which we want to receive threat detection policies
    """

    threat_list = client.azure_sql_db_threat_policy_get(server_name, db_name)
    threat = copy.deepcopy(threat_list)

    properties = threat.get('properties', {})
    if properties:
        threat.update(properties)
        del threat['properties']

    human_readable = tableToMarkdown(name='Database Threat Detection Policies', t=threat,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBThreatPolicy',
        outputs_key_field='id',
        outputs=threat,
        raw_response=threat_list
    )


@logger
def azure_sql_db_threat_policy_create_update_command(client: Client, server_name: str, db_name: str,
                                                     state: str, disabled_alerts: str = '',
                                                     email_account_admins: str = '',
                                                     email_addresses: str = '',
                                                     retention_days: str = '', storage_account_access_key: str = '',
                                                     use_server_default: str = '',
                                                     storage_endpoint: str = '') -> CommandResults:
    """azure_sql_db_audit_policy_create_update command: Upadate and create audit policies related to the server
        and database

        :type client: ``Client``
        :param client: AzureSQLManagement client to use

        :return:
            A ``CommandResults`` object that is then passed to ``return_results``,
            that contains a scan status

        :rtype: ``CommandResults``

        Args:
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

        """
    disabled_alerts_list: List[str] = []
    if disabled_alerts:
        disabled_alerts_list = argToList(disabled_alerts)
        if disabled_alerts_list[0] == 'none':
            disabled_alerts_list = [""]
    email_addresses = email_addresses if not email_addresses else argToList(email_addresses)

    response = client.azure_sql_db_threat_policy_create_update(server_name=server_name, db_name=db_name, state=state,
                                                               disabled_alerts=disabled_alerts_list,
                                                               email_account_admins=email_account_admins,
                                                               email_addresses=email_addresses,
                                                               retention_days=retention_days,
                                                               storage_account_access_key=storage_account_access_key,
                                                               use_server_default=use_server_default,
                                                               storage_endpoint=storage_endpoint)
    response_hr = copy.deepcopy(response)
    properties = response_hr.get('properties', {})
    if properties:
        response_hr.update(properties)
        del response_hr['properties']

    human_readable = tableToMarkdown(name='Create Or Update Database Threat Detection Policies', t=response_hr,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBThreatPolicy',
        outputs_key_field='id',
        outputs=response_hr,
        raw_response=response
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
        commands = {
            'azure-sql-servers-list': azure_sql_servers_list_command,
            'azure-sql-db-list': azure_sql_db_list_command,
            'azure-sql-db-audit-policy-list': azure_sql_db_audit_policy_list_command,
            'azure-sql-db-audit-policy-create-update': azure_sql_db_audit_policy_create_update_command,
            'azure-sql-db-threat-policy-get': azure_sql_db_threat_policy_get_command,
            'azure-sql-db-threat-policy-create-update': azure_sql_db_threat_policy_create_update_command,
            'azure-sql-auth-start': start_auth,
            'azure-sql-auth-complete': complete_auth,
            'azure-sql-auth-reset': reset_auth,
        }
        if command == 'test-module':
            return_error("Please run `!azure-sql-auth-start` and `!azure-sql-auth-complete` to log in."
                         " For more details press the (?) button.")

        if command == 'azure-sql-auth-test':
            return_results(test_connection(client))
        else:
            return_results(commands[command](client, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from MicrosoftApiModule import *  # noqa: E402

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
