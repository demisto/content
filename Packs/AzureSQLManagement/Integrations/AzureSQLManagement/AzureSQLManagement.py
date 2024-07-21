import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *

import urllib3
import copy
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2021-11-01'
''' CLIENT CLASS '''


class Client:
    """Client class to interact with the service API
    """

    @logger
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy, auth_type, tenant_id=None,
                 enc_key=None, auth_code=None, redirect_uri=None, azure_ad_endpoint='https://login.microsoftonline.com',
                 managed_identities_client_id=None):
        self.resource_group_name = resource_group_name
        AUTH_TYPES_DICT: dict = {
            'Authorization Code': {
                'grant_type': AUTHORIZATION_CODE,
                'resource': None,
                'scope': 'https://management.azure.com/.default'
            },
            'Device Code': {
                'grant_type': DEVICE_CODE,
                'resource': 'https://management.core.windows.net',
                'scope': 'https://management.azure.com/user_impersonation offline_access user.read'
            },
            'Client Credentials': {
                'grant_type': CLIENT_CREDENTIALS,
                'resource': None,
                'scope': 'https://management.azure.com/.default'
            }
        }
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}'
        client_args = assign_params(
            self_deployed=True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token' if 'Device Code' in
                                                                                                       auth_type else None,
            grant_type=AUTH_TYPES_DICT.get(auth_type, {}).get('grant_type'),  # disable-secrets-detection
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            resource=AUTH_TYPES_DICT.get(auth_type, {}).get('resource'),  # disable-secrets-detection
            scope=AUTH_TYPES_DICT.get(auth_type, {}).get('scope'),
            ok_codes=(200, 201, 202, 204),
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            azure_ad_endpoint=azure_ad_endpoint,
            tenant_id=tenant_id,
            enc_key=enc_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-sql",
        )
        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = {},
                     data: dict = None, resp_type: str = 'json') -> requests.Response:
        if not full_url:
            params['api-version'] = API_VERSION

        try:
            return self.ms_client.http_request(method=method,
                                               url_suffix=url_suffix,
                                               full_url=full_url,
                                               json_data=data,
                                               params=params,
                                               resp_type=resp_type)
        except DemistoException as e:
            if 'Error in API call [404] - Not Found' not in e.message:
                raise DemistoException(e)
            message = e.message.split('"message":')[1].split('"')[1]
            return message

    @logger
    def azure_sql_servers_list(self, resource_group_name: str = None):
        if resource_group_name:
            return self.http_request('GET', f'/resourceGroups/{resource_group_name}/providers/Microsoft.Sql/servers')
        return self.http_request('GET', '/providers/Microsoft.Sql/servers')

    @logger
    def azure_sql_db_list(self, server_name: str):
        return self.http_request('GET', f'resourceGroups/{self.resource_group_name}/providers/Microsoft.Sql/servers/'
                                        f'{server_name}/databases')

    @logger
    def azure_sql_db_audit_policy_list(self, server_name: str, db_name: str, resource_group_name: str):
        return self.http_request('GET', f'resourceGroups/{resource_group_name}/providers/Microsoft.Sql/servers/'
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
                                                storage_endpoint: str,
                                                is_managed_identity_in_use: bool,
                                                resource_group_name: str):
        properties = assign_params(state=state, auditActionsAndGroups=audit_actions_groups,
                                   isAzureMonitorTargetEnabled=is_azure_monitor_target_enabled,
                                   isStorageSecondaryKeyInUse=is_storage_secondary_key_in_use,
                                   queueDelayMs=queue_delay_ms,
                                   retentionDays=retention_days,
                                   storageAccountAccessKey=storage_account_access_key,
                                   storageAccountSubscriptionId=storage_account_subscription_id,
                                   storageEndpoint=storage_endpoint,
                                   isManagedIdentityInUse=is_managed_identity_in_use)

        request_body = {'properties': properties} if properties else {}

        return self.http_request(method='PUT', url_suffix=f'resourceGroups/{resource_group_name}/providers'
                                                          f'/Microsoft.Sql/servers/{server_name}/databases/'
                                                          f'{db_name}/auditingSettings/default',
                                 data=request_body)

    def azure_sql_db_threat_policy_create_update(self, server_name: str, db_name: str, state: str,
                                                 disabled_alerts: List[str], email_account_admins: str,
                                                 email_addresses: List[str], retention_days: str,
                                                 storage_account_access_key: str,
                                                 use_server_default: str, storage_endpoint: str,
                                                 resource_group_name: str):
        properties = assign_params(state=state,
                                   retentionDays=retention_days,
                                   storageAccountAccessKey=storage_account_access_key,
                                   storageEndpoint=storage_endpoint,
                                   disabledAlerts=disabled_alerts,
                                   emailAccountAdmins=email_account_admins,
                                   emailAddresses=email_addresses,
                                   useServerDefault=use_server_default)

        request_body = {'properties': properties} if properties else {}

        return self.http_request(method='PUT', url_suffix=f'resourceGroups/{resource_group_name}/providers'
                                                          f'/Microsoft.Sql/servers/{server_name}/databases/'
                                                          f'{db_name}/securityAlertPolicies/default',
                                 data=request_body)

    def subscriptions_list_request(self):
        """ Gets all subscriptions for a tenant.e.
        Returns:
            A dictionary that contains the list of subscription.
        """
        return self.http_request(method='GET', full_url='https://management.azure.com/subscriptions?api-version=2020-01-01')

    def resource_group_list_request(self, sub_id: str, tag: str, limit: int):
        """ Gets all the resource groups for a subscription.
        Args:
            sub_id: str - A subscription id.
            tag: str - The tag and value that attached to the resource group.
            limit: int - The number of results to return.
        Returns:
            A dictionary that contains the list of resource groups for the given subscription id.
        """
        full_url = f'https://management.azure.com/subscriptions/{sub_id}/resourcegroups?api-version=2021-04-01'
        if tag:
            tag_split = tag.split(':')
            tag_name = tag_split[0]
            tag_value = tag_split[1]
            demisto.debug(f'{tag=}, {tag_split}, {tag_name=}, {tag_value=}')
            full_url = f"{full_url}&$filter=tagName eq '{tag_name}' and tagValue eq '{tag_value}'"
        if limit:
            full_url = f'{full_url}&$top={limit}'
        return self.http_request(method='GET', full_url=full_url)


@logger
def azure_sql_servers_list_command(client: Client, args: Dict[str, str], resource_group_name: str) -> CommandResults:
    """azure-sql-servers-list command returns a list of all servers

    Args:
        client: AzureSQLManagement Client to use
        limit: The maximum number of servers returned to the War Room. Default is 50.
        offset: Offset in the data set. Default is 0.
        resource_group_name: str - The name of the resource group that contains the resource.
    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a list of all servers
    """
    offset_int = int(args.get('offset', '0'))
    limit_int = int(args.get('limit', '50'))
    list_by_resource_group = argToBoolean(args.get('list_by_resource_group', False))

    if list_by_resource_group:
        server_list_raw = client.azure_sql_servers_list(resource_group_name)
        name = f'The list of servers in the resource group: {resource_group_name}'
    else:
        server_list_raw = client.azure_sql_servers_list()
        name = 'Servers List'

    if isinstance(server_list_raw, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=server_list_raw)

    server_list_fixed = copy.deepcopy(server_list_raw.get('value', '')[offset_int:(offset_int + limit_int)])
    for server in server_list_fixed:
        if properties := server.get('properties', {}):
            server.update(properties)
            del server['properties']

    human_readable = tableToMarkdown(name=name, t=server_list_fixed,
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

    if isinstance(database_list_raw, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=database_list_raw)

    database_list_fixed = copy.deepcopy(database_list_raw.get('value', '')[offset_int:(offset_int + limit_int)])

    for db in database_list_fixed:
        properties = db.get('properties', {})
        if properties:
            db.update(properties)
            del db['properties']

    human_readable = tableToMarkdown(name='Database List', t=database_list_fixed,
                                     headers=['name', 'location', 'status', 'managedBy'],
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DB',
        outputs_key_field='id',
        outputs=database_list_fixed,
        raw_response=database_list_raw
    )


@logger
def azure_sql_db_audit_policy_list_command(client: Client, args: Dict[str, str], resource_group_name: str) -> CommandResults:
    """azure_sql_db_audit_policy_list command returns a list of auditing settings of a database

    Args:
        client: AzureSQLManagement Client to use
        server_name: server name for which we want to receive list of auditing settings
        db_name: database for which we want to receive list of auditing settings
        limit: The maximum number of audit policies returned to the War Room. Default
        is 50.
        offset: Offset in the data set. Default is 0.
        resource_group_name: The name of the resource group that contains the resource.

    Returns:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a list of auditing settings of a database

    """
    server_name = args.get('server_name')
    db_name = args.get('db_name')
    offset_int = int(args.get('offset', '0'))
    limit_int = int(args.get('limit', '50'))

    audit_list_raw = client.azure_sql_db_audit_policy_list(server_name, db_name, resource_group_name)

    if isinstance(audit_list_raw, str):  # if there is 404 then, error message will return
        return CommandResults(readable_output=audit_list_raw)

    audit_list_fixed = copy.deepcopy(audit_list_raw.get('value', '')[offset_int:(offset_int + limit_int)])
    for db in audit_list_fixed:
        db['serverName'] = server_name
        db['databaseName'] = db_name
        if properties := db.get('properties', {}):
            db.update(properties)
            del db['properties']

    human_readable = tableToMarkdown(name=f'Database Audit Settings for {resource_group_name=}', t=audit_list_fixed,
                                     headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBAuditPolicy',
        outputs_key_field='id',
        outputs=audit_list_fixed,
        raw_response=audit_list_raw
    )


@logger
def azure_sql_db_audit_policy_create_update_command(client: Client, args: Dict[str, str], resource_group_name: str) \
        -> CommandResults:
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
        resource_group_name: The name of the resource group that contains the resource.

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
    is_managed_identity_in_use = args.get('is_managed_identity_in_use', '')

    raw_response = client.azure_sql_db_audit_policy_create_update(server_name=server_name, db_name=db_name, state=state,
                                                                  audit_actions_groups=audit_actions_groups,
                                                                  is_azure_monitor_target_enabled=is_azure_monitor_target_enabled,
                                                                  is_storage_secondary_key_in_use=is_storage_secondary_key_in_use,
                                                                  queue_delay_ms=queue_delay_ms,
                                                                  retention_days=retention_days,
                                                                  storage_account_access_key=storage_account_access_key,
                                                                  storage_account_subscription_id=storage_account_subscription_id,
                                                                  storage_endpoint=storage_endpoint,
                                                                  is_managed_identity_in_use=is_managed_identity_in_use,
                                                                  resource_group_name=resource_group_name)

    if isinstance(raw_response, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=raw_response)

    fixed_response = copy.deepcopy(raw_response)
    if properties := fixed_response.get('properties', {}):
        fixed_response['serverName'] = server_name
        fixed_response['databaseName'] = db_name
        fixed_response.update(properties)
        del fixed_response['properties']

    human_readable = tableToMarkdown(name=f'Create Or Update Database Auditing Settings for {resource_group_name=}',
                                     t=fixed_response, headerTransform=pascalToSpace, removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBAuditPolicy',
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

        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a threat detection policy of a database
    """
    server_name = args.get('server_name')
    db_name = args.get('db_name')
    threat_raw = client.azure_sql_db_threat_policy_get(server_name, db_name)

    if isinstance(threat_raw, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=threat_raw)

    threat_fixed = copy.deepcopy(threat_raw)

    if properties := threat_fixed.get('properties', {}):
        threat_fixed['serverName'] = server_name
        threat_fixed['databaseName'] = db_name
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
def azure_sql_db_threat_policy_create_update_command(client: Client, args: Dict[str, str], resource_group_name: str) \
        -> CommandResults:
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
            resource_group_name: The name of the resource group that contains the resource.

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
                                                                   storage_endpoint=storage_endpoint,
                                                                   resource_group_name=resource_group_name)

    if isinstance(raw_response, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=raw_response)

    fixed_response = copy.deepcopy(raw_response)
    if properties := fixed_response.get('properties', {}):
        fixed_response['serverName'] = server_name
        fixed_response['databaseName'] = db_name
        fixed_response.update(properties)
        del fixed_response['properties']

    human_readable = tableToMarkdown(name=f'Create Or Update Database Threat Detection Policies for '
                                          f'{resource_group_name=}',
                                     t=fixed_response,
                                     headerTransform=pascalToSpace,
                                     removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.DBThreatPolicy',
        outputs_key_field='id',
        outputs=fixed_response,
        raw_response=raw_response
    )


def subscriptions_list_command(client: Client) -> CommandResults:
    """Gets all subscriptions for a tenant.
    Args:
        client: AzureSQLManagement Client to use.
    Returns:
    A ``CommandResults`` object that is then passed to ``return_results``,
    that contains all the subscriptions for a tenant.
    """
    response = client.subscriptions_list_request()

    if isinstance(response, str):  # if there is 404, an error message will return
        return CommandResults(readable_output=response)

    response = response.get('value', [{}])
    readable_output_table = []
    for result in response:
        d = {
            'Subscription Id': result.get('subscriptionId'),
            'Tenant Id': result.get('tenantId'),
            'State': result.get('state'),
            'Name': result.get('displayName')
        }
        readable_output_table.append(d)
    headers = ['Subscription Id', 'Name', 'Tenant Id', 'State']
    human_readable = tableToMarkdown(name='Subscription List',
                                     t=readable_output_table,
                                     removeNull=True,
                                     headers=headers)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='AzureSQL.Subscription',
        outputs=response,
        raw_response=response,
        outputs_key_field='subscriptionId'
    )


def resource_group_list_command(client: Client, args: Dict, subscriptions_id: List) -> List:
    """Gets all subscriptions for a tenant.
    Args:
        client: Client - AzureSQLManagement Client to use.
        args: Dict - The command arguments.
        subscriptions_id: List - A list of subscription ids.
    Returns:
    A ``CommandResults`` object that is then passed to ``return_results``,
    that contains all the subscriptions for a tenant.
    """
    tag = args.get('tag', '')
    limit = arg_to_number(args.get('limit')) or 50

    results = []
    for sub_id in subscriptions_id:
        response = client.resource_group_list_request(sub_id, tag, limit)
        demisto.debug(f'{response=}')

        if isinstance(response, str):  # if there is 404, an error message will return
            result_message = CommandResults(readable_output=response)
            results.append(result_message)

        else:
            response = response.get('value', [{}])
            readable_output_table = []
            for result in response:
                d = {
                    'Name': result.get('name'),
                    'Location': result.get('location'),
                    'Tags': result.get('tags'),
                    'Provisioning State': result.get('properties', {}).get('provisioningState')
                }
                readable_output_table.append(d)
            headers = ['Name', 'Location', 'Tags', 'Provisioning State']
            human_readable = tableToMarkdown(name=f'Resource Group List for {sub_id}',
                                             t=readable_output_table,
                                             removeNull=True,
                                             headers=headers)
            command_result = CommandResults(
                readable_output=human_readable,
                outputs_prefix='AzureSQL.ResourceGroup',
                outputs=response,
                raw_response=response,
                outputs_key_field='id'
            )
            results.append(command_result)
    return results


@logger
def test_connection(client: Client) -> CommandResults:
    if demisto.params().get('auth_type') == 'Device Code':
        client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    else:
        client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


@logger
def start_auth(client: Client) -> CommandResults:  # pragma: no cover
    result = client.ms_client.start_auth('!azure-sql-auth-complete')
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: Client) -> CommandResults:  # pragma: no cover
    client.ms_client.get_access_token()
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def test_module(client):
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns ok if successful.
    """
    params = demisto.params()
    if params.get('auth_type') == 'Device Code':
        raise Exception("When using device code flow configuration, "
                        "Please enable the integration and run `!azure-sql-auth-start` and `!azure-sql-auth-complete` to "
                        "log in. You can validate the connection by running `!azure-sql-auth-test`\n"
                        "For more details press the (?) button.")

    elif params.get('auth_type') == 'Authorization Code':
        raise Exception("When using user auth flow configuration, "
                        "Please enable the integration and run the !azure-sql-auth-test command in order to test it")
    elif params.get('auth_type') == 'Azure Managed Identities' or params.get('auth_type') == 'Client Credentials':
        client.ms_client.get_access_token()
        return 'ok'
    return None


def command_with_multiple_resource_group_name(client: Client, args: Dict, command: str, resource_group_name: List) -> List:
    """Manage commands that can have multiple resource_group_name.
    Args:
        client: Client - Azure SQL management client.
        args: Dict - The arguments to the command.
        command: str - the name of the command
        resource_group_name: List - A list of the resource group names

    Returns:
        A list of CommandResults objects that is then passed to ``return_results``,
        that contains the results of the relevant command.
    """
    results = []
    for name in resource_group_name:
        if command == 'azure-sql-db-audit-policy-create-update':
            result = azure_sql_db_audit_policy_create_update_command(client, args, name)
        elif command == 'azure-sql-servers-list':
            result = azure_sql_servers_list_command(client, args, name)
        elif command == 'azure-sql-db-threat-policy-create-update':
            result = azure_sql_db_threat_policy_create_update_command(client, args, name)
        else:  # command == 'azure-sql-db-audit-policy-list':
            result = azure_sql_db_audit_policy_list_command(client, args, name)
        results.append(result)
    return results


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        subscription_id = argToList(args.get('subscription_id')) or [params.get('subscription_id', '')]
        resource_group_name = argToList(args.get('resource_group_name')) or [params.get('resource_group_name', '')]
        client = Client(
            tenant_id=params.get('tenant_id', ''),
            auth_type=params.get('auth_type', 'Device Code'),
            auth_code=params.get('auth_code', {}).get('password', ''),
            redirect_uri=params.get('redirect_uri', ''),
            enc_key=params.get('credentials', {}).get('password', ''),
            app_id=params.get('app_id', ''),
            subscription_id=subscription_id[0],
            resource_group_name=resource_group_name[0],
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com',
            managed_identities_client_id=get_azure_managed_identities_client_id(params)
        )
        commands_with_multiple_resource_group_name_list = ['azure-sql-servers-list',
                                                           'azure-sql-db-audit-policy-list',
                                                           'azure-sql-db-audit-policy-create-update',
                                                           'azure-sql-db-threat-policy-create-update']

        if command == 'test-module':
            return_results(test_module(client))

        elif command in commands_with_multiple_resource_group_name_list:
            return_results(command_with_multiple_resource_group_name(client, args, command, resource_group_name))

        elif command == 'azure-sql-db-list':
            return_results(azure_sql_db_list_command(client, args))

        elif command == 'azure-sql-db-threat-policy-get':
            return_results(azure_sql_db_threat_policy_get_command(client, args))

        elif command == 'azure-sql-auth-start':
            return_results(start_auth(client))

        elif command == 'azure-sql-auth-complete':
            return_results(complete_auth(client))

        elif command == 'azure-sql-auth-reset':
            return_results(reset_auth())

        elif command == 'azure-sql-auth-test':
            return_results(test_connection(client))

        elif command == 'azure-sql-generate-login-url':
            return_results(generate_login_url(client.ms_client))

        elif command == 'azure-sql-subscriptions-list':
            return_results(subscriptions_list_command(client))

        elif command == 'azure-sql-resource-group-list':
            return_results(resource_group_list_command(client, args, subscription_id))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
