Microsoft Azure SQL Management Integration manages the Auditing and Threat Policies for Azure SQL.

> <i>Note:</i> The integration is in ***beta*** as it uses a preview version of the Azure SQL Database API. The stable Azure SQL Database API version does not contain all required endpoints used in some of the integration commands.

# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

The application must have *user_impersonation* permission and must allow public client flows (found under the **Authentication** section of the app). And must allow public client flows (found under the **Authentication** section of the app) for Device-code based authentications.

## Authentication Using the  User-Authentication Flow (recommended)

Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. choose the 'User Auth' option in the ***Authentication Type*** parameter.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
7. Enter your Authorization code in the ***Authorization code*** parameter.
8. Save the instance.
9. Run the ***!azure-sql-auth-test*** command - a 'Success' message should be printed to the War Room.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (8f9010bb-4efe-4cfa-a197-98a2694b7e0c).

You only need to fill in your subscription ID and resource group name. You can find your resource group and 
subscription ID in the Azure Portal. For a more detailed explanation, visit [this page](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

### Authentication Using the Device Code Flow
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure SQL Management with Cortex XSOAR.

Follow these steps for a self-deployed configuration:
1. Fill in the required parameters.
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
3. Run the ***!azure-sql-auth-start*** command. 
4. Follow the instructions that appear.
5. Run the ***!azure-sql-auth-complete*** command.

## Configure Azure SQL Management on Cortex XSOAR

In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure SQL Management using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
   
    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID |  | True |
    | Subscription ID |  | True |
    | Resource Group Name |  | True |
    | Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Tenant ID (for User Auth mode) | Tenant ID | False |
    | Client Secret (for User Auth mode) | Encryption key given by the admin | False |
    | Authentication Type | The request authentication type for the instance | False |
    | Authorization code | as received from the authorization step | False |
    | Application redirect URI | the redirect URI entered in the Azure portal | False |

At the end of the process you'll see a message that you've logged in successfully.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-sql-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.


#### Base Command

`azure-sql-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-sql-auth-start```

#### Human Readable Output

>### Authorization instructions
>1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
> and enter the code **CODECODE** to authenticate.
>2. Run the ***!azure-sql-auth-complete*** command in the War Room.

### azure-sql-auth-complete
***
Run this command to complete the authorization process. Should be used after running the ***azure-sql-auth-start*** command.


#### Base Command

`azure-sql-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-nsg-auth-complete```

#### Human Readable Output

>✅ Authorization completed successfully.

### azure-sql-auth-reset
***
Run this command if you need to rerun the authentication process.


#### Base Command

`azure-sql-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-sql-auth-reset```

#### Human Readable Output

>Authorization was reset successfully. You can now run ***!azure-sql-auth-start*** and ***!azure-sql-auth-complete***.

### azure-sql-auth-test
***
Tests the connectivity to the Azure SQL Management.


#### Base Command

`azure-sql-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-sql-auth-test```

#### Human Readable Output

>✅ Success!

### azure-sql-servers-list
***
Lists all the servers.


#### Base Command

`azure-sql-servers-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of servers returned to the War Room. Default is 50. | Optional | 
| offset | Offset in the data set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.Server | Unknown | Server list. | 
| AzureSQL.Server.kind | String | Kind of server. | 
| AzureSQL.Server.location | String | Server location. | 
| AzureSQL.Server.tags | Unknown | Server Tags. | 
| AzureSQL.Server.id | String | Server ID. | 
| AzureSQL.Server.name | String | Server name. | 
| AzureSQL.Server.type | String | Server type. | 
| AzureSQL.Server.administratorLogin | String | Username of the server administrator. | 
| AzureSQL.Server.version | String | Server version. | 
| AzureSQL.Server.state | String | Server state. | 
| AzureSQL.Server.fullyQualifiedDomainName | Unknown | Fully qualified domain name of the server. | 
| AzureSQL.Server.privateEndpointConnections | Unknown | List of private endpoint connections of the server. | 
| AzureSQL.Server.publicNetworkAccess | String | Whether the public endpoint access of the server is enabled. The value is 'Enabled' or 'Disabled'. | 


#### Command Example
```!azure-sql-servers-list```

#### Context Example
```json
{
    "AzureSQL": {
        "Server": {
            "administratorLogin": "xsoaradmin",
            "fullyQualifiedDomainName": "sqlintegration.database.windows.net",
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration",
            "kind": "v12.0",
            "location": "eastus",
            "name": "sqlintegration",
            "privateEndpointConnections": [],
            "publicNetworkAccess": "Enabled",
            "state": "Ready",
            "tags": {},
            "type": "Microsoft.Sql/servers",
            "version": "12.0"
        }
    }
}
```

#### Human Readable Output

>### Servers List
>|Administrator Login|Fully Qualified Domain Name|Id|Kind|Location|Name|Public Network Access|State|Type|Version|
>|---|---|---|---|---|---|---|---|---|---|
>| xsoaradmin | sqlintegration.database.windows.net | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration | v12.0 | eastus | sqlintegration | Enabled | Ready | Microsoft.Sql/servers | 12.0 |


### azure-sql-db-list
***
Lists all of the databases for the server.


#### Base Command

`azure-sql-db-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| limit | The maximum number of databases returned to the War Room. Default is 50. | Optional | 
| offset | Offset in the data set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DB | Unknown | All databases related to the server. | 
| AzureSQL.DB.kind | String | Kind of database. | 
| AzureSQL.DB.location | String | Database location. | 
| AzureSQL.DB.id | String | Database ID. | 
| AzureSQL.DB.name | String | Database name. | 
| AzureSQL.DB.type | String | Database type. | 
| AzureSQL.DB.managedBy | String | Resource that manages the database. | 
| AzureSQL.DB.sku | Unknown | Database SKU. | 
| AzureSQL.DB.catalogCollation | String | Collation of the catalog for the database. | 
| AzureSQL.DB.collation | String | Database collation. | 
| AzureSQL.DB.creationDate | String | Creation date of the database in ISO format. | 
| AzureSQL.DB.currentServiceObjectiveName | String | Current service level objective name of the database. | 
| AzureSQL.DB.currentSku | Unknown | Name, tier, and capacity of the SKU. | 
| AzureSQL.DB.databaseID | String | Database ID. | 
| AzureSQL.DB.defaultSecondaryLocation | String | Default secondary location of the database. | 
| AzureSQL.DB.maxSizeBytes | Number | The maximum size of the database in bytes. | 
| AzureSQL.DB.readReplicaCount | Number | The number of read-only secondary replicas of the database. | 
| AzureSQL.DB.readScale | String | The read-only routing state.  "Enabled" or "Disabled". | 
| AzureSQL.DB.requestedServiceObjectiveName | String | The requested service objective name of the database.  | 
| AzureSQL.DB.status | String | Database status. | 
| AzureSQL.DB.storageAccountType | String | Database storage account type. | 
| AzureSQL.DB.zoneRedundant | Boolean | Whether the database zone is redundant. | 


#### Command Example
```!azure-sql-db-list server_name=sqlintegration```

#### Context Example
```json
{
    "AzureSQL": {
        "DB": [
            {
                "catalogCollation": "SQL_Latin1_General_CP1_CI_AS",
                "collation": "SQL_Latin1_General_CP1_CI_AS",
                "creationDate": "2020-12-15T14:29:43.72Z",
                "currentServiceObjectiveName": "System0",
                "currentSku": {
                    "capacity": 0,
                    "name": "System",
                    "tier": "System"
                },
                "databaseId": "12345ID",
                "defaultSecondaryLocation": "westus",
                "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/master",
                "kind": "v12.0,system",
                "location": "eastus",
                "managedBy": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration",
                "maxSizeBytes": 32212254720,
                "name": "master",
                "readReplicaCount": 0,
                "readScale": "Disabled",
                "requestedServiceObjectiveName": "System0",
                "sku": {
                    "capacity": 0,
                    "name": "System",
                    "tier": "System"
                },
                "status": "Online",
                "storageAccountType": "LRS",
                "type": "Microsoft.Sql/servers/databases",
                "zoneRedundant": false
            },
            {
                "catalogCollation": "SQL_Latin1_General_CP1_CI_AS",
                "collation": "SQL_Latin1_General_CP1_CI_AS",
                "creationDate": "2020-12-15T14:31:06.663Z",
                "currentServiceObjectiveName": "S0",
                "currentSku": {
                    "capacity": 10,
                    "name": "Standard",
                    "tier": "Standard"
                },
                "databaseId": "5343c264-7cf0-47c4-8cbb-1593d2337b69",
                "defaultSecondaryLocation": "westus",
                "earliestRestoreDate": "2020-12-28T00:00:00Z",
                "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db",
                "kind": "v12.0,user",
                "location": "eastus",
                "maxSizeBytes": 268435456000,
                "name": "sql-integration-db",
                "readReplicaCount": 0,
                "readScale": "Disabled",
                "requestedServiceObjectiveName": "S0",
                "sku": {
                    "capacity": 10,
                    "name": "Standard",
                    "tier": "Standard"
                },
                "status": "Online",
                "storageAccountType": "GRS",
                "tags": {},
                "type": "Microsoft.Sql/servers/databases",
                "zoneRedundant": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Database List
>|Name|Location|Status|Managed By|
>|---|---|---|---|
>| master | eastus | Online | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration |
>| sql-integration-db | eastus | Online |  |


### azure-sql-db-audit-policy-list
***
Gets the audit settings of the specified database.


#### Base Command

`azure-sql-db-audit-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 
| limit | The maximum number of DataBases audit policies returned to the War Room. Default is 50. | Optional | 
| offset | Offset in the data set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DBAuditPolicy | Unknown | List of all database audit settings. | 
| AzureSQL.DBAuditPolicy.kind | String | Kind of audit policy. | 
| AzureSQL.DBAuditPolicy.id | String | Audit policy ID. | 
| AzureSQL.DBAuditPolicy.name | String | Audit policy name. | 
| AzureSQL.DBAuditPolicy.type | String | Resource type. | 
| AzureSQL.DBAuditPolicy.isAzureMonitorTargetEnabled | Boolean | Whether audit events are sent to Azure Monitor. Possible values: "True" (Enabled) or "False" (Disabled). | 
| AzureSQL.DBAuditPolicy.retentionDays | Number | Number of days to keep in the audit logs in the storage account. | 
| AzureSQL.DBAuditPolicy.state | String | Policy state. | 
| AzureSQL.DBAuditPolicy.storageAccountSubscriptionId | String | Storage subscription ID. | 
| AzureSQL.DBAuditPolicy.databaseName | String | The name of the database that the audit policy is related to. | 
| AzureSQL.DBAuditPolicy.serverName | String | The name of the server that the audit policy is related to. | 


#### Command Example
```!azure-sql-db-audit-policy-list server_name=sqlintegration db_name=sql-integration-db```

#### Context Example
```json
{
    "AzureSQL": {
        "DBAuditPolicy": {
            "auditActionsAndGroups": [
                "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                "FAILED_DATABASE_AUTHENTICATION_GROUP",
                "BATCH_COMPLETED_GROUP"
            ],
            "databaseName": "sql-integration-db",
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default",
            "isAzureMonitorTargetEnabled": true,
            "name": "Default",
            "queueDelayMs": 123,
            "retentionDays": 3,
            "serverName": "sqlintegration",
            "state": "Enabled",
            "storageAccountSubscriptionId": "00000000-0000-0000-0000-000000000000",
            "storageEndpoint": "",
            "type": "Microsoft.Sql/servers/databases/auditingSettings"
        }
    }
}
```

#### Human Readable Output

>### Database Audit Settings
>|Audit Actions And Groups|Database Name|Id|Is Azure Monitor Target Enabled|Name|Queue Delay Ms|Retention Days|Server Name|State|Storage Account Subscription Id|Type|
>|---|---|---|---|---|---|---|---|---|---|---|
>| SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP,<br/>FAILED_DATABASE_AUTHENTICATION_GROUP,<br/>BATCH_COMPLETED_GROUP | sql-integration-db | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default | true | Default | 123 | 3 | sqlintegration | Enabled | 00000000-0000-0000-0000-000000000000 | Microsoft.Sql/servers/databases/auditingSettings |


### azure-sql-db-threat-policy-get
***
Gets the threat detection policy of the specified database.


#### Base Command

`azure-sql-db-threat-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DBThreatPolicy | Unknown | All threat policies related to the database. | 
| AzureSQL.DBThreatPolicy.kind | String | Kind of threat policy. | 
| AzureSQL.DBThreatPolicy.location | String | Threat policy location. | 
| AzureSQL.DBThreatPolicy.id | String | Threat policy ID. | 
| AzureSQL.DBThreatPolicy.name | String | Threat policy name. | 
| AzureSQL.DBThreatPolicy.type | String | Threat policy type. | 
| AzureSQL.DBThreatPolicy.state | String | Threat policy state. | 
| AzureSQL.DBThreatPolicy.creationTime | String | Threat policy creation time. | 
| AzureSQL.DBThreatPolicy.retentionDays | Number | Number of days to keep in the Threat Detection audit logs. | 
| AzureSQL.DBThreatPolicy.storageAccountAccessKey | String | The identifier key of the Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.storageEndpoint | String | Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.emailAccountAdmins | Boolean | Email account administrators who the alert is sent to. | 
| AzureSQL.DBThreatPolicy.emailAddresses | String | List of email addresses to which the alert is sent. | 
| AzureSQL.DBThreatPolicy.disabledAlerts | String |  List of alerts that are disabled, or an empty string if no alerts are disabled. | 
| AzureSQL.DBThreatPolicy.useServerDefault | Unknown | Whether to use the default server policy. | 
| AzureSQL.DBThreatPolicy.databaseName | String | The name of the database that the threat policy is related to. | 
| AzureSQL.DBThreatPolicy.serverName | String | The name of the server that the threat policy is related to. | 


#### Command Example
```!azure-sql-db-threat-policy-get server_name=sqlintegration db_name=sql-integration-db```

#### Context Example
```json
{
    "AzureSQL": {
        "DBThreatPolicy": {
            "creationTime": "2021-01-04T08:05:32.05Z",
            "databaseName": "sql-integration-db",
            "disabledAlerts": [
                "Sql_Injection",
                "Sql_Injection_Vulnerability"
            ],
            "emailAccountAdmins": false,
            "emailAddresses": [
                ""
            ],
            "id": "/subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default",
            "name": "Default",
            "retentionDays": 5,
            "serverName": "sqlintegration",
            "state": "Enabled",
            "storageAccountAccessKey": "",
            "storageEndpoint": "",
            "type": "Microsoft.Sql/servers/databases/securityAlertPolicies"
        }
    }
}
```

#### Human Readable Output

>### Database Threat Detection Policies
>|Creation Time|Database Name|Disabled Alerts|Email Account Admins|Email Addresses|Id|Name|Retention Days|Server Name|State|Type|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-04T08:05:32.05Z | sql-integration-db | Sql_Injection,<br/>Sql_Injection_Vulnerability | false |  | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default | Default | 5 | sqlintegration | Enabled | Microsoft.Sql/servers/databases/securityAlertPolicies |


### azure-sql-db-audit-policy-create-update
***
Creates or updates the database's auditing policy.


#### Base Command

`azure-sql-db-audit-policy-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 
| state | Set the state of the policy. Possible values: "Enable" or "Disable". When *state* is enabled, *storage_endpoint* or *is_azure_monitor_target_enabled* are required. | Required | 
| audit_actions_groups | Comma-separated list of actions groups and actions to audit. For all possible values, see the integration documentation at https://docs.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-action-groups-and-actions?view=sql-server-ver15. | Optional | 
| is_azure_monitor_target_enabled | Whether audit events are sent to the Azure Monitor. Possible values: "true" and "false". | Optional | 
| is_storage_secondary_key_in_use | Whether the storage Account Access Key value is the storage's secondary key. Possible values: "true" and "false". | Optional | 
| queue_delay_ms | Time in milliseconds that can elapse before audit actions are forced to be processed. The default minimum value is 1000 (1 second). | Optional | 
| retention_days | Number of days to keep the policy in the audit logs. | Optional | 
| storage_account_access_key | Identifier key of the auditing storage account. | Optional | 
| storage_account_subscription_id | Storage subscription ID. | Optional | 
| storage_endpoint | Storage endpoint. If the value for the state argument is enabled, the value for the &storage_endpoint* or *is_azure_monitor_target_enabled* argument is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DBAuditPolicy.kind | String | Kind of audit policy. | 
| AzureSQL.DBAuditPolicy.id | String | Audit policy ID. | 
| AzureSQL.DBAuditPolicy.name | String | Audit policy name. | 
| AzureSQL.DBAuditPolicy.type | String | Resource type. | 
| AzureSQL.DBAuditPolicy.isAzureMonitorTargetEnabled | Boolean | Whether audit events are sent to the Azure Monitor. The value is "True" (Enabled) or "False" (Disabled). | 
| AzureSQL.DBAuditPolicy.retentionDays | Number | Number of days to keep in the audit logs in the storage account. | 
| AzureSQL.DBAuditPolicy.state | String | Policy state. | 
| AzureSQL.DBAuditPolicy.storageAccountSubscriptionId | String | Storage subscription ID. | 
| AzureSQL.DBAuditPolicy.auditActionsAndGroups | Unknown | Audit actions and groups to audit. | 
| AzureSQL.DBAuditPolicy.isStorageSecondaryKeyInUse | String | Whether the *storage_account_access_key* value is the storage's secondary key. | 
| AzureSQL.DBAuditPolicy.queueDelayMs | String | Time in milliseconds that can elapse before audit actions are forced to be processed. | 
| AzureSQL.DBAuditPolicy.storageAccountAccessKey | String | Identifier key of the auditing storage account. | 
| AzureSQL.DBAuditPolicy.storageEndpoint | String | Storage endpoint. | 
| AzureSQL.DBAuditPolicy.databaseName | String | The name of the database that the audit policy is related to. | 
| AzureSQL.DBAuditPolicy.serverName | String | The name of the server that the audit policy is related to. | 


#### Command Example
```!azure-sql-db-audit-policy-create-update server_name=sqlintegration db_name=sql-integration-db state=Enabled is_azure_monitor_target_enabled=true retention_days=3 queue_delay_ms=123```

#### Context Example
```json
{
    "AzureSQL": {
        "DBAuditPolicy": {
            "auditActionsAndGroups": [
                "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                "FAILED_DATABASE_AUTHENTICATION_GROUP",
                "BATCH_COMPLETED_GROUP"
            ],
            "databaseName": "sql-integration-db",
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default",
            "isAzureMonitorTargetEnabled": true,
            "name": "Default",
            "queueDelayMs": 123,
            "retentionDays": 3,
            "serverName": "sqlintegration",
            "state": "Enabled",
            "storageAccountSubscriptionId": "00000000-0000-0000-0000-000000000000",
            "type": "Microsoft.Sql/servers/databases/auditingSettings"
        }
    }
}
```

#### Human Readable Output

>### Create Or Update Database Auditing Settings
>|Audit Actions And Groups|Database Name|Id|Is Azure Monitor Target Enabled|Name|Queue Delay Ms|Retention Days|Server Name|State|Storage Account Subscription Id|Type|
>|---|---|---|---|---|---|---|---|---|---|---|
>| SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP,<br/>FAILED_DATABASE_AUTHENTICATION_GROUP,<br/>BATCH_COMPLETED_GROUP | sql-integration-db | /subscriptions/012345678/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default | true | Default | 123 | 3 | sqlintegration | Enabled | 00000000-0000-0000-0000-000000000000 | Microsoft.Sql/servers/databases/auditingSettings |


### azure-sql-db-threat-policy-create-update
***
Creates or updates the database's threat detection policy.


#### Base Command

`azure-sql-db-threat-policy-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 
| state | The state of the policy. Possible values: "Enabled" and "Disabled". | Required | 
| retention_days | Number of days to keep the policy in the audit logs. | Optional | 
| storage_account_access_key | The identifier key of the threat detection audit storage account | Optional | 
| storage_endpoint | The blob storage endpoint. This blob storage will hold all Threat Detection audit logs. | Optional | 
| disabled_alerts | Comma-separated list of alerts that are disabled. Possible values: "None", "Sql_Injection", "Sql_Injection_Vulnerability", "Access_Anomaly", "Data_Exfiltration", and "Unsafe_Action". | Optional | 
| email_addresses | Comma-separated list of email addresses to which the alert is sent. | Optional | 
| email_account_admins | Whether the alert is sent to the account administrators. Possible values: "true" and "false". | Optional | 
| use_server_default | Whether to use the default server policy. Possible values: "Enabled" and "Disabled". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DBThreatPolicy.kind | String | Kind of threat policy. | 
| AzureSQL.DBThreatPolicy.location | String | Threat policy location. | 
| AzureSQL.DBThreatPolicy.id | String | Threat policy ID. | 
| AzureSQL.DBThreatPolicy.name | String | Threat policy name. | 
| AzureSQL.DBThreatPolicy.type | String | Threat policy type. | 
| AzureSQL.DBThreatPolicy.state | String | Threat policy state. | 
| AzureSQL.DBThreatPolicy.creationTime | String | Threat policy creation time. | 
| AzureSQL.DBThreatPolicy.retentionDays | Number | Number of days to keep in the Threat Detection audit logs. | 
| AzureSQL.DBThreatPolicy.storageAccountAccessKey | String | The identifier key of the Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.storageEndpoint | String | Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.emailAccountAdmins | Boolean | Email account administrators who the alert is sent to. | 
| AzureSQL.DBThreatPolicy.emailAddresses | String | List of email addresses to which the alert is sent. | 
| AzureSQL.DBThreatPolicy.disabledAlerts | String | List of alerts that are disabled, or an empty string if no alerts are disabled. | 
| AzureSQL.DBThreatPolicy.useServerDefault | Unknown | Whether to use the default server policy. | 
| AzureSQL.DBThreatPolicy.databaseName | String | The name of the database that the threat policy is related to. | 
| AzureSQL.DBThreatPolicy.serverName | String | The name of the server that the threat policy is related to. | 


#### Command Example
```!azure-sql-db-threat-policy-create-update server_name=sqlintegration db_name=sql-integration-db state=Enabled disabled_alerts="Sql_Injection,Sql_Injection_Vulnerability" retention_days=5```

#### Context Example
```json
{
    "AzureSQL": {
        "DBThreatPolicy": {
            "creationTime": "0001-01-01T00:00:00Z",
            "databaseName": "sql-integration-db",
            "disabledAlerts": [
                "Sql_Injection",
                "Sql_Injection_Vulnerability"
            ],
            "emailAccountAdmins": false,
            "emailAddresses": [],
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default",
            "name": "Default",
            "retentionDays": 5,
            "serverName": "sqlintegration",
            "state": "Enabled",
            "storageAccountAccessKey": "",
            "type": "Microsoft.Sql/servers/databases/securityAlertPolicies"
        }
    }
}
```

#### Human Readable Output

>### Create Or Update Database Threat Detection Policies
>|Creation Time|Database Name|Disabled Alerts|Email Account Admins|Id|Name|Retention Days|Server Name|State|Type|
>|---|---|---|---|---|---|---|---|---|---|
>| 0001-01-01T00:00:00Z | sql-integration-db | Sql_Injection,<br/>Sql_Injection_Vulnerability | false | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default | Default | 5 | sqlintegration | Enabled | Microsoft.Sql/servers/databases/securityAlertPolicies |

