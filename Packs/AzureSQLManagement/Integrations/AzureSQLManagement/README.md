Microsoft Azure SQL Database is a managed cloud database provided as part of Microsoft Azure.

## Configure Azure SQL Management on Cortex XSOAR

In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure SQL Management using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!azure-sql-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-sql-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (8f9010bb-4efe-4cfa-a197-98a2694b7e0c).

You only need to fill in your subscription ID and resource group name. You can find your resource group and subscription ID at Azure Portal.

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

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
>2. Run the **!azure-sql-auth-complete** command in the War Room.

### azure-sql-auth-complete
***
Run this command to complete the authorization process. Should be used after running the azure-sql-auth-start command.


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
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-sql-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-sql-auth-reset```

#### Human Readable Output

>Authorization was reset successfully. You can now run **!azure-sql-auth-start** and **!azure-sql-auth-complete**.

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
List of all servers.


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
| AzureSQL.Server | Unknown | Servers list | 
| AzureSQL.Server.kind | String | Kind of server. | 
| AzureSQL.Server.location | String | Server location. | 
| AzureSQL.Server.tags | Unknown | Server Tags | 
| AzureSQL.Server.id | String | Server id | 
| AzureSQL.Server.name | String | Server name | 
| AzureSQL.Server.type | String | Server type. | 
| AzureSQL.Server.administratorLogin | String | username of server administrator | 
| AzureSQL.Server.version | String | Server version | 
| AzureSQL.Server.state | String | Server state | 
| AzureSQL.Server.fullyQualifiedDomainName | Unknown | servers fully qualified domain name | 
| AzureSQL.Server.privateEndpointConnections | Unknown | List of servers private endpoint connections | 
| AzureSQL.Server.publicNetworkAccess | String | servers public endpoint access. The value is 'Enabled' or 'Disabled'. | 


#### Command Example
```!azure-sql-servers-list```

#### Context Example
```json
{
    "AzureSQL": {
        "Server": {
            "administratorLogin": "demistoadmin",
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
>| demistoadmin | sqlintegration.database.windows.net | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration | v12.0 | eastus | sqlintegration | Enabled | Ready | Microsoft.Sql/servers | 12.0 |


### azure-sql-db-list
***
List of all DataBases for server.


#### Base Command

`azure-sql-db-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| limit | The maximum number of DataBases returned to the War Room. Default is 50. | Optional | 
| offset | (Int) Offset in the data set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DB | Unknown | All DB related to the server. | 
| AzureSQL.DB.kind | String | Kind of database. | 
| AzureSQL.DB.location | String | Database location. | 
| AzureSQL.DB.id | String | Database id | 
| AzureSQL.DB.name | String | Database name | 
| AzureSQL.DB.type | String | Database type. | 
| AzureSQL.DB.managedBy | String | Recource that manages database. | 
| AzureSQL.DB.sku | Unknown | Database SKU. | 
| AzureSQL.DB.catalogCollation | String | Collation of catalog. | 
| AzureSQL.DB.collation | String | Database collation | 
| AzureSQL.DB.creationDate | String | Creation date of the database, in ISO format. | 
| AzureSQL.DB.currentServiceObjectiveName | String | Database's current service level objective name. | 
| AzureSQL.DB.currentSku | Unknown | Name, Tier and capacity of the SKU. | 
| AzureSQL.DB.databaseID | String | Database ID. | 
| AzureSQL.DB.defaultSecondaryLocation | String | Default secondarylocation of the database. | 
| AzureSQL.DB.maxSizeBytes | Number | The max size of the database in bytes. | 
| AzureSQL.DB.readReplicaCount | Number | The number of readonly secondary replicas of the database. | 
| AzureSQL.DB.readScale | String | The state of read-only routing.  "Enabled" or "Disabled". | 
| AzureSQL.DB.requestedServiceObjectiveName | String | Database's requested service objective name.  | 
| AzureSQL.DB.status | String | Database status. | 
| AzureSQL.DB.storageAccountType | String | Database storage account type. | 
| AzureSQL.DB.zoneRedundant | Boolean | Is the database zone redundan. | 


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
>|Id|Database Id|Name|Location|Status|Managed By|
>|---|---|---|---|---|---|
>| /subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/master | 16b60b0c-53ef-4de0-b367-2c2bcc9617cd | master | eastus | Online | /subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration |
>| /subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db | 5343c264-7cf0-47c4-8cbb-1593d2337b69 | sql-integration-db | eastus | Online |  |


### azure-sql-db-audit-policy-list
***
Auditing settings of a database.


#### Base Command

`azure-sql-db-audit-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 
| limit | The maximum number of DataBases audit policies returned to the War Room. Default is 50. | Optional | 
| offset | (Int) Offset in the data set. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DbAuditPolicy | Unknown | All DB related to the server. | 
| AzureSQL.DbAuditPolicy.kind | String | Kind of audit policy. | 
| AzureSQL.DbAuditPolicy.id | String | Audit policy id | 
| AzureSQL.DbAuditPolicy.name | String | Audit policy name | 
| AzureSQL.DbAuditPolicy.type | String | Database type. | 
| AzureSQL.DbAuditPolicy.isAzureMonitorTargetEnabled | Boolean | Whether audit events are sent to Azure Monitor. the value is " Enabled" or "Disabled". | 
| AzureSQL.DbAuditPolicy.retentionDays | Number | Number of days to keep in the audit logs in the storage account | 
| AzureSQL.DbAuditPolicy.state | String | Policy state | 
| AzureSQL.DbAuditPolicy.storageAccountSubscriptionId | String | storage subscription Id. | 


#### Command Example
```!azure-sql-db-audit-policy-list server_name=sqlintegration db_name=sql-integration-db```

#### Context Example
```json
{
    "AzureSQL": {
        "DbAuditPolicy": {
            "auditActionsAndGroups": [
                "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                "FAILED_DATABASE_AUTHENTICATION_GROUP",
                "BATCH_COMPLETED_GROUP"
            ],
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default",
            "isAzureMonitorTargetEnabled": true,
            "name": "Default",
            "retentionDays": 0,
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
>|Audit Actions And Groups|Id|Is Azure Monitor Target Enabled|Name|Retention Days|State|Storage Account Subscription Id|Type|
>|---|---|---|---|---|---|---|---|
>| SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP,<br/>FAILED_DATABASE_AUTHENTICATION_GROUP,<br/>BATCH_COMPLETED_GROUP | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default | true | Default | 0 | Enabled | 00000000-0000-0000-0000-000000000000 | Microsoft.Sql/servers/databases/auditingSettings |


### azure-sql-db-threat-policy-get
***
Threat detection policies of a database


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
| AzureSQL.DBThreatPolicy | Unknown | All Threat Policy related to the database. | 
| AzureSQL.DBThreatPolicy.kind | String | Kind of Threat Policy. | 
| AzureSQL.DBThreatPolicy.location | String | Threat Policy location. | 
| AzureSQL.DBThreatPolicy.id | String | Threat Policy id | 
| AzureSQL.DBThreatPolicy.name | String | Threat Policy name | 
| AzureSQL.DBThreatPolicy.type | String | Threat Policy type. | 
| AzureSQL.DBThreatPolicy.state | String | Policy state | 
| AzureSQL.DBThreatPolicy.creationTime | String | Policy creation Time | 
| AzureSQL.DBThreatPolicy.retentionDays | Number | Number of days to keep in the Threat Detection audit logs. | 
| AzureSQL.DBThreatPolicy.storageAccountAccessKey | String | Specifies the identifier key of the Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.storageEndpoint | String | Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.emailAccountAdmins | Boolean | Email account administrators that alert is sent to. | 
| AzureSQL.DBThreatPolicy.emailAddresses | String | list of e-mail addresses to which the alert is sent. | 
| AzureSQL.DBThreatPolicy.disabledAlerts | String | list of alerts that are disabled, or empty string to disable no alerts. | 
| AzureSQL.DBThreatPolicy.useServerDefault | Unknown | whether to use the default server policy. | 


#### Command Example
```!azure-sql-db-threat-policy-get server_name=sqlintegration db_name=sql-integration-db```

#### Context Example
```json
{
    "AzureSQL": {
        "DBThreatPolicy": {
            "creationTime": "2021-01-04T08:05:32.05Z",
            "disabledAlerts": [
                ""
            ],
            "emailAccountAdmins": false,
            "emailAddresses": [
                ""
            ],
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default",
            "name": "Default",
            "retentionDays": 0,
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
>|Creation Time|Disabled Alerts|Email Account Admins|Email Addresses|Id|Name|Retention Days|State|Type|
>|---|---|---|---|---|---|---|---|---|
>| 2021-01-04T08:05:32.05Z |  | false |  | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default | Default | 0 | Enabled | Microsoft.Sql/servers/databases/securityAlertPolicies |


### azure-sql-db-audit-policy-create-update
***
Create or update database's auditing policy.


#### Base Command

`azure-sql-db-audit-policy-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 
| state | set state 'Enable' or 'Disable'. Possible values are: Enabled, Disabled. | Required | 
| audit_actions_groups | Comma-separated Actions-Groups and Actions to audit. Possible values: APPLICATION_ROLE_CHANGE_PASSWORD_GROUP BACKUP_RESTORE_GROUP DATABASE_LOGOUT_GROUP DATABASE_OBJECT_CHANGE_GROUP DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP DATABASE_OBJECT_PERMISSION_CHANGE_GROUP DATABASE_OPERATION_GROUP DATABASE_PERMISSION_CHANGE_GROUP DATABASE_PRINCIPAL_CHANGE_GROUP DATABASE_PRINCIPAL_IMPERSONATION_GROUP DATABASE_ROLE_MEMBER_CHANGE_GROUP FAILED_DATABASE_AUTHENTICATION_GROUP SCHEMA_OBJECT_ACCESS_GROUP SCHEMA_OBJECT_CHANGE_GROUP SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP USER_CHANGE_PASSWORD_GROUP BATCH_STARTED_GROUP BATCH_COMPLETED_GROUP| Optional | 
| is_azure_monitor_target_enabled | Is audit events are sent to Azure Monitor. Possible values are: true, false. | Optional | 
| is_storage_secondary_key_in_use | Is storage Account Access Key value is the storage's secondary key. Possible values are: true, false. | Optional | 
| queue_delay_ms | Time in milliseconds that can elapse before audit actions are forced to be processed. The default minimum value is 1000 (1 second). | Optional | 
| retention_days | Number of days to keep the policy in the audit logs. | Optional | 
| storage_account_access_key | identifier key of the auditing storage account. | Optional | 
| storage_account_subscription_id | storage subscription Id. | Optional | 
| storage_endpoint | Storage endpoint. If state is Enabled, storageEndpoint or isAzureMonitorTargetEnabled is required. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DbAuditPolicy.kind | String | Kind of audit policy. | 
| AzureSQL.DbAuditPolicy.id | String | Audit policy id | 
| AzureSQL.DbAuditPolicy.name | String | Audit policy name | 
| AzureSQL.DbAuditPolicy.type | String | Database type. | 
| AzureSQL.DbAuditPolicy.isAzureMonitorTargetEnabled | Boolean | Whether audit events are sent to Azure Monitor. the value is " Enabled" or "Disabled". | 
| AzureSQL.DbAuditPolicy.retentionDays | Number | Number of days to keep in the audit logs in the storage account | 
| AzureSQL.DbAuditPolicy.state | String | Policy state | 
| AzureSQL.DbAuditPolicy.storageAccountSubscriptionId | String | storage subscription Id. | 
| AzureSQL.DbAuditPolicy.auditActionsAndGroups | Unknown | audit Actions And Groups to audit. | 
| AzureSQL.DbAuditPolicy.isStorageSecondaryKeyInUse | String | Is storageAccountAccessKey value is the storage's secondary key | 
| AzureSQL.DbAuditPolicy.queueDelayMs | String | Time in milliseconds that can elapse before audit actions are forced to be processed. | 
| AzureSQL.DbAuditPolicy.storageAccountAccessKey | String | identifier key of the auditing storage account | 
| AzureSQL.DbAuditPolicy.storageEndpoint | String | Storage endpoint. | 


#### Command Example
```!azure-sql-db-audit-policy-create-update server_name=sqlintegration db_name=sql-integration-db state=Enabled is_azure_monitor_target_enabled=true retention_days=3 queue_delay_ms=123```

#### Context Example
```json
{
    "AzureSQL": {
        "DbAuditPolicy": {
            "auditActionsAndGroups": [
                "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                "FAILED_DATABASE_AUTHENTICATION_GROUP",
                "BATCH_COMPLETED_GROUP"
            ],
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default",
            "isAzureMonitorTargetEnabled": true,
            "name": "Default",
            "queueDelayMs": 123,
            "retentionDays": 3,
            "state": "Enabled",
            "storageAccountSubscriptionId": "00000000-0000-0000-0000-000000000000",
            "type": "Microsoft.Sql/servers/databases/auditingSettings"
        }
    }
}
```

#### Human Readable Output

>### Create Or Update Database Auditing Settings
>|Audit Actions And Groups|Id|Is Azure Monitor Target Enabled|Name|Queue Delay Ms|Retention Days|State|Storage Account Subscription Id|Type|
>|---|---|---|---|---|---|---|---|---|
>| SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP,<br/>FAILED_DATABASE_AUTHENTICATION_GROUP,<br/>BATCH_COMPLETED_GROUP | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/auditingSettings/Default | true | Default | 123 | 3 | Enabled | 00000000-0000-0000-0000-000000000000 | Microsoft.Sql/servers/databases/auditingSettings |


### azure-sql-db-threat-policy-create-update
***
Create or update database's threat detection policy.


#### Base Command

`azure-sql-db-threat-policy-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| server_name | Server name. | Required | 
| db_name | Database name. | Required | 
| state | set state 'Enable' or 'Disable'. Possible values are: Enabled, Disabled. | Required | 
| retention_days | Number of days to keep the policy in the audit logs. | Optional | 
| storage_account_access_key | identifier key of the auditing storage account. | Optional | 
| storage_endpoint | Storage endpoint. If state is Enabled, storageEndpoint or isAzureMonitorTargetEnabled is required. | Optional | 
| disabled_alerts | Comma-separated list of alerts that are disabled, or "none" to disable no alerts. Possible values: Sql_Injection, Sql_Injection_Vulnerability, Access_Anomaly, Data_Exfiltration, Unsafe_Action. | Optional | 
| email_addresses | Comma-separated list of e-mail addresses to which the alert is sent. | Optional | 
| email_account_admins | The alert is sent to the account administrators. Possible values are: true, false. | Optional | 
| use_server_default | Whether to use the default server policy or not. Possible values are: Enabled, Disabled. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSQL.DBThreatPolicy.kind | String | Kind of Threat Policy. | 
| AzureSQL.DBThreatPolicy.location | String | Threat Policy location. | 
| AzureSQL.DBThreatPolicy.id | String | Threat Policy id | 
| AzureSQL.DBThreatPolicy.name | String | Threat Policy name | 
| AzureSQL.DBThreatPolicy.type | String | Threat Policy type. | 
| AzureSQL.DBThreatPolicy.state | String | Policy state | 
| AzureSQL.DBThreatPolicy.creationTime | String | Policy creation Time | 
| AzureSQL.DBThreatPolicy.retentionDays | Number | Number of days to keep in the Threat Detection audit logs. | 
| AzureSQL.DBThreatPolicy.storageAccountAccessKey | String | Specifies the identifier key of the Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.storageEndpoint | String | Threat Detection audit storage account. | 
| AzureSQL.DBThreatPolicy.emailAccountAdmins | Boolean | Email account administrators that alert is sent to. | 
| AzureSQL.DBThreatPolicy.emailAddresses | String | list of e-mail addresses to which the alert is sent. | 
| AzureSQL.DBThreatPolicy.disabledAlerts | String | list of alerts that are disabled, or empty string to disable no alerts. | 
| AzureSQL.DBThreatPolicy.useServerDefault | Unknown | whether to use the default server policy. | 


#### Command Example
```!azure-sql-db-threat-policy-create-update server_name=sqlintegration db_name=sql-integration-db state=Enabled disabled_alerts="Sql_Injection,Sql_Injection_Vulnerability" retention_days=5```

#### Context Example
```json
{
    "AzureSQL": {
        "DBThreatPolicy": {
            "creationTime": "0001-01-01T00:00:00Z",
            "disabledAlerts": [
                "Sql_Injection",
                "Sql_Injection_Vulnerability"
            ],
            "emailAccountAdmins": false,
            "emailAddresses": [],
            "id": "/subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default",
            "name": "Default",
            "retentionDays": 5,
            "state": "Enabled",
            "storageAccountAccessKey": "",
            "type": "Microsoft.Sql/servers/databases/securityAlertPolicies"
        }
    }
}
```

#### Human Readable Output

>### Create Or Update Database Threat Detection Policies
>|Creation Time|Disabled Alerts|Email Account Admins|Id|Name|Retention Days|State|Type|
>|---|---|---|---|---|---|---|---|
>| 0001-01-01T00:00:00Z | Sql_Injection,<br/>Sql_Injection_Vulnerability | false | /subscriptions/0123456789/resourceGroups/sql-integration/providers/Microsoft.Sql/servers/sqlintegration/databases/sql-integration-db/securityAlertPolicies/Default | Default | 5 | Enabled | Microsoft.Sql/servers/databases/securityAlertPolicies |

