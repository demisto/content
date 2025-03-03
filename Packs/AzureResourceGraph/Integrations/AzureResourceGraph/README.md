Azure Resource Graph is an Azure service designed to extend Azure Resource Management by providing efficient and performant resource exploration with the ability to query at scale across a given set of resources.

## Authorize Cortex XSOAR for Azure Resource Graph (Self-Deployed Configuration)

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, see the [Microsoft article](https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app).

## Authentication

To enable and configure authentication using self deployed app, follow the [Self-Deployed Application Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#self-deployed-application)

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

- After authorizing the Self-Deployed Application, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields. After giving consent, the application has to have a role assigned so it can access the relevant resources per subscription.
- In order to assign a role to the application after consent was given:
  - Go to the Azure Portal UI. 
  - Go to **Subscriptions**, and then **Access Control (IAM)**. 
  - Click "Add role assignment". 
  - Create a new role or select a role that includes permissions for the queries you plan to run.
  - Select the Azure Resource Graph application. By default, Azure Applications aren't displayed in the available options. To find your application, search for the name and select it.


### Client Credentials Flow

---
Follow these steps for [client-credentials configuration:](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#client-credentials-flow).

1. In the instance configuration, select the **Use a self-deployed Azure application - Client Credentials Authorization Flow** checkbox.
2. Enter your Client ID in the **ID (Client ID)** parameter. 
3. Enter your Client Secret in the **Key (Client Secret)** parameter.
4. Enter your Tenant ID in the **Token (Tenant ID)** parameter.
5. Click **Test** to validate the URLs, token, and connection.

To use The Azure Resource Graph, you must have appropriate rights in Azure role-based access control (Azure RBAC) with at least read access to the resources you want to query. No results are returned if you don't have at least read permissions to the Azure object or object group.

## Configure Azure Resource Graph in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Token / Tenant ID | Received from the authorization process or from the self-deployed configuration process \(find the tenant ID in your app overview page in the Azure portal\) | False |
| Token / Tenant ID |  | False |
| ID / Client ID | Received from the authorization process or from the self-deployed configuration process. | False |
| Key / Client Secret |  | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-rg-list-operations

---

#### Base Command

`azure-rg-list-operations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of operations to return (Default is 50). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
|  AzureResourceGraph.Operations | String | A list of available Azure Resource Graph operations permissions and descriptions.| 

#### Command Example

`!azure-rg-list-operations limit=50`

#### Context Example

```json
{
  "value": [
      {
          "name": "Microsoft.ResourceGraph/operations/read",
          "display": {
              "provider": "Microsoft Resource Graph",
              "resource": "Operation",
              "operation": "Get Operations",
              "description": "Gets the list of supported operations"
          }
      },
      {
          "name": "Microsoft.ResourceGraph/resources/read",
          "display": {
              "provider": "Microsoft Resource Graph",
              "resource": "Resources",
              "operation": "Query resources",
              "description": "Submits a query on resources within specified subscriptions, management groups or tenant scope"
          }
      }
  ]
}
```

#### Human Readable Output

|Display|Name|
|---|---|
| provider: Microsoft Resource Graph<br>resource: Operation<br>operation: Get Operations<br>description: Gets the list of supported operations | Microsoft.ResourceGraph/operations/read |
| provider: Microsoft Resource Graph<br>resource: Resources<br>operation: Query resources<br>description: Submits a query on resources within specified subscriptions, management groups or tenant scope | Microsoft.ResourceGraph/resources/read |


### azure-rg-query

---

#### Base Command

`azure-rg-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to execute. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureResourceGraph.Query | String | Data returned from query. | 

#### Command Example

```!azure-rg-query query="resources | where type == 'microsoft.network/publicipaddresses'| where properties['ipAddress'] == '11.22.33.44' | project name, id, tenantId, subscriptionId, resourceGroup | join kind=inner (resourcecontainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId, properties.managementGroupAncestorsChain) on subscriptionId"```

#### Context Example

```json
{
    "count": 1,
    "data": [
        {
            "id": "/subscriptions/1abc234d-12a3-12a3-12a3-1234abcde123/resourceGroups/test-vm-resource-group/providers/Microsoft.Network/publicIPAddresses/test-vm-1-ip",
            "name": "test-vm-1-ip",
            "properties_managementGroupAncestorsChain": [
                {
                    "displayName": "grand-child-managment-group",
                    "name": "grand-child-managment-group"
                },
                {
                    "displayName": "child-management-group",
                    "name": "child-management-group"
                },
                {
                    "displayName": "test-new-managment-group",
                    "name": "test-new-managment-group"
                },
                {
                    "displayName": "Tenant Root Group",
                    "name": "a11111111-222-3333-12a3-1234abcde123"
                }
            ],
            "resourceGroup": "test-vm-resource-group",
            "subscriptionId": "1abc234d-12a3-12a3-12a3-1234abcde123",
            "tenantId": "a11111111-222-3333-12a3-1234abcde123"
        }
    ],
    "facets": [],
    "resultTruncated": "false",
    "totalRecords": 1
}
```

#### Human Readable Output

| id                                                                                                                                                   | name         | properties_managementGroupAncestorsChain                                                                                                                                                                                                                                                                                                           | resourceGroup           | subscriptionId                        | tenantId                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------- | ------------------------------------- |
| /subscriptions/1abc234d-12a3-12a3-12a3-1234abcde123/resourceGroups/test-vm-resource-group/providers/Microsoft.Network/publicIPAddresses/test-vm-1-ip | test-vm-1-ip | {'displayName': 'grand-child-managment-group', 'name': 'grand-child-managment-group'},<br>{'displayName': 'child-management-group', 'name': 'child-management-group'},<br>{'displayName': 'test-new-managment-group', 'name': 'test-new-managment-group'},<br>{'displayName': 'Tenant Root Group', 'name': 'a11111111-222-3333-12a3-1234abcde123'} | test-vm-resource-group  | 1abc234d-12a3-12a3-12a3-1234abcde123  | a11111111-222-3333-12a3-1234abcde123  |                                                                                                                                         |          |                                                                                                                                                                                                                                                                                                                                                    |               |                                      |                                      |                                      |

### azure-rg-auth-reset

Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-rg-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.