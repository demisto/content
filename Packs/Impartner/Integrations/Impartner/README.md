Impartner is the fastest-growing, most award-winning channel management solution provider on the market.
This integration was integrated and tested with version v1 of [Impartner Objects API](https://prod.impartner.live/swagger/ui/index#/).

## Configure Impartner on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Impartner.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
5. to get API key, please reach out to Impartner contact
6. 
## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### impartner-get-account-list

***
Get account IDs from Impartner

#### Base Command

`impartner-get-account-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | query for searching accounts. | Optional | 
| fields | Comma separated list of fields to retrieve. | Optional | 
| filter | Optional where clause (eg, Field1 = Val1 and Field2 &gt; Val2). | Optional | 
| orderby | Comma separated list of fields to sort by. | Optional | 
| skip | Number of results to skip for pagination. | Optional | 
| take | Number of results to take for pagination. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Impartner.Account.count | String | Number of results returned. | 
| Impartner.Account.entity | String | Type of entity returned. | 
| Impartner.Account.results.id | String | ID of account. | 
| Impartner.Account.results.name | String | Name of account. | 
| Impartner.Account.results.recordLink | String | Link to account. | 
| Impartner.Account.results.tech_BD_Assigned_for_XSOAR__cf | String | Tech partner BD assigned to account. | 

#### Command example
```!impartner-get-account-list```
#### Context Example
```json
{
    "Impartner": {
        "Accounts": {
            "List": {
                "count": 471,
                "entity": "Account",
                "results": [
                    {
                        "name": "1111",
                        "id": 1111,
                        "recordLink": "https://prod.impartner.live/load/ACT/1111",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1112",
                        "id": 1112,
                        "recordLink": "https://prod.impartner.live/load/ACT/1112",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1113",
                        "id": 1113,
                        "recordLink": "https://prod.impartner.live/load/ACT/1113",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1114",
                        "id": 1114,
                        "recordLink": "https://prod.impartner.live/load/ACT/1114",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1115",
                        "id": 1115,
                        "recordLink": "https://prod.impartner.live/load/ACT/1115",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1116",
                        "id": 1116,
                        "recordLink": "https://prod.impartner.live/load/ACT/1116",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1117",
                        "id": 1117,
                        "recordLink": "https://prod.impartner.live/load/ACT/1117",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1118",
                        "id": 1118,
                        "recordLink": "https://prod.impartner.live/load/ACT/1118",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1119",
                        "id": 1119,
                        "recordLink": "https://prod.impartner.live/load/ACT/1119",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    },
                    {
                        "name": "1120",
                        "id": 1120,
                        "recordLink": "https://prod.impartner.live/load/ACT/1120",
                        "tech_BD_Assigned_for_XSOAR__cf": null
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### List of account ID's
>| id   | name | recordLink |  tech_BBD_Assigned_for_XSOAR__cf|
>|------|------|------|------|------|
>| 1111 | 1111 | https://prod.impartner.live/load/ACT/1111 | |
>| 1112 | 1112 | https://prod.impartner.live/load/ACT/1112 | |
>| 1113 | 1113 | https://prod.impartner.live/load/ACT/1113 | |
>| 1114 | 1114 | https://prod.impartner.live/load/ACT/1114 | |
>| 1115 | 1115 | https://prod.impartner.live/load/ACT/1115 | |
>| 1116 | 1116 | https://prod.impartner.live/load/ACT/1116 | |
>| 1117 | 1117 | https://prod.impartner.live/load/ACT/1117 | |
>| 1118 | 1118 | https://prod.impartner.live/load/ACT/1118 | |
>| 1119 | 1119 | https://prod.impartner.live/load/ACT/1119 | |
>| 1120 | 1120 | https://prod.impartner.live/load/ACT/1120 | |


### impartner-get-account-id

***
Get account details from Impartner

#### Base Command

`impartner-get-account-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | id of Impartner account. | required |
| fields | Comma separated list of fields to retrieve. | Optional |
| all_fields | Whether to return all fields. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Impartner.Account.id | Number | Account ID. | 
| Impartner.Account.isActive | Boolean | Is account active. | 
| Impartner.Account.tech_BD_Assigned_for_XSOAR__cf | String | Tech partner BD assigned to account. | 
| Impartner.Account.mailingCity | String | City of account. | 
| Impartner.Account.mailingCountry | String | Country of account. | 
| Impartner.Account.mailingPostalCode | String | Account postal code. | 
| Impartner.Account.mailingState | String | State of account. | 
| Impartner.Account.mailingStreet | String | Street of account. | 
| Impartner.Account.name | String | Account Name. | 
| Impartner.Account.recordLink | Date | Link to account in Impartner. | 
| Impartner.Account.website | Number | Account website. | 
| Impartner.Account.mainProductToIntegrate | String | Partner main product they are looking to integrate with. | 
| Impartner.Account.mutualCustomer | String | Partner mutual customer with XSOAR. | 
| Impartner.Account.tpA_Product_s__cf | String | Cortex products TPA is signed for. | 
| Impartner.Account.target_customers__cf | String | Target customers for partner. | 
| Impartner.Account.company_Main_Market_Segment__cf | String | Partner main market segment. | 
| Impartner.Account.panW_Integration_Product__cf | String | Cortex integrated products. | 
| Impartner.Account.account_Integration_Status__cf | String | Account integration status. | 
| Impartner.Account.accountTimeline | String | Account timeline. | 
 

#### Command example
```!impartner-get-account-id id=2247998```
#### Context Example
```json
{
    "Impartner": {
        "Account": {
                      'id': 11111111, 
                      'isActive': True,
                      'tech_BD_Assigned_for_XSOAR__cf': 'Edi',
                      'mailingCity': 'Palo Alto',
                      'mailingCountry': 'United States', 
                      'mailingPostalCode': '11111', 
                      'mailingState': 'California', 
                      'mailingStreet': '236 test Ave',
                      'name': 'test_account', 
                      'recordLink': 'https://prod.impartner.live/load/ACT/11111111',
                      'website': 'https://www.test-account.ai/', 
                      'mainProductToIntegrate': 'test', 
                      'mutualCustomer': 'test', 
                      'tpA_Product_s__cf': 'test', 
                      'integration_Status__cf': 'Integration Approved',
                      'target_customers__cf': ['Large Enterprise', 'SMB', 'SME'], 
                      'company_Main_Market_Segment__cf': ['Automation Orchestration & SOC tools', 'Data Security Governance & Classification'],
                      'panW_Integration_Product__cf': ['test'],
                      'account_Integration_Status__cf': ['Integrations in Process'],
                      'accountTimeline': '2022-06-30T00:00:00'
        }
    }
}
```

#### Human Readable Output

>### Account Details
>|Name|ID|Link|PST Engineer|
>|---|---|---|---|
>| test_account | 11111111 | https://prod.impartner.live/load/ACT/11111111 | Edi |

