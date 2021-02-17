Ingest indicator feeds from OpenCTI. Works with OpenCTI v4 instances.
This integration was integrated and tested with version v4.0.7 of OpenCTI.
## Configure OpenCTI Feed v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenCTI Feed v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL |  | True |
    | API Key |  | True |
    | Indicators Type to fetch | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "User-Account", "Domain", "Email-Address", "File-md5", "File-sha1", "File-sha256", "HostName", "IPV4-Addr", "IPV6-Addr", "Registry-Key-Value", and "URL". The rest will not cause automatic indicator creation in XSOAR. Please refer to the integration documentation for more information. The default is "ALL". | True |
    | Max. indicators per fetch (default is 500) |  | False |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |
    | Feed Fetch Interval |  | False |
    | Tags | Supports CSV values. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### opencti-get-indicators
***
Gets indicators from the feed.


#### Base Command

`opencti-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return per fetch. The default value is "50". Maximum value is "200". Default is 50. | Optional | 
| indicator_types | The indicator types to fetch. Out of the box indicator types supported in XSOAR are: "User-Account", "Domain", "Email-Address", "File-md5", "File-sha1", "File-sha256", "HostName", "IPV4-Addr", "IPV6-Addr", "Registry-Key-Value", and "URL". The rest will not cause automatic indicator creation in XSOAR. Please refer to the integration documentation for more information. The default is "ALL". Possible values are: ALL, User-Account, Domain, Email-Address, File-MD5, File-SHA1, File-SHA256, HostName, IPV4-Addr, IPV6-Addr, Registry-Key-Value, URL. Default is ALL. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicators.type | String | Indicator type. | 
| OpenCTI.Indicators.value | String | Indicator value. | 
| OpenCTI.Indicators.id | String | Indicator id. | 
| OpenCTI.Indicators.createdBy | String | The creator of indicator. | 
| OpenCTI.Indicators.score | Number | Indicator score. | 
| OpenCTI.Indicators.description | String | Indicator Description. | 
| OpenCTI.Indicators.labels | Unknown | Indicator labels. | 
| OpenCTI.Indicators.marking | Unknown | Indicator marking definitions. | 


#### Command Example
```!opencti-get-indicators limit=3 indicator_types="IPV4-Addr"```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicators": [
            {
                "createdBy": "5dd205b7-73ed-497c-b4f7-9f59e7380f56",
                "description": "test ip",
                "id": "85b04cf3-d608-4a1f-8e55-d6d732e82749",
                "labels": [
                    "demisto"
                ],
                "marking": [
                    "TLP:GREEN"
                ],
                "score": 50,
                "type": "IPV4-Addr",
                "value": "1.1.1.1"
            },
            {
                "createdBy": "e24f219c-e631-4901-9eaf-515cf7747b53",
                "description": "bad IP create",
                "id": "69c38da9-feb2-4751-a8fa-51f1059b9af3",
                "labels": [
                    "test-label"
                ],
                "marking": [
                    "TLP:RED"
                ],
                "score": 100,
                "type": "IPV4-Addr",
                "value": "1.2.3.4"
            },
            {
                "createdBy": "e24f219c-e631-4901-9eaf-515cf7747b53",
                "description": "bad IP update",
                "id": "006c3ccf-a9c3-4dce-b3b7-4ca981661a31",
                "labels": [
                    "test-label"
                ],
                "marking": [
                    "TLP:RED"
                ],
                "score": 90,
                "type": "IPV4-Addr",
                "value": "1.2.3.5"
            }
        ]
    }
}
```

#### Human Readable Output

>### Indicators from OpenCTI
>|type|value|id|
>|---|---|---|
>| IPV4-Addr | 1.1.1.1 | 85b04cf3-d608-4a1f-8e55-d6d732e82749 |
>| IPV4-Addr | 1.2.3.4 | 69c38da9-feb2-4751-a8fa-51f1059b9af3 |
>| IPV4-Addr | 1.2.3.5 | 006c3ccf-a9c3-4dce-b3b7-4ca981661a31 |


### opencti-indicator-delete
***
Delete indicator.


#### Base Command

`opencti-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-indicator-delete id=2fdd419e-3a22-4a28-9876-3de6bebd4075```

#### Human Readable Output

>Indicator deleted.

### opencti-indicator-field-update
***
Update indicator field. Available fields to update - score, description.


#### Base Command

`opencti-indicator-field-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 
| field | Indicator field to update. Possible values are: score, description. | Required | 
| value | Value of the field to update. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | String | Updated indicator id. | 


#### Command Example
```!opencti-indicator-field-update id=676c1652-e9b6-48d1-bf14-c509e4c3a6fd field=description value="update test"```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicator": {
            "id": "676c1652-e9b6-48d1-bf14-c509e4c3a6fd"
        }
    }
}
```

#### Human Readable Output

>Indicator updated successfully.

### opencti-indicator-create
***
Create new indicator.


#### Base Command

`opencti-indicator-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The indicator type to create. Out of the box indicator types supported in XSOAR are: "User-Account", "Domain", "Email-Address", "File-md5", "File-sha1", "File-sha256", "HostName", "IPV4-Addr", "IPV6-Addr", "Registry-Key-Value", and "URL". The rest will not cause automatic indicator creation in XSOAR. Possible values are: User-Account, Domain, Email-Address, File-MD5, File-SHA1, File-SHA256, HostName, IPV4-Addr, IPV6-Addr, Registry-Key-Value, URL. | Required | 
| created_by | Organization id. Use opencti-organization-list to find all organizations id at opencti, or use  opencti-organization-create to create new organization id. | Optional | 
| marking | Indicator marking. Possible values are: TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED. | Optional | 
| label | Indicator label name. | Optional | 
| external_references_url | External References URL. In order to use external references, external_references_url and external_references_source_name are madatory. | Optional | 
| external_references_source_name | External References Source Name. In order to use external references, external_references_url and external_references_source_name are madatory. | Optional | 
| description | Indicator description. | Optional | 
| score | Indicator score - number between 0 - 100. Default score value 50. | Optional | 
| data | Indicator data - json. Mandatory Data fields are: value - value of the indicator. Mandatory for the following types: Domain, Email-Address, IPV4-Addr, IPV6-Addr, URL, HostName. For file-md5, file-sha1, file-sha256 data argument should contain hashes, and size keys. For User-Account type data should contain user_id. Registry-Key-Value data json should contain key "key". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Indicator.id | String | New indicator id. | 
| OpenCTI.Indicator.data | Unknown | New indicator data. | 


#### Command Example
```!opencti-indicator-create type=Domain created_by=0c7cb378-64c3-4809-b423-986ac7cecf91 marking=TLP:RED description=test data="{\"value\": \"TestDomainDocs.com\"}" label=test-label```

#### Context Example
```json
{
    "OpenCTI": {
        "Indicator": {
            "data": {
                "type": "Domain-Name",
                "value": "TestDomainDocs.com"
            },
            "id": "dab6780f-3612-4f95-979f-bda8bebf397f"
        }
    }
}
```

#### Human Readable Output

>Indicator created successfully. New Indicator id: dab6780f-3612-4f95-979f-bda8bebf397f

### opencti-indicator-field-add
***
Add field to indicator. Avalible fields to add - marking defenition, label.


#### Base Command

`opencti-indicator-field-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 
| field | Indicator field to add. Possible values are: marking, label. | Required | 
| value | Value of the field to add. For marking available values are TLP:RED, TLP:WHITE, TLP:GREEN, TLP:AMBER. Indicator can have up to 1 marking. For label, enter label name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-indicator-field-add value=new-label id=676c1652-e9b6-48d1-bf14-c509e4c3a6fd field=label```

#### Human Readable Output

>Added label successfully.

### opencti-indicator-field-remove
***
Remove field from indicator. Avalible fields to remove - marking defenition, label.


#### Base Command

`opencti-indicator-field-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Indicator ID. | Required | 
| field | Indicator field to update. Possible values are: marking, label. | Required | 
| value | Value of the field to remove. For marking available values are TLP:RED, TLP:WHITE, TLP:GREEN, TLP:AMBER. For label, enter label name. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!opencti-indicator-field-remove field=marking value=TLP:GREEN id=85b04cf3-d608-4a1f-8e55-d6d732e82749```

#### Human Readable Output

>Field removed successfully.

### opencti-organization-list
***
Get list of all organizations.


#### Base Command

`opencti-organization-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of organizations to return per fetch. The default value is "50". Maximum value is "200". Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organizations.id | String | Organization id. | 
| OpenCTI.Organizations.name | String | Organization name. | 


#### Command Example
```!opencti-organization-list limit=3```

#### Context Example
```json
{
    "OpenCTI": {
        "Organizations": [
            {
                "id": "1e12fe87-db3e-4838-8391-6910547bf60d",
                "name": "Test_Organization"
            },
            {
                "id": "11ddff08-8933-46d7-ab22-31f49496499f",
                "name": "ExampleOrganization"
            },
            {
                "id": "3b554565-4103-419b-a6a4-d875b00907bf",
                "name": "OrgTest"
            }
        ]
    }
}
```

#### Human Readable Output

>### Organizations from OpenCTI
>|Id|Name|
>|---|---|
>| 1e12fe87-db3e-4838-8391-6910547bf60d | Test_Organization |
>| 11ddff08-8933-46d7-ab22-31f49496499f | ExampleOrganization |
>| 3b554565-4103-419b-a6a4-d875b00907bf | OrgTest |


### opencti-organization-create
***
Create organization.


#### Base Command

`opencti-organization-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of organization to create. | Required | 
| description | Description of the organization. | Optional | 
| reliability | Reliability of the organization. Possible values are: A, B, C, D, E, F. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCTI.Organization.id | String | New organization id. | 


#### Command Example
```!opencti-organization-create name=ExampleOrganization description="create organization" reliability="C"```

#### Context Example
```json
{
    "OpenCTI": {
        "Organization": {
            "id": "11ddff08-8933-46d7-ab22-31f49496499f"
        }
    }
}
```

#### Human Readable Output

>Organization created successfully with id: 11ddff08-8933-46d7-ab22-31f49496499f.
