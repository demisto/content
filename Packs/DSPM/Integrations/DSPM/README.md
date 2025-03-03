# Overview
The Prisma Cloud DSPM(Data Security Posture Management) integration enhances the management and remediation of DSPM risks. The integration provides users with actionable data, insights and a seamless workflow for addressing potential security threats.

# Use Cases
- Remediation of DSPM out-of-the-box risks based on automated playbooks.
- Close or update risks by interacting with DSPM API using a dedicated list of building blocks.
- Distribute DSPM risks to other systems.

# Prerequisites
 1. An active Prisma Cloud DSPM account
 2. Slack V3 Pack
 3. AWS-S3 Pack
 4. Core REST APIs pack
 5. Atlassian Jira v3 Pack
 6. Google Cloud Storage Pack ( Optional )
 7. Azure Storage Container Pack ( Optional )

## Configure Cortex XSOAR on Prisma Cloud DSPM

1. Log in to you Prisma Cloud DSPM platform.
2. Navigate to **Settings** > **Workflow** > **XSOAR**.
3. Click **Connect** to create and configure a new XSOAR integration.
4. **XSOAR link** - Add the XSOAR API URL.
5. **Notified On** - Select the Risks option. 
6. **Severity Threshold** - Set the severity threshold to receive notifications for assets that fall under that severity.
7. **Filter By Tags** - Notifications will be sent for assets that match any of the selected tags.
8. **Advanced** - Add required headers **Authorization** and **x-xdr-auth-id**

## Configure Prisma Cloud DSPM on Cortex XSOAR

1. Navigate to **Settings & Info** > **Settings** > **Integrations** > **Instances**.
2. Search for Prisma Cloud DSPM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | DSPM server URL | The tenant URL of the Prisma Cloud DSPM | True |
    | DSPM API Key | API key to use for the connection. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dspm-list-risk-findings

***
Retrieves risk findings matching the input criteria.

#### Base Command

`dspm-list-risk-findings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| rule_name_in | A comma-separated list of rule names. | Optional | 
| rule_name_equal | The exact rule name. | Optional | 
| dspm_tag_key_in | A comma-separated list of DSPM tag keys. | Optional | 
| dspm_tag_key_equal | Exact DSPM tag key. | Optional | 
| dspm_tag_value_in | A comma-separated list of DSPM tag values. | Optional | 
| dspm_tag_value_equal | The exact DSPM tag value. | Optional | 
| projectId_in | A comma-separated list of project IDs. | Optional | 
| projectId_equal | The exact project ID. | Optional | 
| cloud_provider_in | A comma-separated list of cloud providers. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. Default is AWS. | Optional | 
| cloud_provider_equal | The exact cloud provider. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| affects_in | A comma-separated list of affects. Possible values are: SECURITY, COMPLIANCE, GOVERNANCE, SECURITY_AND_COMPLIANCE, SECURITY_AND_GOVERNANCE, COMPLIANCE_AND_GOVERNANCE, SECURITY_AND_COMPLIANCE_AND_GOVERNANCE. | Optional | 
| affects_equal | The exact effect. Possible values are: SECURITY, COMPLIANCE, GOVERNANCE, SECURITY_AND_COMPLIANCE, COMPLIANCE_AND_GOVERNANCE, SECURITY_AND_GOVERNANCE, SECURITY_AND_COMPLIANCE_AND_GOVERNANCE. | Optional | 
| status_in | A comma-separated list of statuses. Possible values are: OPEN, CLOSED, UNIMPORTANT, WRONG, HANDLED, INVESTIGATING. | Optional | 
| status_equal | The exact status. Possible values are: OPEN, CLOSED, UNIMPORTANT, WRONG, HANDLED, INVESTIGATING. | Optional | 
| sort | The sort order. | Optional | 
| limit | The maximum number of risk findings to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.RiskFinding.asset | Unknown | The asset details associated with the risk finding. | 
| DSPM.RiskFinding.cloudEnvironment | String | The cloud environment \(public or private\) associated with the risk finding. | 
| DSPM.RiskFinding.cloudProvider | String | The cloud provider associated with the risk finding \(e.g., AWS, Azure, GCP\). | 
| DSPM.RiskFinding.complianceStandards | Unknown | The compliance standards relevant to the risk finding. | 
| DSPM.RiskFinding.firstDiscovered | Date | The date the risk finding was first discovered. | 
| DSPM.RiskFinding.id | String | The unique ID of the risk finding. | 
| DSPM.RiskFinding.projectId | String | The project ID where the asset resides. | 
| DSPM.RiskFinding.ruleName | String | The rule name associated with the risk finding. | 
| DSPM.RiskFinding.severity | String | The severity of the risk finding \(e.g., Low, Medium, High\). | 
| DSPM.RiskFinding.status | String | The current status of the risk finding \(e.g., Open, Closed\). | 

#### Command example
```!dspm-list-risk-findings```
#### Context Example
```json
{
  "DSPM": {
    "RiskFinding": [
      {
        "id": "00000000-0000-4f99-0000-616843b6b19e",
        "ruleName": "Empty storage asset",
        "severity": "LOW",
        "asset": {},
        "status": "OPEN",
        "projectId": "********",
        "cloudProvider": "AWS",
        "cloudEnvironment": "UNKNOWN",
        "firstDiscovered": "2024-09-27T11:55:39.059125Z",
        "complianceStandards": {}
    }
    ]
  }
}
```

#### Human Readable Output

>### Results
>|Asset|Cloud Environment|Cloud Provider|Compliance Standards|First Discovered|ID|Project ID|Rule Name|Severity|Status|
>|---|---|---|---|---|---|---|---|---|---|
>|{}|UNKNOWN|AWS|{}|2024-09-27T11:55:39.059125Z|00000000-0000-4f99-0000-616843b6b19e|********|Empty storage asset|LOW|OPEN|

### dspm-get-risk-finding-by-id

***
Retrieves the details of a risk for the provided risk ID.

#### Base Command

`dspm-get-risk-finding-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_id | ID of the risk for which to retrieve details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.RiskFinding.asset | Unknown | The asset details associated with the risk finding. | 
| DSPM.RiskFinding.cloudEnvironment | String | The cloud environment \(public or private\) associated with the risk finding. | 
| DSPM.RiskFinding.cloudProvider | String | The cloud provider associated with the risk finding \(e.g., AWS, Azure, GCP\). | 
| DSPM.RiskFinding.complianceStandards | Unknown | The compliance standards relevant to the risk finding. | 
| DSPM.RiskFinding.firstDiscovered | Date | The date the risk finding was first discovered. | 
| DSPM.RiskFinding.id | String | The unique ID of the risk finding. | 
| DSPM.RiskFinding.projectId | String | The project ID where the asset resides. | 
| DSPM.RiskFinding.ruleName | String | The rule name associated with the risk finding. | 
| DSPM.RiskFinding.severity | String | The severity of the risk finding \(e.g., Low, Medium, High\). | 
| DSPM.RiskFinding.status | String | The current status of the risk finding \(e.g., Open, Closed\). | 

#### Command example
```!dspm-get-risk-finding-by-id finding_id="00000000-0000-4f99-0000-616843b6b19e"```
#### Context Example
```json
{
    "DSPM": {
            "RiskFinding": {
            "id": "00000000-0000-4f99-0000-616843b6b19e",
            "ruleName": "Empty storage asset",
            "severity": "LOW",
            "asset": {},
            "status": "OPEN",
            "projectId": "********",
            "cloudProvider": "AWS",
            "cloudEnvironment": "UNKNOWN",
            "firstDiscovered": "2024-09-27T11:55:39.059125Z",
            "complianceStandards": {}
        }
    }
}
```

#### Human Readable Output

>### Results
>|Asset|Cloud Environment|Cloud Provider|Compliance Standards|First Discovered|ID|Project ID|Rule Name|Severity|Status|
>|---|---|---|---|---|---|---|---|---|---|
>|{}|UNKNOWN|AWS|{}|2024-09-27T11:55:39.059125Z|00000000-0000-4f99-0000-616843b6b19e|********|Empty storage asset|LOW|OPEN|

### dspm-list-assets

***
Retrieves a list of assets for the company.

#### Base Command

`dspm-list-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region_in | A comma-separated list of regions. | Optional | 
| region_equal | The exact region. | Optional | 
| cloud_provider_in | A comma-separated list of cloud providers. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| cloud_provider_equal | The exact cloud provider. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| service_type_in | A comma-separated list of service types. | Optional | 
| service_type_equal | The exact service type. | Optional | 
| lifecycle_in | A comma-separated list of life cycles. Possible values are: RUNNING, STOPPED, DELETED. | Optional | 
| lifecycle_equal | The exact lifecycle. Possible values are: RUNNING, STOPPED, DELETED. | Optional | 
| sort | The sorting criteria in the format: property,(asc\|desc). Default sort order is ascending. Multiple sort criteria are supported. | Optional | 
| limit | The maximum number of assets to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.Asset.dataTypes | Unknown | Data types associated with the asset. | 
| DSPM.Asset.dataTypeGroups | Unknown | Data type groups associated with the asset. | 
| DSPM.Asset.assetDigTags | Unknown | Dig tags associated with the asset. | 
| DSPM.Asset.cloudEnvironment | String | The cloud environment in which the asset exists. | 
| DSPM.Asset.cloudProvider | String | The cloud provider for the asset. | 
| DSPM.Asset.encrypted | Boolean | Indicates if the asset is encrypted. | 
| DSPM.Asset.id | String | The unique identifier of the asset. | 
| DSPM.Asset.lifecycle | String | Lifecycle status of the asset. | 
| DSPM.Asset.name | String | The name of the asset. | 
| DSPM.Asset.openAlertsCount | Number | The count of open alerts for the asset. | 
| DSPM.Asset.openRisksCount | Number | The count of open risks for the asset. | 
| DSPM.Asset.openToWorld | Boolean | Indicates if the asset is open to the world. | 
| DSPM.Asset.projectId | String | The ID of the project associated with the asset. | 
| DSPM.Asset.projectName | String | The name of the project associated with the asset. | 
| DSPM.Asset.serviceType | String | The type of service associated with the asset. | 
| DSPM.Asset.tags | Unknown | Tags related to the asset. | 

#### Command example
```!dspm-list-assets cloudProviderEqual=AWS serviceTypeEqual=S3```
#### Context Example
```json
{
    "DSPM": {
        "Assets": [{
        "projectId": "************",
        "projectName": "************",
        "name": "dymmy-ci0jq3kgvjnccdfp-us-east-1",
        "cloudProvider": "AWS",
        "cloudEnvironment": "TESTING",
        "serviceType": "S3",
        "dataTypeGroups": [],
        "dataTypes": [],
        "lifecycle": "RUNNING",
        "openRisksCount": 0,
        "openAlertsCount": 0,
        "encrypted": true,
        "openToWorld": false,
        "tags": {},
        "assetDigTags": [],
        "id": "arn:aws:s3:::dymmy-ci0jq3kgvjnccdfp-us-east-1"
    }]
    }
}
```

#### Human Readable Output

>### Results
>|Asset Dig Tags|Cloud Environment|Cloud Provider|Encrypted|ID|Lifecycle|Name|Open Alerts Count|Open Risks Count|Open To World|Project ID|Project Name|Service Type|Tags|Data Type Groups|Data Types|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | TESTING | AWS | true | arn:aws:s3:::dymmy-ci0jq3kgvjnccdfp-us-east-1 | RUNNING | dymmy-ci0jq3kgvjnccdfp-us-east-1 | 0 | 0 | false | ************ | ************ | S3 |  |  |  |

### dspm-get-asset-details

***
Retrieves details for the specified asset ID.

#### Base Command

`dspm-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset for which to retrieve details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AssetDetails.assetDigTags | Unknown | The dig tags associated with the asset. | 
| DSPM.AssetDetails.cloudEnvironment | String | The cloud environment in which the asset exists. | 
| DSPM.AssetDetails.cloudProvider | String | The cloud provider for the asset \(e.g., AWS, Azure, GCP\). | 
| DSPM.AssetDetails.dataTypeGroups | Unknown | Groups of data types associated with the asset. | 
| DSPM.AssetDetails.dataTypes | Unknown | The data types related to the asset. | 
| DSPM.AssetDetails.encrypted | Boolean | Indicates if the asset is encrypted. | 
| DSPM.AssetDetails.id | String | The unique identifier of the asset. | 
| DSPM.AssetDetails.lifecycle | String | The lifecycle status of the asset. | 
| DSPM.AssetDetails.name | String | The name of the asset. | 
| DSPM.AssetDetails.openAlertsCount | Number | The count of open alerts for the asset. | 
| DSPM.AssetDetails.openRisksCount | Number | The count of open risks for the asset. | 
| DSPM.AssetDetails.openToWorld | Boolean | Indicates if the asset is open to the world. | 
| DSPM.AssetDetails.projectId | String | The ID of the project associated with the asset. | 
| DSPM.AssetDetails.projectName | String | The name of the project associated with the asset. | 
| DSPM.AssetDetails.serviceType | String | The type of service associated with the asset. | 
| DSPM.AssetDetails.tags | Unknown | Tags related to the asset. | 

#### Command example
```!dspm-get-asset-details asset_id="arn:aws:s3:::dummyS3-cifp-us-east-1"```
#### Context Example
```json
{
    "DSPM": {
        "AssetDetails": {
            "assetDigTags": [],
            "cloudEnvironment": "TESTING",
            "cloudProvider": "AWS",
            "dataTypeGroups": [],
            "dataTypes": [],
            "encrypted": true,
            "id": "arn:aws:s3:::dummyS3-cifp-us-east-1",
            "lifecycle": "RUNNING",
            "name": "dymmy-ci0jq3kgvjnccdfp-us-east-1",
            "openAlertsCount": 0,
            "openRisksCount": 0,
            "openToWorld": false,
            "projectId": "************",
            "projectName": "************",
            "serviceType": "S3",
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### Results
>|assetDigTags|cloudEnvironment|cloudProvider|dataTypeGroups|dataTypes|encrypted|id|lifecycle|name|openAlertsCount|openRisksCount|openToWorld|projectId|projectName|serviceType|tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|   | TESTING | AWS |  |  | true | arn:aws:s3:::dummyS3-cifp-us-east-1 | RUNNING | dymmy-ci0jq3kgvjnccdfp-us-east-1 | 0 | 0 | false | ************ | ************ | S3 |  |

### dspm-get-asset-files-by-id

***
Retrieves file details for the specified asset ID.

#### Base Command

`dspm-get-asset-files-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset for which to retrieve file details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AssetFiles.filename | String | Asset file name. | 
| DSPM.AssetFiles.path | String | Asset file path. | 
| DSPM.AssetFiles.type | String | Asset file type. | 
| DSPM.AssetFiles.size | String | Asset file size. | 
| DSPM.AssetFiles.openToWorld | Boolean | Whether the asset is open to world. | 
| DSPM.AssetFiles.isDeleted | Boolean | Whether the asset is deleted. | 
| DSPM.AssetFiles.isMalicious | Boolean | Whether the asset is malicious. | 
| DSPM.AssetFiles.dataTypes.name | String | Asset file data types name. | 
| DSPM.AssetFiles.dataTypes.label | String | Asset file data types label. | 
| DSPM.AssetFiles.dataTypes.count | Number | Asset file data types count. | 
| DSPM.AssetFiles.dataTypes.valueDetails.masked_value | String | Asset file data types value detail masked value. | 
| DSPM.AssetFiles.dataTypes.valueDetails.line | Number | Asset file data types value detail line. | 
| DSPM.AssetFiles.labels | String | Asset file labels. | 
| DSPM.AssetFiles.isDbDump | Boolean | Asset file is a database dump. | 

#### Command example
```!dspm-get-asset-files-by-id asset_id="arn:aws:s3:::dummyS3-cifp-us-east-1"```
#### Context Example
```json
{
    "files": [
        {
            "filename": "268d4e2d-03f2-4044-b82d-8855b2e77f8d.csv",
            "path": "268d4e2d-03f2-4044-b82d-8855b2e77f8d.csv",
            "type": "Data Format",
            "size": "17081",
            "openToWorld": true,
            "isDeleted": false,
            "isMalicious": false,
            "dataTypes": [
                {
                    "name": "IP Address",
                    "label": "Sensitive",
                    "count": 100,
                    "valueDetails": [
                        {
                            "masked_value": "20.163.*.*",
                            "line": 3
                        },
                        {
                            "masked_value": "38.229.*.*",
                            "line": 4
                        },
                        {
                            "masked_value": "45.136.*.*",
                            "line": 5
                        }
                    ]
                },
                {
                    "name": "Internal IP Address",
                    "label": "Sensitive",
                    "count": 100,
                    "valueDetails": [
                        {
                            "masked_value": "10.0.*.*",
                            "line": 2
                        },
                        {
                            "masked_value": "10.0.*.*",
                            "line": 8
                        },
                        {
                            "masked_value": "10.0.*.*",
                            "line": 14
                        }
                    ]
                }
            ],
            "labels": [
                "Sensitive"
            ],
            "isDbDump": false
        },
        {
            "filename": "data security test cases.pdf",
            "path": "data security test cases.pdf",
            "type": "Document",
            "size": "73286",
            "openToWorld": true,
            "isDeleted": false,
            "isMalicious": false,
            "dataTypes": [
                {
                    "name": "Street Address",
                    "label": "Sensitive",
                    "count": 1,
                    "valueDetails": [
                        {
                            "masked_value": "3** E*** R******* Street",
                            "line": null
                        }
                    ]
                },
                {
                    "name": "Email Address",
                    "label": "PII",
                    "count": 1,
                    "valueDetails": [
                        {
                            "masked_value": "t**t@b****l.com",
                            "line": null
                        }
                    ]
                }
            ],
            "labels": [
                "PII",
                "Sensitive"
            ],
            "isDbDump": false
        }
    ],
    "filesCount": 2
}
```

#### Human Readable Output

>|filename|path|type|size|openToWorld|isDeleted|isMalicious|dataTypes|labels|isDbDump|
>|---|---|---|---|---|---|---|---|---|---|
>|268d4e2d-03f2-4044-b82d-8855b2e77f8d.csv|268d4e2d-03f2-4044-b82d-8855b2e77f8d.csv|Data Format|17081|true|false|false|IP Address (Sensitive), Internal IP Address (Sensitive)|Sensitive|false|
>|data security test cases.pdf|data security test cases.pdf|Document|73286|true|false|false|Street Address (Sensitive), Email Address (PII)|PII, Sensitive|false|

### dspm-get-list-of-asset-fields-by-id

***
Return list of fields for structured assets such as RDS, Aurora, and BigQuery.

#### Base Command

`dspm-get-list-of-asset-fields-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assetId | ID of the asset for which to retrieve field details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AssetFields.name | String | Asset field name. | 
| DSPM.AssetFields.path | String | Asset field path. | 
| DSPM.AssetFields.tableName | String | Asset field table name. | 
| DSPM.AssetFields.tableSize | String | Asset field table size. | 
| DSPM.AssetFields.databaseName | String | Asset field database name. | 
| DSPM.AssetFields.collectionName | String | Asset field collection name. | 
| DSPM.AssetFields.type | String | Asset field type. | 
| DSPM.AssetFields.dataTypes.name | String | Asset field data type name. | 
| DSPM.AssetFields.dataTypes.label | String | Asset field data type label. | 
| DSPM.AssetFields.dataTypes.hitPercentage | Number | Asset field data type hit percentage. | 
| DSPM.AssetFields.dataTypes.maskedValues.masked_value | String | Asset field datat ype masked value. | 
| DSPM.AssetFields.dataTypes.maskedValues.line | Number | Asset field data type masked value line. | 
| DSPM.AssetFields.schemaName | String | Asset field schema name. | 

#### Command example
```!dspm-get-list-of-asset-fields-by-id assetId="arn:aws:rds:::dummyrds-cifp-us-east-1"```
#### Context Example
```json
{
    "fields": [
        {
            "name": "maidenname",
            "dataTypes": [],
            "path": "/public/dummy",
            "tableName": "dummy",
            "tableSize": "29996",
            "databaseName": "Hi",
            "collectionName": null,
            "type": "varchar",
            "schemaName": "public"
        },
        {
            "name": "phone",
            "dataTypes": [],
            "path": "/public/dummy",
            "tableName": "dummy",
            "tableSize": "29996",
            "databaseName": "Hi",
            "collectionName": null,
            "type": "varchar",
            "schemaName": "public"
        }
    ],
    "fieldsCount": 2
}
```

#### Human Readable Output

## Asset Fields

| name | dataTypes | path | tableName | tableSize | databaseName | collectionName | type | schemaName |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| maidenname | [] | /public/dummy | dummy | 29996 | Hi | null | varchar | public |
| maidenname | [] | /public/dummy | dummy | 29996 | Hi | null | varchar | public |

### dspm-get-data-types

***
Fetches the available data types for the DSPM integration.

#### Base Command

`dspm-get-data-types`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.DataTypes.Key | String | Data types key. | 
| DSPM.DataTypes.No | Number | Data types number. | 

#### Command example
```!dspm-get-data-types```
#### Context Example
```json
{
    "DSPM": {
        "DataTypes": [
            {
                "Key": "ID Number - Aadhaar (India)",
                "No": 1
            },
            {
                "Key": "Artifactory API Key",
                "No": 2
            },
            {
                "Key": "AWS Secret Key",
                "No": 3
            },
            {
                "Key": "Credit Card Expiration Date",
                "No": 4
            },
            {
                "Key": "Certificate",
                "No": 5
            }
        ]
    }
}
```

#### Human Readable Output

>### Data Types
> | No | Key  |
> |----|------|
>| 1  | ID Number - Aadhaar (India) |
>| 2  | Artifactory API Key |
>| 3  | AWS Secret Key |
>| 4  | Credit Card Expiration Date |
>| 5  | Certificate |

### dspm-list-labels

***
Returns a list of label names based on the company.

#### Base Command

`dspm-list-labels`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.Label.Key | String | Label key. | 
| DSPM.Label.No | unknown | Label number. | 

#### Command example
```!dspm-list-labels```
#### Context Example
```json
{
    "DSPM": {
        "Label": [
            {
                "Key": "PCI",
                "No": 1
            },
            {
                "Key": "PHI",
                "No": 2
            },
            {
                "Key": "PII",
                "No": 3
            },
            {
                "Key": "Confidential",
                "No": 4
            },
            {
                "Key": "Sensitive",
                "No": 5
            }
        ]
    }
}
```

#### Human Readable Output

>### Data Types
> | No | Key  |
> |----|------|
>| 1  | PCI |
>| 2  | PHI |
>| 3  | PII |
>| 4  | Confidential |
>| 5  | Sensitive |

### dspm-list-data-types-findings

***
Retrieves a list of data type findings for the company.

#### Base Command

`dspm-list-data-types-findings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region_in | A comma-separated list of regions. | Optional | 
| region_equal | The exact region. | Optional | 
| cloud_provider_in | A comma-separated list of cloud providers. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| cloud_provider_equal | The exact cloud provider. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| service_type_in | A comma-separated list of service types. | Optional | 
| service_type_equal | The exact service type. | Optional | 
| lifecycle_in | A comma-separated list of life cycles. | Optional | 
| projectId_in | A comma-separated list of project IDs. | Optional | 
| projectId_equal | The exact project ID. | Optional | 
| lifecycle_equal | The exact life cycle. | Optional | 
| sort | The sorting criteria in the format: property,(asc\|desc). Default sort order is ascending. Multiple sort criteria are supported. | Optional | 
| limit | The maximum number of data types findings to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.DataTypesFinding.dataTypeName | String | Represents the name of the data type being analyzed. | 
| DSPM.DataTypesFinding.label | String | Label associated with the data type, such as PII. | 
| DSPM.DataTypesFinding.records | Integer | The number of records associated with the data type. | 
| DSPM.DataTypesFinding.publicRecords | Integer | The number of public records found for this data type. | 
| DSPM.DataTypesFinding.assets | Integer | The number of assets associated with this data type. | 
| DSPM.DataTypesFinding.clouds | String | The clouds where the data type was found \(e.g., AWS, Azure\). | 
| DSPM.DataTypesFinding.regions | String | The regions where the data type was found. | 
| DSPM.DataTypesFinding.lastFound | Date | The timestamp when the data type was last found. | 
| DSPM.DataTypesFinding.recordsAtRisk.high | Integer | The number of high-risk records found for this data type. | 
| DSPM.DataTypesFinding.recordsAtRisk.medium | Integer | The number of medium-risk records found for this data type. | 
| DSPM.DataTypesFinding.recordsAtRisk.low | Integer | The number of low-risk records found for this data type. | 

#### Command example
```!dspm-list-data-types-findings cloudProviderEqual=AWS```
#### Context Example
```json
[{
        "dataTypeName": "AADHAAR_INDIVIDUAL_IDENTIFICATION",
        "label": "PII",
        "records": 4,
        "publicRecords": 0,
        "assets": 1,
        "clouds": [
            "AWS"
        ],
        "regions": [
            "us-east-1"
        ],
        "lastFound": "2024-05-09T03:24:29Z",
        "recordsAtRisk": {
            "high": 0,
            "medium": 4,
            "low": 0
        }
}]
```

#### Human Readable Output

>### Data Types Findings
| dataTypeName | label | records | publicRecords | assets | clouds | regions | lastFound | recordsAtRisk.high | recordsAtRisk.medium | recordsAtRisk.low |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AADHAAR_INDIVIDUAL_IDENTIFICATION | PII | 4 | 0 | 1 | AWS | us-east-1 | 2024-05-09T03:24:29Z | 0 | 4 | 0 |


### dspm-update-risk-finding-status

***
Updates the status of a risk finding.

#### Base Command

`dspm-update-risk-finding-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risk_finding_id | Risk Finding ID. | Required | 
| status | List of supported statuses. Possible values are: OPEN, CLOSED, UNIMPORTANT, WRONG, HANDLED, INVESTIGATING. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.RiskFindingStatusUpdate.newStatus | String | Updated risk finding status. | 
| DSPM.RiskFindingStatusUpdate.oldStatus | String | Old risk finding status. | 
| DSPM.RiskFindingStatusUpdate.riskFindingId | String | Risk finding ID. | 

#### Command example
```!dspm-update-risk-finding-status riskFindingId="00000000-0000-4f99-0000-616843b6b19e" status=INVESTIGATING```
#### Context Example
```json
{
    "DSPM": {
        "RiskFindingStatusUpdate": {
            "newStatus": "INVESTIGATING",
            "oldStatus": "INVESTIGATING",
            "riskFindingId": "00000000-0000-4f99-0000-616843b6b19e"
        }
    }
}
```

#### Human Readable Output

>### Risk Status Update
>|Risk Finding ID|Old Status|New Status|
>|---|---|---|
>| 00000000-0000-4f99-0000-616843b6b19e | INVESTIGATING | INVESTIGATING |

### dspm-update-alert-status

***
Updates the status of an alert.

#### Base Command

`dspm-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | Alert ID. | Required | 
| status | List of supported statuses. Possible values are: OPEN, UNIMPORTANT, WRONG, HANDLED, INVESTIGATING. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AlertStatusUpdate.newStatus | String | Updated alert status. | 
| DSPM.AlertStatusUpdate.oldStatus | String | Old alert status. | 
| DSPM.AlertStatusUpdate.alertId | String | Alert ID. | 

#### Command example
```!dspm-update-alert-status alertId="000000608" status=INVESTIGATING```
#### Context Example
```json
{
    "DSPM": {
        "AlertStatusUpdate": {
            "newStatus": "INVESTIGATING",
            "oldStatus": "INVESTIGATING",
            "alertId": "000000608"
        }
    }
}
```

#### Human Readable Output

>### Alert Status Update
>| Alert ID | Old Status | New Status |
>|---|---|---|
>| 000000608 | INVESTIGATING | INVESTIGATING |

### dspm-list-alerts

***
Fetch list of alerts.

#### Base Command

`dspm-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detection_time_equals | The exact detection time (equals). detection time format - YYYY-MM-DDTHH:MM:SSZ. | Optional | 
| detection_time_greater_than_or_equal | Detection time (greater than or equal). detection time format - YYYY-MM-DDTHH:MM:SSZ. | Optional | 
| detection_time_greater_than | Detection time (greater than). detection time format - YYYY-MM-DDTHH:MM:SSZ. | Optional | 
| detection_time_less_than_or_equal | Detection time (less than or equal). detection time format - YYYY-MM-DDTHH:MM:SSZ. | Optional | 
| detection_time_less_than | Detection time (less than). detection time format - YYYY-MM-DDTHH:MM:SSZ. | Optional | 
| policy_name_in | A comma-separated list of policy names. | Optional | 
| policy_name_equals | The exact policy name. | Optional | 
| asset_name_in | A comma-separated list of asset names. | Optional | 
| asset_name_equals | The exact asset name. | Optional | 
| cloud_provider_in | A comma-separated list of cloud providers. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| cloud_provider_equals | The exact cloud provider. Possible values are: AWS, AZURE, GCP, SNOWFLAKE, FILE_SHARE, O365. | Optional | 
| destination_project_vendor_name_in | A comma-separated list of project vendor names. | Optional | 
| destination_project_vendor_name_equals | The exact destination project vendor name. | Optional | 
| cloud_environment_in | A comma-separated list of cloud environments. Possible values are: UNKNOWN, DEVELOPMENT, STAGING, TESTING, PRODUCTION. | Optional | 
| cloud_environment_equals | The exact cloud environment. Possible values are: UNKNOWN, DEVELOPMENT, STAGING, TESTING, PRODUCTION. | Optional | 
| policy_severity_in | A comma-separated list of policy severities. Possible values are: HIGH, MEDIUM, LOW. | Optional | 
| policy_severity_equals | The exact policy severity. Possible values are: HIGH, MEDIUM, LOW. | Optional | 
| category_type_in | A comma-separated list of category types. Possible values are: FIRST_MOVE, ATTACK, COMPLIANCE, ASSET_AT_RISK, RECONNAISSANCE. | Optional | 
| category_type_equals | The exact category type. Possible values are: FIRST_MOVE, ATTACK, COMPLIANCE, ASSET_AT_RISK, RECONNAISSANCE. | Optional | 
| status_in | A comma-separated list of statuses. Possible values are: OPEN, CLOSED, UNIMPORTANT, WRONG, HANDLED, INVESTIGATING. | Optional | 
| status_equals | The exact status. Possible values are: OPEN, CLOSED, UNIMPORTANT, WRONG, HANDLED, INVESTIGATING. | Optional | 
| sort | Sort order (property,asc\|desc). | Optional | 
| limit | The maximum number of alerts to retrieve. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.Alert.id | String | Alert ID. | 
| DSPM.Alert.detectionTime | Date | Alert detection time. | 
| DSPM.Alert.policyName | String | Alert policy name. | 
| DSPM.Alert.assetName | String | Alert asset name. | 
| DSPM.Alert.assetLabels | Unknown | Alert asset label. | 
| DSPM.Alert.cloudProvider | String | Alert cloud provider. | 
| DSPM.Alert.destinationProjects | Unknown | Alert destination projects. | 
| DSPM.Alert.cloudEnvironment | String | Alert cloud enviroment. | 
| DSPM.Alert.policySeverity | String | Alert policy severity. | 
| DSPM.Alert.policyCategoryType | String | Alert policy category type. | 
| DSPM.Alert.status | String | Alert status. | 
| DSPM.Alert.eventActor | String | Alert event actor. | 
| DSPM.Alert.eventUserAgent | String | Alert event user agent. | 
| DSPM.Alert.eventActionMedium | String | Alert event action medium. | 
| DSPM.Alert.eventSource | String | Alert event source. | 
| DSPM.Alert.policyFrameWorks | String | Alert policy frameworks. | 
| DSPM.Alert.eventRawData | String | Alert event raw data. | 

#### Command example
```!dspm-list-alerts cloudEnvironmentEquals="TESTING"```
#### Context Example
```json
{
    "DSPM": {
        "Alerts": [
    {
        "id": "340256006",
        "detectionTime": "2024-08-07T18:55:50.64996Z",
        "policyName": "Asset made public",
        "assetName": "mikeys3",
        "assetLabels": [],
        "cloudProvider": "AWS",
        "destinationProjects": {},
        "cloudEnvironment": "TESTING",
        "policySeverity": "HIGH",
        "policyCategoryType": "ATTACK",
        "status": "OPEN",
        "eventActor": "dummy_email",
        "eventUserAgent": "[S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.488 Linux/5.10.220-187.867.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.372-b08 java/1.8.0_372 vendor/Oracle_Corporation cfg/retry-mode/standard]",
        "eventActionMedium": "CONSOLE",
        "eventSource": "***.**.**.***.***",
        "policyFrameWorks": [
            "MITRE-T1098"
        ],
        "eventRawData": "{\"eventVersion\":\"1.09\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"AROASI3QR4HKUAIEPBICG:dummy_email\",\"arn\":\"arn:aws:sts::576847873638:assumed-role/sso_admin-tac-nam/dummy_email\",\"accountId\":\"576847873638\",\"accessKeyId\":\"ASIASI3QR4HK2LDI5JMN\",\"sessionContext\":{\"sessionIssuer\":{\"type\":\"Role\",\"principalId\":\"AROASI3QR4HKUAIEPBICG\",\"arn\":\"arn:aws:iam::576847873638:role/sso_admin-tac-nam\",\"accountId\":\"576847873638\",\"userName\":\"sso_admin-tac-nam\"},\"attributes\":{\"creationDate\":\"2024-08-07T18:51:51Z\",\"mfaAuthenticated\":\"false\"}}},\"eventTime\":\"2024-08-07T18:55:37Z\",\"eventSource\":\"s3.amazonaws.com\",\"eventName\":\"PutBucketPolicy\",\"awsRegion\":\"us-east-1\",\"sourceIPAddress\":\"***.**.**.***.***\",\"userAgent\":\"[S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.488 Linux/5.10.220-187.867.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.372-b08 java/1.8.0_372 vendor/Oracle_Corporation cfg/retry-mode/standard]\",\"requestParameters\":{\"bucketPolicy\":{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Statement1\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":[\"s3:AbortMultipartUpload\",\"s3:DeleteObject\",\"s3:GetObject\",\"s3:ListBucketMultipartUploads\",\"s3:ListMultipartUploadParts\",\"s3:PutObject\"],\"Resource\":[\"arn:aws:s3:::mikeys3\",\"arn:aws:s3:::mikeys3/*\"]}]},\"bucketName\":\"mikeys3\",\"Host\":\"s3.amazonaws.com\",\"policy\":\"\"},\"responseElements\":null,\"additionalEventData\":{\"SignatureVersion\":\"SigV4\",\"CipherSuite\":\"TLS_AES_128_GCM_SHA256\",\"bytesTransferredIn\":568,\"AuthenticationMethod\":\"AuthHeader\",\"x-amz-id-2\":\"KXHYo+o2L/Gnk0pmKY+gV+0YufF6uGyD3GRwK+FXEJ7eai772ytOzbV9CwwoezhB5PPR/6RxZyhOyBowBOyQih\",\"bytesTransferredOut\":0},\"requestID\":\"CJ3J7M851NAGAF58\",\"eventID\":\"df06b9ad-79dc-4a17-ae0e-82ecff9cfa5e\",\"readOnly\":false,\"resources\":[{\"accountId\":\"576847873638\",\"type\":\"AWS::S3::Bucket\",\"ARN\":\"arn:aws:s3:::mikeys3\"}],\"eventType\":\"AwsApiCall\",\"managementEvent\":true,\"recipientAccountId\":\"576847873638\",\"vpcEndpointId\":\"vpce-f40dc59d\",\"eventCategory\":\"Management\",\"tlsDetails\":{\"tlsVersion\":\"TLSv1.3\",\"cipherSuite\":\"TLS_AES_128_GCM_SHA256\",\"clientProvidedHostHeader\":\"s3.amazonaws.com\"}}"
    }
   ]
    }
}
```

#### Human Readable Output

>### DSPM Alert
>| Alert ID | Detection Time | Policy Name | Asset Name | Cloud Provider | Cloud Environment | Policy Severity | Policy Category | Status | Event Actor | Event Action Medium | Event Source | Policy Frameworks | eventRawData |
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 340256006 | 2024-08-07T18:55:50.64996Z | Asset made public | mikeys3 | AWS | TESTING | HIGH | ATTACK | OPEN | dummy_email | CONSOLE | ***.**.**.***.*** | MITRE-T1098 | "{\"eventVersion\":\"1.09\",\"userIdentity\":{\"type\":\"AssumedRole\",\"principalId\":\"AROASI3QR4HKUAIEPBICG:dummy_email\",\"arn\":\"arn:aws:sts::576847873638:assumed-role/sso_admin-tac-nam/dummy_email\",\"accountId\":\"576847873638\",\"accessKeyId\":\"ASIASI3QR4HK2LDI5JMN\",\"sessionContext\":{\"sessionIssuer\":{\"type\":\"Role\",\"principalId\":\"AROASI3QR4HKUAIEPBICG\",\"arn\":\"arn:aws:iam::576847873638:role/sso_admin-tac-nam\",\"accountId\":\"576847873638\",\"userName\":\"sso_admin-tac-nam\"},\"attributes\":{\"creationDate\":\"2024-08-07T18:51:51Z\",\"mfaAuthenticated\":\"false\"}}},\"eventTime\":\"2024-08-07T18:55:37Z\",\"eventSource\":\"s3.amazonaws.com\",\"eventName\":\"PutBucketPolicy\",\"awsRegion\":\"us-east-1\",\"sourceIPAddress\":\"***.**.**.***.***\",\"userAgent\":\"[S3Console/0.4, aws-internal/3 aws-sdk-java/1.12.488 Linux/5.10.220-187.867.amzn2int.x86_64 OpenJDK_64-Bit_Server_VM/25.372-b08 java/1.8.0_372 vendor/Oracle_Corporation cfg/retry-mode/standard]\",\"requestParameters\":{\"bucketPolicy\":{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"Statement1\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":[\"s3:AbortMultipartUpload\",\"s3:DeleteObject\",\"s3:GetObject\",\"s3:ListBucketMultipartUploads\",\"s3:ListMultipartUploadParts\",\"s3:PutObject\"],\"Resource\":[\"arn:aws:s3:::mikeys3\",\"arn:aws:s3:::mikeys3/*\"]}]},\"bucketName\":\"mikeys3\",\"Host\":\"s3.amazonaws.com\",\"policy\":\"\"},\"responseElements\":null,\"additionalEventData\":{\"SignatureVersion\":\"SigV4\",\"CipherSuite\":\"TLS_AES_128_GCM_SHA256\",\"bytesTransferredIn\":568,\"AuthenticationMethod\":\"AuthHeader\",\"x-amz-id-2\":\"KXHYo+o2TWL/Gnk0pmKY+gV+0YufF6uGyD3GRwK+FXEJ7eai772ytOzbV9CwwoBq+pezhB5PPR/6RxZyhOyZltIBowBOyQih\",\"bytesTransferredOut\":0},\"requestID\":\"CJ3J7M851NAGAF58\",\"eventID\":\"df06b9ad-79dc-4a17-ae0e-82ecff9cfa5e\",\"readOnly\":false,\"resources\":[{\"accountId\":\"576847873638\",\"type\":\"AWS::S3::Bucket\",\"ARN\":\"arn:aws:s3:::mikeys3\"}],\"eventType\":\"AwsApiCall\",\"managementEvent\":true,\"recipientAccountId\":\"576847873638\",\"vpcEndpointId\":\"vpce-f40dc59d\",\"eventCategory\":\"Management\",\"tlsDetails\":{\"tlsVersion\":\"TLSv1.3\",\"cipherSuite\":\"TLS_AES_128_GCM_SHA256\",\"clientProvidedHostHeader\":\"s3.amazonaws.com\"}}"

----------------