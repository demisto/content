# Overview
The Prisma Cloud DSPM(Data Security Posture Management) Integration enhances the management and remediation of DSPM risks. The integration provides users with actionable data, insights and a seamless workflow for addressing potential security threats.

# Use Cases
- Remediation of DSPM out-of-the-box risks based on automated playbooks.
- Close or update risks by Interacting with DSPM API using a dedicated list of building blocks.
- Distribute DSPM risks to other systems.

# Prerequisites
 1. An active Prisma Cloud DSPM account. 
 2. Slack V3 Pack.
 3. AWS-S3 Pack.
 4. Core REST APIs pack.
 5. Atlassian Jira v3 Pack.
 6. Google Cloud Storage Pack. ( Optional )
 7. Azure Storage Container Pack. ( Optional )

## Configure Prisma Cloud DSPM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma Cloud DSPM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | DSPM server URL | The tenant URL of the Prisma Cloud DSPM | True |
    | DSPM API Key | API key to use for the connection | True |
    | Default Slack user for notifications | the default user to receive Slack notifications in case of any errors | True |
    | Azure Storage Account name |  | False |
    | Azure Storage Shared Key | The shared API key available in the Azure Storage Account | False |
    | GCP Service Account JSON |  | False |
    | Lifetime for slack notification (in hours) |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, tokens, and connection.

## Commands

Prisma Cloud DSPM pack allows the users to execute individual commands on the Cortex XSOAR CLI to gain more insights/data about their DSPM risk(s).
The following commands can be executed as a part of an automation or playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### dspm-get-risk-findings

***
Retrieves risk findings matching the input criteria.

#### Base Command

`dspm-get-risk-findings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ruleNameIn | List of rule names. | Optional | 
| ruleNameEqual | Exact rule name. | Optional | 
| dspmTagKeyIn | List of DSPM tag keys. | Optional | 
| dspmTagKeyEqual | Exact DSPM tag key. | Optional | 
| dspmTagValueIn | List of DSPM tag values. | Optional | 
| dspmTagValueEqual | Exact DSPM tag value. | Optional | 
| projectIdIn | List of project IDs. | Optional | 
| projectIdEqual | Exact project ID. | Optional | 
| cloudProviderIn | List of cloud providers ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional | 
| cloudProviderEqual | Exact cloud provider ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional | 
| affectsIn | List of affects ["SECURITY", "COMPLIANCE", "GOVERNANCE", "SECURITY_AND_COMPLIANCE", "SECURITY_AND_GOVERNANCE", "COMPLIANCE_AND_GOVERNANCE","SECURITY_AND_COMPLIANCE_AND_GOVERNANCE"]. | Optional | 
| affectsEqual | Exact affect ["SECURITY", "COMPLIANCE", "GOVERNANCE", "SECURITY_AND_COMPLIANCE", "SECURITY_AND_GOVERNANCE", "COMPLIANCE_AND_GOVERNANCE","SECURITY_AND_COMPLIANCE_AND_GOVERNANCE"]. | Optional | 
| statusIn | List of statuses ["OPEN", "CLOSED", "UNIMPORTANT", "WRONG", "HANDLED", "INVESTIGATING"]. | Optional | 
| statusEqual | Exact status ["OPEN", "CLOSED", "UNIMPORTANT", "WRONG", "HANDLED", "INVESTIGATING"]. | Optional | 
| sort | Sort order. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.RiskFindings | String | List of risk findings matching the input criteria. | 
| DSPM.RiskFindings.ID |String |The unique ID of the risk finding.
| DSPM.RiskFindings.AssetID |String |The ID of the asset associated with the risk finding.
| DSPM.RiskFindings.AssetName |String |The name of the asset associated with the risk finding.
| DSPM.RiskFindings.ComplianceStandards |String |The compliance standards relevant to the risk finding.
| DSPM.RiskFindings.Severity |String |The severity of the risk finding (e.g., Low, Medium, High).
| DSPM.RiskFindings.RuleName |String |The rule name associated with the risk finding.
| DSPM.RiskFindings.FirstDiscovered |Date |The date the risk finding was first discovered.
| DSPM.RiskFindings.CloudProvider |String |The cloud provider associated with the risk finding (e.g., AWS, Azure, GCP).
| DSPM.RiskFindings.Status |String |The current status of the risk finding (e.g., Open, Closed).
| DSPM.RiskFindings.CloudEnvironment |String |The cloud environment (public or private) associated with the risk finding.
| DSPM.RiskFindings.ProjectID |String |The project ID where the asset resides.

#### Command example
```!dspm-get-risk-findings```
#### Context Example
```json
{
  "DSPM": {
    "RiskFindings": [
      {
        "ID": "riskfinding123",
        "AssetID": "asset123",
        "AssetName": "Example Asset",
        "ComplianceStandards": "PCI-DSS",
        "Severity": "High",
        "RuleName": "Sensitive Data Exposure",
        "FirstDiscovered": "2024-09-01T12:00:00Z",
        "CloudProvider": "AWS",
        "Status": "Open",
        "CloudEnvironment": "Public",
        "ProjectID": "project123"
      }
    ]
  }
}
```

#### Human Readable Output

>### Results
>|Asset ID|Asset Name|Cloud Environment|Cloud Provider|Compliance Standards|First Discovered|ID|Project ID|Rule Name|Severity|Status|
>|---|---|---|---|---|---|---|---|---|---|---|
>| arn:aws:s3:::emptybucketdspm-test | emptybucketdspm-test | UNKNOWN | AWS |  | 2024-09-05T13:40:33.565153Z | 00000000-0000-4f99-0000-616843b6b19e | 774305603864 | Empty storage asset | LOW | INVESTIGATING |

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
| DSPM.RiskFinding | String | Details of the risk finding for the provided ID. | 

#### Command example
```!dspm-get-risk-finding-by-id finding_id="00000000-0000-4f99-0000-616843b6b19e"```
#### Context Example
```json
{
    "DSPM": {
        "RiskFinding": {
            "Asset ID": "arn:aws:s3:::emptybucketdspm-test",
            "Asset Name": "emptybucketdspm-test",
            "Cloud Environment": "UNKNOWN",
            "Cloud Provider": "AWS",
            "Compliance Standards": {},
            "First Discovered": "2024-09-05T13:40:33.565153Z",
            "ID": "00000000-0000-4f99-0000-616843b6b19e",
            "Project ID": "774305603864",
            "Rule Name": "Empty storage asset",
            "Severity": "LOW",
            "Status": "INVESTIGATING"
        }
    }
}
```

#### Human Readable Output

>### Results
>|Asset ID|Asset Name|Cloud Environment|Cloud Provider|Compliance Standards|First Discovered|ID|Project ID|Rule Name|Severity|Status|
>|---|---|---|---|---|---|---|---|---|---|---|
>| arn:aws:s3:::emptybucketdspm-test | emptybucketdspm-test | UNKNOWN | AWS |  | 2024-09-05T13:40:33.565153Z | 00000000-0000-4f99-0000-616843b6b19e | 774305603864 | Empty storage asset | LOW | INVESTIGATING |

### dspm-get-list-of-assets

***
Retrieves a list of assets for the company.

#### Base Command

`dspm-get-list-of-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regionIn | List of regions (comma-separated values). | Optional | 
| regionEqual | Exact region. | Optional | 
| cloudProviderIn | List of cloud providers ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"] (comma separated values). | Optional | 
| cloudProviderEqual | Exact cloud provider ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional | 
| serviceTypeIn | List of Service Types (comma separated values). | Optional | 
| serviceTypeEqual | Exact Service Type. | Optional | 
| lifecycleIn | List of Life Cycles egs.['RUNNING', 'STOPPED', 'DELETED'](comma separated values). | Optional | 
| lifecycleEqual | Exact Life Cycle ['RUNNING', 'STOPPED', 'DELETED']. | Optional | 
| sort | Sorting criteria in the format: property,(asc\|desc). Default sort order is ascending. Multiple sort criteria are supported. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.Assets | String | List of assets for the company. | 

#### Command example
```!dspm-get-list-of-assets cloudProviderEqual=AWS serviceTypeEqual=S3```
#### Context Example
```json
{
    "DSPM": {
        "Assets": {
            "Asset Dig Tags": [],
            "Cloud Environment": "TESTING",
            "Cloud Provider": "AWS",
            "Encrypted": true,
            "ID": "arn:aws:s3:::dummyS3-cifp-us-east-1",
            "Lifecycle": "RUNNING",
            "Name": "appcomposer-ci0jq3kgvjnccdfp-us-east-1",
            "Open Alerts Count": 0,
            "Open Risks Count": 0,
            "Open To World": false,
            "Project ID": "590183896679",
            "Project Name": "590183896679",
            "Service Type": "S3",
            "Tags": {}
        }
    }
}
```

#### Human Readable Output

>### Results
>|Asset Dig Tags|Cloud Environment|Cloud Provider|Encrypted|ID|Lifecycle|Name|Open Alerts Count|Open Risks Count|Open To World|Project ID|Project Name|Service Type|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  | TESTING | AWS | true | arn:aws:s3:::dummyS3-cifp-us-east-1 | RUNNING | appcomposer-ci0jq3kgvjnccdfp-us-east-1 | 0 | 0 | false | 590183896679 | 590183896679 | S3 |  |

### dspm-get-asset-details

***
Retrieves details for the specified asset ID

#### Base Command

`dspm-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset for which to retrieve details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AssetDetails | String | Details of the asset for the provided ID. | 

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
            "name": "appcomposer-ci0jq3kgvjnccdfp-us-east-1",
            "openAlertsCount": 0,
            "openRisksCount": 0,
            "openToWorld": false,
            "projectId": "590183896679",
            "projectName": "590183896679",
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
>|  | TESTING | AWS |  |  | true | arn:aws:s3:::dummyS3-cifp-us-east-1 | RUNNING | appcomposer-ci0jq3kgvjnccdfp-us-east-1 | 0 | 0 | false | 590183896679 | 590183896679 | S3 |  |

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
| DSPM.AssetFiles | String | File Details of the asset for the provided ID. | 

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


### dspm-get-data-types

***

#### Base Command

`dspm-get-data-types`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.DataTypes | String | List of data types for company. | 

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


### dspm-get-data-types-findings

***
Retrieves a list of data type findings for the company.

#### Base Command

`dspm-get-data-types-findings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regionIn | List of regions (comma-separated values). | Optional | 
| regionEqual | Exact region. | Optional | 
| cloudProviderIn | List of cloud providers ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional | 
| cloudProviderEqual | Exact cloud provider ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional | 
| serviceTypeIn | List of Service Types (comma separated values). | Optional | 
| serviceTypeEqual | Exact Service Type. | Optional | 
| lifecycleIn | List of Life Cycles (comma separated values). | Optional | 
| projectIdIn | List of project IDs. | Optional | 
| projectIdEqual | Exact project ID. | Optional | 
| lifecycleEqual | Exact Life Cycle. | Optional | 
| sort | Sorting criteria in the format: property,(asc\|desc). Default sort order is ascending. Multiple sort criteria are supported. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.DataTypeFindings | String | List of data type findings for the company. | 

#### Command example
```!dspm-get-data-types-findings cloudProviderEqual=AWS```
#### Context Example
```json
{
    "DSPM": {
        "DataTypesFindings": {
            "Key": "AADHAAR_INDIVIDUAL_IDENTIFICATION",
            "No": 1
        }
    }
}
```

#### Human Readable Output

>### Data Types
> | No | Key  |
> |----|------|
>| 1  | AADHAAR_INDIVIDUAL_IDENTIFICATION |


### dspm-update-risk-finding-status

***
Updates the status of a risk finding.

#### Base Command

`dspm-update-risk-finding-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| riskFindingId | Risk Finding ID. | Required | 
| status | Updated Status. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.RiskFindingStatusUpdate | String | The updated risk finding. | 

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

----------------


### dspm-get-list-of-alerts

***
Fetch list of alerts.

#### Base Command

`dspm-get-list-of-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| detectionTimeEquals | Exact detection time (equals). | Optional |
| detectionTimeGreaterThanOrEqual | Detection time (greater than or equal). | Optional |
| detectionTimeGreaterThan | Detection time (greater than). | Optional |
| detectionTimeLessThanOrEqual | Detection time (less than or equal). | Optional |
| detectionTimeLessThan | Detection time (less than). | Optional |
| policyNameIn | List of policy names. | Optional |
| policyNameEquals | Exact policy name. | Optional |
| assetNameIn | List of asset names. | Optional |
| assetNameEquals | Exact asset name. | Optional |
| cloudProviderIn | List of cloud providers ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional |
| cloudProviderEquals | Exact cloud provider ["AWS", "AZURE", "GCP", "SNOWFLAKE", "FILE_SHARE", "O365"]. | Optional |
| destinationProjectVendorNameIn | List of destination project vendor names. | Optional |
| destinationProjectVendorNameEquals | Exact destination project vendor name. | Optional |
| cloudEnvironmentIn | List of cloud environments ["UNKNOWN", "DEVELOPMENT", "STAGING", "TESTING", "PRODUCTION"]. | Optional |
| cloudEnvironmentEquals | Exact cloud environment ["UNKNOWN", "DEVELOPMENT", "STAGING", "TESTING", "PRODUCTION"]. | Optional |
| policySeverityIn | List of policy severities ["HIGH", "MEDIUM", "LOW"]. | Optional |
| policySeverityEquals | Exact policy severity ["HIGH", "MEDIUM", "LOW"]. | Optional |
| categoryTypeIn | List of category types ["FIRST_MOVE", "ATTACK", "COMPLIANCE", "ASSET_AT_RISK", "RECONNAISSANCE"]. | Optional |
| categoryTypeEquals | Exact category type ["FIRST_MOVE", "ATTACK", "COMPLIANCE", "ASSET_AT_RISK", "RECONNAISSANCE"]. | Optional |
| statusIn | List of statuses ["OPEN", "UNIMPORTANT", "WRONG", "HANDLED", "INVESTIGATING"]. | Optional |
| statusEquals | Exact status ["OPEN", "UNIMPORTANT", "WRONG", "HANDLED", "INVESTIGATING"]. | Optional |
| sort | Sort order (property, asc|desc). | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.Alerts | String | List of alerts. | 

#### Command example
```!dspm-get-list-of-alerts cloudEnvironmentEquals="TESTING"```
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


### dspm-update-alert-status

***
Updates the status of a alert.

#### Base Command

`dspm-update-alert-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | Alert ID. | Required | 
| status | Updated Status. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AlertStatusUpdate | String | The updated alert. | 

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
>|Alert ID|Old Status|New Status|
>|---|---|---|
>| 000000608 | INVESTIGATING | INVESTIGATING |

----------------
