Remediate your data security risks. Integrate with Prisma Cloud DSPM to fetch your data security risks and remediate them with OOTB playbooks.

This integration was integrated and tested with version xx of DSPM.

## Configure Prisma Cloud DSPM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Prisma Cloud DSPM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your DSPM server URL |  | True |
    | DSPM API Key | API key to use for the connection | True |
    | Your Jira server URL |  | True |
    | Your Jira user name (email). |  | True |
    | JIRA API Token | API token for Jira connection | True |
    | Azure Storage Account name |  | True |
    | Azure Storage Shared Key | The shared API key available in the Azure Storage Account | True |
    | GCP Service Account JSON |  | True |
    | Lifetime for slack notification ( in hours) |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, tokens, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

### dspm-get-risk-finding-by-id

***
Retrieves risk details for the provided risk ID.

#### Base Command

`dspm-get-risk-finding-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| finding_id | ID of the risk to retrieve details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.RiskFinding | String | Details of the risk finding for the provided ID. | 

### dspm-get-list-of-assets

***
for retrieve list of assets for company.

#### Base Command

`dspm-get-list-of-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regionIn | List of regions (comma separated values). | Optional | 
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
| DSPM.Assets | String | List of assets for company. | 

### dspm-get-asset-details

***
Retrieves asset details for the provided asset ID.

#### Base Command

`dspm-get-asset-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset to retrieve details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AssetDetails | String | Details of the asset for the provided ID. | 

### dspm-get-asset-files-by-id

***
Retrieves asset file details for the provided asset ID.

#### Base Command

`dspm-get-asset-files-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | ID of the asset to retrieve details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.AssetFiles | String | File Details of the asset for the provided ID. | 

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

### dspm-get-data-types-findings

***
for retrieve list of data type findings for company.

#### Base Command

`dspm-get-data-types-findings`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| regionIn | List of regions (comma separated values). | Optional | 
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
| DSPM.DataTypeFindings | String | List of data type findings for company. | 

### fetch-incidents

***
for testing the fetch-handle method.

#### Base Command

`fetch-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### dspm-get-integration-cofig

***
for getting integration config.

#### Base Command

`dspm-get-integration-cofig`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DSPM.configs | String | Integration configuration values. | 

### dspm-get-lifetime-for-slack

***
waiting time for user response

#### Base Command

`dspm-get-lifetime-for-slack`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
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

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Prisma Cloud DSPM corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:
1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Prisma Cloud DSPM.
