Unified security and compliance findings management using the AWS Security Hub V2 API.
This integration was integrated and tested with version xx of AWS - Security Hub v2.

Some changes have been made that might affect your existing content.
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-aws---security-hub-v2).

## Configure AWS - Security Hub v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Role Arn |  | False |
| Role Session Name |  | False |
| AWS Default Region |  | True |
| Role Session Duration |  | False |
| Access Key |  | False |
| Secret Key |  | False |
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| PrivateLink service URL. |  | False |
| STS PrivateLink URL. |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch incidents |  | False |
| Incident type |  | False |
| First fetch time | The time range to consider for the initial data fetch, in the format &lt;number&gt; &lt;unit&gt; \(for example, 3 days, 12 hours, 7 minutes\). | False |
| Maximum number of incidents per fetch | The maximum number of findings to fetch per cycle. The maximum is 100. | False |
| Minimum severity to fetch | Only fetch findings with this severity or higher \(based on the OCSF severity_id\). Leave empty to fetch all severities. | False |
| Additional fetch filters | Extra string filters to narrow the fetch, in the same format as the string_filters command argument: "fieldname=&lt;OCSF field&gt;,value=&lt;value&gt;,comparison=&lt;comparison&gt;", multiple entries separated by ";". Combined with the time and severity filters using AND. | False |
| Incident Mirroring Direction | Choose the direction to mirror the finding: Incoming \(from AWS - Security Hub to Cortex XSOAR\), Outgoing \(from Cortex XSOAR to AWS - Security Hub\), or Incoming And Outgoing \(from/to Cortex XSOAR and AWS - Security Hub\). | False |
| Resolve finding of closed incident from XSOAR in AWS Security Hub | When enabled, closing an incident in Cortex XSOAR sets the corresponding finding's status to Resolved in AWS Security Hub \(applies to outgoing mirroring\). | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-securityhub-security-hub-enable

***
Enables AWS Security Hub V2 for the configured account and region. Required IAM Permission: securityhub:EnableSecurityHubV2.

#### Base Command

`aws-securityhub-security-hub-enable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tags | The tags to assign to the Security Hub V2 resource, in the format: key=key1,value=value1;key=key2,value=value2. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityHub.Hub.HubV2Arn | String | The ARN of the enabled Security Hub V2 resource. |

### aws-securityhub-security-hub-disable

***
Disables AWS Security Hub V2 for the configured account and region. Required IAM Permission: securityhub:DisableSecurityHubV2.

#### Base Command

`aws-securityhub-security-hub-disable`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### aws-securityhub-findings-get

***
Retrieves a list of OCSF-formatted findings from AWS Security Hub V2. Required IAM Permission: securityhub:GetFindingsV2.

#### Base Command

`aws-securityhub-findings-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| string_filters | String field filters. Each entry: "fieldname=&lt;OCSF field&gt;,value=&lt;value&gt;,comparison=&lt;EQUALS\|PREFIX\|NOT_EQUALS\|PREFIX_NOT_EQUALS\|CONTAINS_WORD&gt;", multiple entries separated by ";". Comparison defaults to EQUALS. For substring matching use CONTAINS_WORD (CONTAINS/NOT_CONTAINS are not supported by this API). Example: fieldname=severity,value=High,comparison=EQUALS;fieldname=finding_info.title,value=root,comparison=CONTAINS_WORD. | Optional |
| date_filters | Date field filters. Each entry must use EITHER an absolute range ("fieldname=&lt;OCSF field&gt;,start=&lt;ISO8601&gt;,end=&lt;ISO8601&gt;" - both start and end are required) OR a relative DateRange ("fieldname=&lt;OCSF field&gt;,value=&lt;number&gt;,unit=&lt;unit&gt;,comparison=&lt;comparison&gt;" - value is required, unit defaults to DAYS, comparison is optional). "days=&lt;number&gt;" is accepted as a shorthand for "value=&lt;number&gt;,unit=DAYS". Multiple entries separated by ";". Examples: fieldname=finding_info.created_time_dt,start=2024-01-01T00:00:00Z,end=2024-02-01T00:00:00Z OR fieldname=finding_info.modified_time_dt,value=7,unit=DAYS OR fieldname=finding_info.modified_time_dt,days=7. | Optional |
| boolean_filters | Boolean field filters. Each entry: "fieldname=&lt;OCSF field&gt;,value=&lt;true\|false&gt;", multiple entries separated by ";". | Optional |
| number_filters | Number field filters. Each entry: "fieldname=&lt;OCSF field&gt;,&lt;operator&gt;=&lt;number&gt;" where operator is one of eq/gt/gte/lt/lte. Multiple operators may be combined in a single entry, and multiple entries are separated by ";". Examples: fieldname=severity_id,gte=4 OR fieldname=severity_id,gte=4,lte=6. | Optional |
| map_filters | Map field filters. Each entry: "fieldname=&lt;OCSF field&gt;,key=&lt;key&gt;,value=&lt;value&gt;,comparison=&lt;EQUALS\|NOT_EQUALS&gt;", multiple entries separated by ";". Comparison defaults to EQUALS. | Optional |
| ip_filters | IP field filters. Each entry: "fieldname=&lt;field&gt;,cidr=&lt;IP address&gt;", multiple entries separated by ";". Allowed fieldname values: evidences.src_endpoint.ip, evidences.dst_endpoint.ip. The cidr value must be a plain IPv4 or IPv6 address (CIDR ranges like 10.0.0.0/8 are not accepted). Example: fieldname=evidences.src_endpoint.ip,cidr=10.0.0.1. | Optional |
| filter_operator | The logical operator used to combine the filter conditions within the composite filter. Possible values are: AND, OR. Default is AND. | Optional |
| composite_operator | The logical operator used to combine multiple composite filters. Possible values are: AND, OR. Default is AND. | Optional |
| sort_field | The finding field to sort the results by. | Optional |
| sort_order | The order to sort the results by. Possible values are: asc, desc. | Optional |
| limit | The maximum number of findings to return. Default is 50. | Optional |
| next_token | The pagination token returned from a previous request, used to retrieve the next set of results. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityHub.Findings | Unknown | The list of OCSF-formatted findings returned by Security Hub V2. Each finding is a free-form OCSF object containing fields such as metadata, finding_info, severity, status, cloud, resources, and time. |
| AWS.SecurityHub.FindingsNextToken | String | The pagination token to use when requesting the next set of findings. |

### aws-securityhub-findings-batch-update

***
Updates one or more AWS Security Hub V2 findings in a single batch request. Findings are targeted by metadata_uids and/or finding_identifiers. Required IAM Permission: securityhub:BatchUpdateFindingsV2.

#### Base Command

`aws-securityhub-findings-batch-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| metadata_uids | A comma-separated list of OCSF finding metadata UIDs to update. Each UID must be a 64-character lowercase hexadecimal string (pattern ^[0-9a-z]{64}$), exactly as returned in the metadata.uid field by aws-securityhub-findings-get. | Optional |
| finding_identifiers | Composite finding identifiers to update. Each entry: "cloud_account_uid=&lt;id&gt;,finding_info_uid=&lt;id&gt;,metadata_product_uid=&lt;id&gt;", multiple entries separated by ";". | Optional |
| comment | The reason for updating the findings. | Optional |
| severity_id | The new OCSF severity ID to assign to the findings (e.g., 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal). | Optional |
| status_id | The new OCSF status ID to assign to the findings (e.g., 1=New, 2=In Progress, 3=Suppressed, 4=Resolved). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.SecurityHub.BatchUpdateFindings.ProcessedFindings | Unknown | The list of findings that were successfully updated. |
| AWS.SecurityHub.BatchUpdateFindings.UnprocessedFindings | Unknown | The list of findings that could not be updated, including the error for each. |

### get-remote-data

***
Returns the updated data of a single mirrored AWS Security Hub V2 finding. This command is used for mirroring and is not intended to be run manually.

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The finding metadata UID to retrieve. | Required |
| lastUpdate | A date string in local time representing the last time the incident was updated. | Optional |

#### Context Output

There is no context output for this command.

### get-mapping-fields

***
Returns the list of fields available for outgoing mirroring. This command is used for mirroring and is not intended to be run manually.

#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### update-remote-system

***
Pushes local (Cortex XSOAR) incident changes to the corresponding AWS Security Hub V2 finding. This command is used for mirroring and is not intended to be run manually.

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| remoteId | The remote finding metadata UID to update. | Optional |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and AWS - Security Hub v2 corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in AWS - Security Hub v2 events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in AWS - Security Hub v2 events (outgoing mirrored fields). |
    | Incoming And Outgoing | Changes in Cortex XSOAR incidents and AWS - Security Hub v2 events will be reflected in both directions. |

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and AWS - Security Hub v2.
