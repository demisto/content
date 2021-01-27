Lacework provides end-to-end cloud security automation for AWS, Azure, and GCP with a comprehensive view of risks across cloud workloads and containers.
This integration was integrated and tested with version 3.32 of Lacework
## Configure Lacework on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Lacework.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| lacework_account | Lacework Account Name \(i.e. Subdomain of the URL: &amp;lt;ACCOUNT&amp;gt;.lacework.net\) | True |
| lacework_api_key | Lacework API Key | True |
| lacework_api_secret | Lacework API Secret | True |
| lacework_event_severity | Lacework Event Severity Threshold | True |
| isFetch | Fetch incidents | False |
| incidentType | Incident type | False |
| lacework_event_history | Lacework Event History to Import \(in days\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lw-get-aws-compliance-assessment
***
Fetch the latest AWS compliance data from Lacework.


#### Base Command

`lw-get-aws-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS Account ID to use when fetching compliance data. | Required |
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 
| report_type | The Report Type to fetch from Lacework. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The supressions for the current recommendation. | 
| Lacework.Compliance.recommendations.INFO_LINK | String | The URL to the compliance violation information. | 
| Lacework.Compliance.recommendations.ASSESSED_RESOURCE_COUNT | Number | The number of assessed resources for the violation. | 
| Lacework.Compliance.recommendations.STATUS | String | The status of the recommendation. | 
| Lacework.Compliance.recommendations.REC_ID | String | The ID of the recommendation. | 
| Lacework.Compliance.recommendations.CATEGORY | String | The category of the recommendation | 
| Lacework.Compliance.recommendations.SERVICE | String | The service associated with the recommendation. | 
| Lacework.Compliance.recommendations.TITLE | String | The title of the recommendation. | 
| Lacework.Compliance.recommendations.VIOLATIONS.region | String | The region of the violating resource. | 
| Lacework.Compliance.recommendations.VIOLATIONS.reasons | String | The reason for the violation. | 
| Lacework.Compliance.recommendations.VIOLATIONS.resource | String | The resource causing the violation. | 
| Lacework.Compliance.recommendations.RESOURCE_COUNT | Number | The number of resources associated with the compliance failure. | 
| Lacework.Compliance.recommendations.SEVERITY | Number | The severity of the compliance failure. | 
| Lacework.Compliance.summary.NUM_RECOMMENDATIONS | Number | The number of recommendations contained in the report. | 
| Lacework.Compliance.summary.NUM_SEVERITY_2_NON_COMPLIANCE | Number | The number of Severity 2 compliance violations. | 
| Lacework.Compliance.summary.NUM_SEVERITY_4_NON_COMPLIANCE | Number | The number of Severity 4 compliance violations. | 
| Lacework.Compliance.summary.NUM_SEVERITY_1_NON_COMPLIANCE | Number | The number of severity 1 compliance violations. | 
| Lacework.Compliance.summary.NUM_COMPLIANT | Number | The number of compliant resources. | 
| Lacework.Compliance.summary.NUM_SEVERITY_3_NON_COMPLIANCE | Number | The number of severity 3 compliance violations. | 
| Lacework.Compliance.summary.ASSESSED_RESOURCE_COUNT | Number | The number of assessed resources. | 
| Lacework.Compliance.summary.NUM_SUPPRESSED | Number | The number of suppressed alerts. | 
| Lacework.Compliance.summary.NUM_SEVERITY_5_NON_COMPLIANCE | Number | The number of severity 5 compliance violations. | 
| Lacework.Compliance.summary.NUM_NOT_COMPLIANT | Number | The number of resources not in compliance. | 
| Lacework.Compliance.summary.VIOLATED_RESOURCE_COUNT | Number | The number of resources violating compliance. | 
| Lacework.Compliance.summary.SUPPRESSED_RESOURCE_COUNT | Number | The number of resources with suppressed violations. | 
| Lacework.Compliance.accountId | String | The AWS account ID. | 
| Lacework.Compliance.accountAlias | String | The AWS account alias. | 
| Lacework.Compliance.tenantId | String | The Azure tenant ID. | 
| Lacework.Compliance.tenantName | String | The Azure tenant name. | 
| Lacework.Compliance.subscriptionId | String | The Azure subscription ID. | 
| Lacework.Compliance.subscriptionName | String | The Azure subscription name. | 
| Lacework.Compliance.projectId | String | The GCP project ID. | 
| Lacework.Compliance.projectName | String | The GCP project name. | 
| Lacework.Compliance.organizationId | String | The GCP organization ID. | 
| Lacework.Compliance.organizationName | String | The GCP organization name. | 
| Lacework.Compliance.reportTime | String | The time the report completed. | 


#### Command Example
``` ```

#### Human Readable Output



### lw-get-azure-compliance-assessment
***
Fetch the latest Azure compliance data from Lacework.


#### Base Command

`lw-get-azure-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The Azure Tenant ID to use when fetching compliance data. | Required | 
| subscription_id | The Azure Subscription ID to use when fetching compliance data. | Required |
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 
| report_type | The Report Type to fetch from Lacework. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The supressions for the current recommendation. | 
| Lacework.Compliance.recommendations.INFO_LINK | String | The URL to the compliance violation information. | 
| Lacework.Compliance.recommendations.ASSESSED_RESOURCE_COUNT | Number | The number of assessed resources for the violation. | 
| Lacework.Compliance.recommendations.STATUS | String | The status of the recommendation. | 
| Lacework.Compliance.recommendations.REC_ID | String | The ID of the recommendation. | 
| Lacework.Compliance.recommendations.CATEGORY | String | The category of the recommendation | 
| Lacework.Compliance.recommendations.SERVICE | String | The service associated with the recommendation. | 
| Lacework.Compliance.recommendations.TITLE | String | The title of the recommendation. | 
| Lacework.Compliance.recommendations.VIOLATIONS.region | String | The region of the violating resource. | 
| Lacework.Compliance.recommendations.VIOLATIONS.reasons | String | The reason for the violation. | 
| Lacework.Compliance.recommendations.VIOLATIONS.resource | String | The resource causing the violation. | 
| Lacework.Compliance.recommendations.RESOURCE_COUNT | Number | The number of resources associated with the compliance failure. | 
| Lacework.Compliance.recommendations.SEVERITY | Number | The severity of the compliance failure. | 
| Lacework.Compliance.summary.NUM_RECOMMENDATIONS | Number | The number of recommendations contained in the report. | 
| Lacework.Compliance.summary.NUM_SEVERITY_2_NON_COMPLIANCE | Number | The number of Severity 2 compliance violations. | 
| Lacework.Compliance.summary.NUM_SEVERITY_4_NON_COMPLIANCE | Number | The number of Severity 4 compliance violations. | 
| Lacework.Compliance.summary.NUM_SEVERITY_1_NON_COMPLIANCE | Number | The number of severity 1 compliance violations. | 
| Lacework.Compliance.summary.NUM_COMPLIANT | Number | The number of compliant resources. | 
| Lacework.Compliance.summary.NUM_SEVERITY_3_NON_COMPLIANCE | Number | The number of severity 3 compliance violations. | 
| Lacework.Compliance.summary.ASSESSED_RESOURCE_COUNT | Number | The number of assessed resources. | 
| Lacework.Compliance.summary.NUM_SUPPRESSED | Number | The number of suppressed alerts. | 
| Lacework.Compliance.summary.NUM_SEVERITY_5_NON_COMPLIANCE | Number | The number of severity 5 compliance violations. | 
| Lacework.Compliance.summary.NUM_NOT_COMPLIANT | Number | The number of resources not in compliance. | 
| Lacework.Compliance.summary.VIOLATED_RESOURCE_COUNT | Number | The number of resources violating compliance. | 
| Lacework.Compliance.summary.SUPPRESSED_RESOURCE_COUNT | Number | The number of resources with suppressed violations. | 
| Lacework.Compliance.accountId | String | The AWS account ID. | 
| Lacework.Compliance.accountAlias | String | The AWS account alias. | 
| Lacework.Compliance.tenantId | String | The Azure tenant ID. | 
| Lacework.Compliance.tenantName | String | The Azure tenant name. | 
| Lacework.Compliance.subscriptionId | String | The Azure subscription ID. | 
| Lacework.Compliance.subscriptionName | String | The Azure subscription name. | 
| Lacework.Compliance.projectId | String | The GCP project ID. | 
| Lacework.Compliance.projectName | String | The GCP project name. | 
| Lacework.Compliance.organizationId | String | The GCP organization ID. | 
| Lacework.Compliance.organizationName | String | The GCP organization name. | 
| Lacework.Compliance.reportTime | String | The time the report completed. | 


#### Command Example
``` ```

#### Human Readable Output



### lw-get-gcp-compliance-assessment
***
Fetch the latest GCP compliance data from Lacework.


#### Base Command

`lw-get-gcp-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | The GCP Organization ID to use when fetching compliance data. | Required | 
| project_id | The GCP Project ID to use when fetching compliance data. | Required | 
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 
| report_type | The Report Type to fetch from Lacework. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The supressions for the current recommendation. | 
| Lacework.Compliance.recommendations.INFO_LINK | String | The URL to the compliance violation information. | 
| Lacework.Compliance.recommendations.ASSESSED_RESOURCE_COUNT | Number | The number of assessed resources for the violation. | 
| Lacework.Compliance.recommendations.STATUS | String | The status of the recommendation. | 
| Lacework.Compliance.recommendations.REC_ID | String | The ID of the recommendation. | 
| Lacework.Compliance.recommendations.CATEGORY | String | The category of the recommendation | 
| Lacework.Compliance.recommendations.SERVICE | String | The service associated with the recommendation. | 
| Lacework.Compliance.recommendations.TITLE | String | The title of the recommendation. | 
| Lacework.Compliance.recommendations.VIOLATIONS.region | String | The region of the violating resource. | 
| Lacework.Compliance.recommendations.VIOLATIONS.reasons | String | The reason for the violation. | 
| Lacework.Compliance.recommendations.VIOLATIONS.resource | String | The resource causing the violation. | 
| Lacework.Compliance.recommendations.RESOURCE_COUNT | Number | The number of resources associated with the compliance failure. | 
| Lacework.Compliance.recommendations.SEVERITY | Number | The severity of the compliance failure. | 
| Lacework.Compliance.summary.NUM_RECOMMENDATIONS | Number | The number of recommendations contained in the report. | 
| Lacework.Compliance.summary.NUM_SEVERITY_2_NON_COMPLIANCE | Number | The number of Severity 2 compliance violations. | 
| Lacework.Compliance.summary.NUM_SEVERITY_4_NON_COMPLIANCE | Number | The number of Severity 4 compliance violations. | 
| Lacework.Compliance.summary.NUM_SEVERITY_1_NON_COMPLIANCE | Number | The number of severity 1 compliance violations. | 
| Lacework.Compliance.summary.NUM_COMPLIANT | Number | The number of compliant resources. | 
| Lacework.Compliance.summary.NUM_SEVERITY_3_NON_COMPLIANCE | Number | The number of severity 3 compliance violations. | 
| Lacework.Compliance.summary.ASSESSED_RESOURCE_COUNT | Number | The number of assessed resources. | 
| Lacework.Compliance.summary.NUM_SUPPRESSED | Number | The number of suppressed alerts. | 
| Lacework.Compliance.summary.NUM_SEVERITY_5_NON_COMPLIANCE | Number | The number of severity 5 compliance violations. | 
| Lacework.Compliance.summary.NUM_NOT_COMPLIANT | Number | The number of resources not in compliance. | 
| Lacework.Compliance.summary.VIOLATED_RESOURCE_COUNT | Number | The number of resources violating compliance. | 
| Lacework.Compliance.summary.SUPPRESSED_RESOURCE_COUNT | Number | The number of resources with suppressed violations. | 
| Lacework.Compliance.accountId | String | The AWS account ID. | 
| Lacework.Compliance.accountAlias | String | The AWS account alias. | 
| Lacework.Compliance.tenantId | String | The Azure tenant ID. | 
| Lacework.Compliance.tenantName | String | The Azure tenant name. | 
| Lacework.Compliance.subscriptionId | String | The Azure subscription ID. | 
| Lacework.Compliance.subscriptionName | String | The Azure subscription name. | 
| Lacework.Compliance.projectId | String | The GCP project ID. | 
| Lacework.Compliance.projectName | String | The GCP project name. | 
| Lacework.Compliance.organizationId | String | The GCP organization ID. | 
| Lacework.Compliance.organizationName | String | The GCP organization name. | 
| Lacework.Compliance.reportTime | String | The time the report completed. | 


#### Command Example
``` ```

#### Human Readable Output



### lw-run-aws-compliance-assessment
***
Run an AWS compliance assessment in Lacework.


#### Base Command

`lw-run-aws-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS Account ID to run a compliance assessment against. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### lw-run-azure-compliance-assessment
***
Run an Azure compliance assessment in Lacework.


#### Base Command

`lw-run-azure-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tenant_id | The Azure Tenant ID to run a compliance assessment against. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### lw-run-gcp-compliance-assessment
***
Run a GCP compliance assessment in Lacework.


#### Base Command

`lw-run-gcp-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP Project ID to run a compliance assessment against. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### lw-get-event-details
***
Fetch Event Details for a specific Event in Lacework.


#### Base Command

`lw-get-event-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | The Lacework Event ID to be retrieved. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Event.START_TIME | Date | The start time of the event. | 
| Lacework.Event.END_TIME | Date | The end time of the event. | 
| Lacework.Event.EVENT_TYPE | String | The type of the event. | 
| Lacework.Event.EVENT_ID | String | The ID of the event. | 
| Lacework.Event.EVENT_ACTOR | String | The actor of the event. | 
| Lacework.Event.EVENT_MODEL | String | The model of the event. | 
| Lacework.Event.ENTITY_MAP.User.MACHINE_HOSTNAME | String | The machine hostname associated to the user in the event. | 
| Lacework.Event.ENTITY_MAP.User.USERNAME | String | The username associated to the user in the event. | 
| Lacework.Event.ENTITY_MAP.Application.APPLICATION | String | The application associated with the event. | 
| Lacework.Event.ENTITY_MAP.Application.HAS_EXTERNAL_CONNS | Number | An integer representing whether the application has external connections. | 
| Lacework.Event.ENTITY_MAP.Application.IS_CLIENT | Number | An integer representing whether the application is the client. | 
| Lacework.Event.ENTITY_MAP.Application.IS_SERVER | Number | An integer representing whether the application is the server. | 
| Lacework.Event.ENTITY_MAP.Application.EARLIEST_KNOWN_TIME | Date | The time when then application was first seen. | 
| Lacework.Event.ENTITY_MAP.Machine.HOSTNAME | String | The hostname of the machine associated with the event. | 
| Lacework.Event.ENTITY_MAP.Machine.EXTERNAL_IP | String | The external IP of the machine associated with the event. | 
| Lacework.Event.ENTITY_MAP.Machine.INSTANCE_ID | String | The instance ID of the machine associated with the event. | 
| Lacework.Event.ENTITY_MAP.Machine.INSTANCE_NAME | String | The instance name of the machine associated with the event. | 
| Lacework.Event.ENTITY_MAP.Machine.CPU_PERCENTAGE | Number | The CPU utiliztion percentage of the machine associated with the event. | 
| Lacework.Event.ENTITY_MAP.Machine.INTERNAL_IP_ADDRESS | String | The internal IP of the machine associated with the event. | 
| Lacework.Event.ENTITY_MAP.Container.IMAGE_REPO | String | The image repository of the container associated with the event. | 
| Lacework.Event.ENTITY_MAP.Container.IMAGE_TAG | String | The image tag of the container associated with the event. | 
| Lacework.Event.ENTITY_MAP.Container.HAS_EXTERNAL_CONNS | Number | An integer representing whether the container has external connections. | 
| Lacework.Event.ENTITY_MAP.Container.IS_CLIENT | Number | An integer representing whether the container is the client. | 
| Lacework.Event.ENTITY_MAP.Container.IS_SERVER | Number | An integer representing whether the container is the server. | 
| Lacework.Event.ENTITY_MAP.Container.FIRST_SEEN_TIME | Date | The time when the container was first seen. | 
| Lacework.Event.ENTITY_MAP.Container.POD_NAMESPACE | String | The pod namespace the container associated with the event resides within. | 
| Lacework.Event.ENTITY_MAP.Container.POD_IP_ADDR | String | The pod IP address of the container associated with the event. | 
| Lacework.Event.ENTITY_MAP.DnsName.HOSTNAME | String | The hostname used in a DNS query associated with the event. | 
| Lacework.Event.ENTITY_MAP.DnsName.PORT_LIST | Number | The ports used to communicate to a specific DNS name associated with the event. | 
| Lacework.Event.ENTITY_MAP.DnsName.TOTAL_IN_BYTES | Number | The total bytes in for a specific DNS name associated with the event. | 
| Lacework.Event.ENTITY_MAP.DnsName.TOTAL_OUT_BYTES | Number | The total bytes out for a specific DNS name associated with the event. | 
| Lacework.Event.ENTITY_MAP.IpAddress.IP_ADDRESS | String | An IP address associated with the event. | 
| Lacework.Event.ENTITY_MAP.IpAddress.TOTAL_IN_BYTES | Number | The total bytes in for a specific IP address associated with the event. | 
| Lacework.Event.ENTITY_MAP.IpAddress.TOTAL_OUT_BYTES | Number | The total bytes out for a specific IP address associated with the event. | 
| Lacework.Event.ENTITY_MAP.IpAddress.THREAT_TAGS | String | A treat tag associated with the IP. | 
| Lacework.Event.ENTITY_MAP.IpAddress.COUNTRY | String | The country that the IP address resides within. | 
| Lacework.Event.ENTITY_MAP.IpAddress.REGION | String | The region that the IP address resides within. | 
| Lacework.Event.ENTITY_MAP.IpAddress.PORT_LIST | Number | The ports used to communicate to the IP address associated with the event. | 
| Lacework.Event.ENTITY_MAP.IpAddress.FIRST_SEEN_TIME | Date | The time when the IP address was first seen. | 
| Lacework.Event.ENTITY_MAP.Process.HOSTNAME | String | The hostname of the process associated with the event. | 
| Lacework.Event.ENTITY_MAP.Process.PROCESS_ID | Number | The process ID \(PID\) of the process associated with the event. | 
| Lacework.Event.ENTITY_MAP.Process.PROCESS_START_TIME | Date | The start time of the process associated with the event. | 
| Lacework.Event.ENTITY_MAP.Process.CMDLINE | String | The command-line entry used to run the process associated with the event. | 
| Lacework.Event.ENTITY_MAP.Process.CPU_PERCENTAGE | Number | The CPU utilization percentage of the process associated with the event. | 
| Lacework.Event.ENTITY_MAP.FileDataHash.FILEDATA_HASH | String | The hash of the binary associated with the event. | 
| Lacework.Event.ENTITY_MAP.FileDataHash.MACHINE_COUNT | Number | The machine count of the binary associated with the event. | 
| Lacework.Event.ENTITY_MAP.FileDataHash.EXE_PATH_LIST | String | The path to the binary associated with the event. | 
| Lacework.Event.ENTITY_MAP.FileDataHash.FIRST_SEEN_TIME | Date | The time that the binary was first seen. | 
| Lacework.Event.ENTITY_MAP.FileDataHash.IS_KNOWN_BAD | Number | An integer representing whether the binary is known bad. | 
| Lacework.Event.ENTITY_MAP.FileExePath.EXE_PATH | String | The path of the binary associated with the event. | 
| Lacework.Event.ENTITY_MAP.FileExePath.FIRST_SEEN_TIME | Date | The time that the binary path was first seen. | 
| Lacework.Event.ENTITY_MAP.FileExePath.LAST_FILEDATA_HASH | String | The hash of the binary located at the given path. | 
| Lacework.Event.ENTITY_MAP.FileExePath.LAST_PACKAGE_NAME | String | The package name of the binary at the given path. | 
| Lacework.Event.ENTITY_MAP.FileExePath.LAST_VERSION | String | The version of the binary at the given path. | 
| Lacework.Event.ENTITY_MAP.FileExePath.LAST_FILE_OWNER | String | The file owner of the binary at the given path. | 
| Lacework.Event.ENTITY_MAP.SourceIpAddress.IP_ADDRESS | String | The IP address of the source IP associated with the event. | 
| Lacework.Event.ENTITY_MAP.SourceIpAddress.REGION | String | The region of the source IP associated with the event. | 
| Lacework.Event.ENTITY_MAP.SourceIpAddress.COUNTRY | String | The country of the source IP associated with the event. | 
| Lacework.Event.ENTITY_MAP.API.SERVICE | String | The service endpoint of the API associated with the event. | 
| Lacework.Event.ENTITY_MAP.API.API | String | The API identifier of the API associated with the event. | 
| Lacework.Event.ENTITY_MAP.Region.REGION | String | The region identifier associated with the event. | 
| Lacework.Event.ENTITY_MAP.Region.ACCOUNT_LIST | String | The account list of the region associated with the event. | 
| Lacework.Event.ENTITY_MAP.CT_User.USERNAME | String | The username of the CloudTrail user associated with the event. | 
| Lacework.Event.ENTITY_MAP.CT_User.ACCOUT_ID | String | The account ID of the CloudTrail user associated with the event. | 
| Lacework.Event.ENTITY_MAP.CT_User.MFA | Number | An integer representing whether MFA was used for the CloudTrail user. | 
| Lacework.Event.ENTITY_MAP.CT_User.API_LIST | String | A list of APIs used by the CloudTrail user associated with the event. | 
| Lacework.Event.ENTITY_MAP.CT_User.REGION_LIST | String | A list of regions used by the CloudTrail user associated with the event. | 
| Lacework.Event.ENTITY_MAP.CT_User.PRINCIPAL_ID | String | The principal ID used by the CloudTrail user associated with the event. | 
| Lacework.Event.ENTITY_MAP.Resource.NAME | String | The name of the resource associated with the event. | 
| Lacework.Event.ENTITY_MAP.Resource.VALUE | String | The value of the resource associated with the event. | 
| Lacework.Event.ENTITY_MAP.RecId.REC_ID | String | The recommendation ID associated with the event. | 
| Lacework.Event.ENTITY_MAP.RecId.ACCOUNT_ID | String | The account ID associated to the recommendation. | 
| Lacework.Event.ENTITY_MAP.RecId.ACCOUNT_ALIAS | String | The account alias associated to the recommendation. | 
| Lacework.Event.ENTITY_MAP.RecId.TITLE | String | The title of the recommendation. | 
| Lacework.Event.ENTITY_MAP.RecId.STATUS | String | The status of the recommendation. | 
| Lacework.Event.ENTITY_MAP.RecId.EVAL_TYPE | String | The evaluation type of the recommendation. | 
| Lacework.Event.ENTITY_MAP.RecId.EVAL_GUID | String | The evaluation GUID of the recommednation. | 
| Lacework.Event.ENTITY_MAP.CustomRule.LAST_UPDATED_TIME | Date | The last updated time of the recommendation. | 
| Lacework.Event.ENTITY_MAP.CustomRule.LAST_UPDATED_USER | String | The last updated user of the recommendation. | 
| Lacework.Event.ENTITY_MAP.CustomRule.DISPLAY_FILTER | String | The display filter attributed to the custom rule. | 
| Lacework.Event.ENTITY_MAP.CustomRule.RULE_GUID | String | The rule GUID associated to the custom rule. | 
| Lacework.Event.ENTITY_MAP.NewViolation.REC_ID | String | The recommendation ID of the new violation. | 
| Lacework.Event.ENTITY_MAP.NewViolation.REASON | String | The reason for the new violation. | 
| Lacework.Event.ENTITY_MAP.NewViolation.RESOURCE | String | The resource associated with the new violation. | 
| Lacework.Event.ENTITY_MAP.ViolationReason.REC_ID | String | The recommendation ID of the violation reason. | 
| Lacework.Event.ENTITY_MAP.ViolationReason.REASON | String | The violation reason. | 


#### Command Example
``` ```

#### Human Readable Output



### lw-get-gcp-projects-by-organization
***
Fetch a list of GCP projects that are under an organization.


#### Base Command

`lw-get-gcp-projects-by-organization`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_id | The GCP Organization ID to use when fetching projects data. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.GCP.organization | String | The GCP Organization. | 
| Lacework.GCP.projects | String | The GCP Projects associated to the Organization. | 


#### Command Example
``` ```

#### Human Readable Output



### lw-get-container-vulnerabilities
***
Fetch the container vulnerability information from Lacework.


#### Base Command

`lw-get-container-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_type | The identifier type for the container. (Image ID or Image Digest) The corresponding argument, image_id or image_digest, must also be provided. | Required | 
| image_id | A string representing the container image ID for which to fetch vulnerabilities. | Optional | 
| image_digest | A string representing the container image digest for which to fetch vulnerabilities. | Optional | 
| severity | A string representing the severity of vulnerabilities to fetch. | Optional | 
| fixable | A boolean which filters for fixable vulnerabilities. | Optional | 
| start_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to begin from. (ex. "2020-01-01T01:10:00Z") | Optional | 
| end_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to end at. (ex. "2020-01-01T01:10:00Z") | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Vulnerability.Container.image.image_info.created_time | String | The creation time of the container image. | 
| Lacework.Vulnerability.Container.image.image_info.image_digest | String | The digest of the container image. | 
| Lacework.Vulnerability.Container.image.image_info.image_id | String | The ID of the container image. | 
| Lacework.Vulnerability.Container.image.image_info.registry | String | The registry of the container image. | 
| Lacework.Vulnerability.Container.image.image_info.repository | String | The repository of the container image. | 
| Lacework.Vulnerability.Container.image.image_info.size | Number | The size of the container image. | 
| Lacework.Vulnerability.Container.image.image_info.tags | String | The tags of the container image. | 
| Lacework.Vulnerability.Container.image.image_layers.hash | String | The hash of the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.created_by | String | The 'created by' of the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.name | String | The package names that exist in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.namespace | String | The package namespaces that exist in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.fix_available | String | A variable representing if a fix is available for a vulnerability in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.version | String | The package versions that exist in the contianer image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.vulnerabilities.name | String | The vulnerability names that exist in packages in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.vulnerabilities.description | String | The vulnerability descriptions that exist in packages in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.vulnerabilities.link | String | The informational links for vulnerabilities that exist in packages in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.vulnerabilities.severity | String | The vulnerability severities that exist in packages in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.vulnerabilities.fix_version | String | The vulnerability fix versions that exist for packages in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.fixed_version | String | The fixed version of vulnerabilities in packages of the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.host_count | String | The host count of the packages in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.severity | String | The severity of package vulnerabilities of the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.cve_link | String | The informational links for package vulnerabilities in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.cvss_score | String | The CVSS score for package vulnerabilities in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.cvss_v3_score | String | The CVSS v3 score for package vulnerabilities in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.cvss_v2_score | String | The CVSS v2 score for package vulnerabilities in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.status | String | The status for package vulnerabilities in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.package_status | String | The status for package activity status in the container image layer. | 
| Lacework.Vulnerability.Container.image.image_layers.packages.first_seen_time | String | The first seen time for packages in the container image layer. | 
| Lacework.Vulnerability.Container.scan_status | String | The scan status for the container. | 
| Lacework.Vulnerability.Container.total_vulnerabilities | Number | The total vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.critical_vulnerabilities | Number | The critical severity vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.high_vulnerabilities | Number | The high severity vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.medium_vulnerabilities | Number | The medium severity vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.low_vulnerabilities | Number | The low severity vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.info_vulnerabilities | Number | The informational severity vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.fixable_vulnerabilities | Number | The fixable vulnerabilties for the container. | 
| Lacework.Vulnerability.Container.last_evaluation_time | String | The last evaluation time for the container. | 


#### Command Example
``` ```

#### Human Readable Output



### lw-get-host-vulnerabilities
***
Fetch the host vulnerability information from Lacework.


#### Base Command

`lw-get-host-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | A string representing the severity of vulnerabilities to fetch. | Optional | 
| fixable | A boolean which filters for fixable vulnerabilities. | Optional | 
| start_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to begin from. (ex. "2020-01-01T01:10:00Z") | Optional | 
| end_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to end at. (ex. "2020-01-01T01:10:00Z") | Optional | 
| cve | A string representing the CVE ID for which to filter returned results. | Optional | 
| namespace | A string representing the package namespace for which to filter results. | Optional | 
| limit | An integer representing the maximum number of results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Vulnerability.Host.cve_id | String | The CVE ID of a host vulnerability. | 
| Lacework.Vulnerability.Host.packages.name | String | The vulnerable package names for a host vulnerability. | 
| Lacework.Vulnerability.Host.packages.namespace | String | The package namespaces for a host vulnerability. | 
| Lacework.Vulnerability.Host.packages.fix_available | String | A string representing if a fix is available for a host vulnerability. | 
| Lacework.Vulnerability.Host.packages.version | String | The package version of a host vulnerability. | 
| Lacework.Vulnerability.Host.packages.vulnerabilities.name | String | The name of a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.vulnerabilities.description | String | The description of a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.vulnerabilities.link | String | The informational link for a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.vulnerabilities.severity | String | The severity of a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.vulnerabilities.fix_version | String | The fixed version for a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.fixed_version | String | The fixed version for a vulnerable package. | 
| Lacework.Vulnerability.Host.packages.host_count | String | The host count of a vulnerable package. | 
| Lacework.Vulnerability.Host.packages.severity | String | The severity of a vulnerable package. | 
| Lacework.Vulnerability.Host.packages.cve_link | String | The informational link for a CVE. | 
| Lacework.Vulnerability.Host.packages.cvss_score | String | The CVSS score for a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.cvss_v3_score | String | The CVSS v3 score for a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.cvss_v2_score | String | The CVSS v2 score for a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.status | String | The status of a package vulnerability. | 
| Lacework.Vulnerability.Host.packages.package_status | String | The package activity status on the host. | 
| Lacework.Vulnerability.Host.packages.first_seen_time | String | The first seen time for a package vulnerability. | 
| Lacework.Vulnerability.Host.summary.total_vulnerabilities | Number | The total vulnerabilities for hte host. | 
| Lacework.Vulnerability.Host.summary.last_evaluation_time | String | The time of the last vulnerability evaluation. | 


#### Command Example
``` ```

#### Human Readable Output


