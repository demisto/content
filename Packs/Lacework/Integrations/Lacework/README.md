Lacework provides end-to-end cloud security automation for AWS, Azure, and GCP with a comprehensive view of risks across cloud workloads and containers.
This integration was integrated and tested with version 2 of the Lacework APIs

## Configure Lacework in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Lacework Account Name (i.e. Sub-Domain of the URL: &lt;ACCOUNT&gt;.lacework.net) | True |
| Lacework Sub-Account Name (If Required) | False |
| Lacework API Key | True |
| Lacework API Secret | True |
| Lacework Alert Severity Threshold | True |
| Fetch incidents | False |
| Incident type | False |
| Lacework Alert History to Import (in days) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### lw-get-alert-details
***
Fetch details for a specific Alert in Lacework.


#### Base Command

`lw-get-alert-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The Lacework Alert ID to be retrieved. | Required | 
| scope | The scope of data to retrieve from Lacework for the specified Alert ID. Possible values are: Details, Investigation, Events, RelatedAlerts, Integrations, Timeline. Default is Details. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Alert.startTime | Date | The start time of the alert. | 
| Lacework.Alert.endTime | Date | The end time of the alert. | 
| Lacework.Alert.alertType | String | The type of the alert. | 
| Lacework.Alert.alertName | String | The name of the alert. | 
| Lacework.Alert.alertId | String | The ID of the alert. | 
| Lacework.Alert.severity | String | The severity of the alert. | 
| Lacework.Alert.status | String | The status of the alert. | 
| Lacework.Alert.alertInfo.description | String | The alert description provides why the potential threat occurred. | 
| Lacework.Alert.alertInfo.subject | String | The alert subject. In some cases, the alert subject can be the same as the alert name. | 
| Lacework.Alert.entityMap | Unknown | The entity map for the alert. | 

### lw-get-aws-compliance-assessment
***
Fetch the latest AWS compliance data from Lacework.


#### Base Command

`lw-get-aws-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The AWS Account ID to use when fetching compliance data. | Required | 
| report_type | The Report Type to fetch from Lacework. Possible values are: AWS_CIS_S3, HIPAA, ISO_2700, NIST_800-53_Rev4, NIST_800-171_Rev2, PCI, SOC. Default is AWS_CIS_S3. | Optional | 
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The suppressions for the current recommendation. | 
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
| report_type | The Report Type to fetch from Lacework. Possible values are: AZURE_CIS, AZURE_PCI, AZURE_SOC. Default is AZURE_CIS. | Optional | 
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The suppressions for the current recommendation. | 
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

### lw-get-gcp-compliance-assessment
***
Fetch the latest GCP compliance data from Lacework.


#### Base Command

`lw-get-gcp-compliance-assessment`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The GCP Project ID to use when fetching compliance data. | Required | 
| report_type | The Report Type to fetch from Lacework. Possible values are: GCP_CIS, GCP_PCI, GCP_SOC. Default is GCP_CIS. | Optional | 
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The suppressions for the current recommendation. | 
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

### lw-get-compliance-report
***
Fetch a specified compliance report from Lacework.


#### Base Command

`lw-get-compliance-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| primary_query_id | The primary ID that is used to fetch the report; for example, AWS Account ID or Azure Tenant ID. | Optional | 
| secondary_query_id | The secondary ID that is used to fetch the report; for example, GCP Project ID or Azure Subscription ID. | Optional | 
| report_name | The report definition's name that is used when generating the report. | Optional | 
| report_type | The report's notification type; for example, AZURE_NIST_CSF. Possible values are: AZURE_CIS, AZURE_CIS_131, AZURE_SOC, AZURE_SOC_Rev2, AZURE_PCI, AZURE_PCI_Rev2, AZURE_ISO_27001, AZURE_NIST_CSF, AZURE_NIST_800_53_REV5, AZURE_NIST_800_171_REV2, AZURE_HIPAA, AWS_CIS_S3, NIST_800-53_Rev4, NIST_800-171_Rev2, ISO_2700, HIPAA, SOC, AWS_SOC_Rev2, GCP_HIPAA, PCI, GCP_CIS, GCP_SOC, GCP_CIS12, GCP_K8S, GCP_PCI_Rev2, GCP_SOC_Rev2, GCP_HIPAA_Rev2, GCP_ISO_27001, GCP_NIST_CSF, GCP_NIST_800_53_REV4, GCP_NIST_800_171_REV2, GCP_PCI, AWS_CIS_14, GCP_CIS13, AWS_CMMC_1.02, AWS_HIPAA, AWS_ISO_27001:2013, AWS_NIST_CSF, AWS_NIST_800-171_rev2, AWS_NIST_800-53_rev5, AWS_PCI_DSS_3.2.1, AWS_SOC_2, LW_AWS_SEC_ADD_1_0. Default is LW_AWS_SEC_ADD_1_0. | Optional | 
| template_name | The template's name that is used for the report; for example, Default. Default is Default. | Required | 
| rec_id | Setting the 'rec_id' will filter compliance results for the specified Recommendation ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Compliance.reportType | String | The Type of the compliance report. | 
| Lacework.Compliance.reportTitle | String | The Title of the compliance report. | 
| Lacework.Compliance.recommendations.SUPPRESSIONS | String | The suppressions for the current recommendation. | 
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

### lw-get-container-vulnerabilities
***
Fetch container vulnerability information from Lacework.


#### Base Command

`lw-get-container-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to begin from. (ex. "2020-01-01T01:10:00Z"). | Optional | 
| end_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to end at. (ex. "2020-01-01T01:10:00Z"). | Optional | 
| filters | An array of objects to add information to refine your search results. | Optional | 
| returns | An array of strings to specify which top-level fields of the response schema you want to receive. | Optional | 
| limit | An integer representing a limit on the number or results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Vulnerability.Container.evalCtx.exception_props | String | The exception properties that were applied in the evaluation | 
| Lacework.Vulnerability.Container.evalCtx.image_info | Date | The image information for the container scanned in the evaluation | 
| Lacework.Vulnerability.Container.evalCtx.integration_props | String | The properties of the integration that performed the evaluation | 
| Lacework.Vulnerability.Container.evalCtx.is_reeval | Boolean | A boolean representing whether the evaluation was a re-evaluation | 
| Lacework.Vulnerability.Container.evalCtx.request_source | String | The source of the evaluation request | 
| Lacework.Vulnerability.Container.evalCtx.scan_batch_id | String | The scan batch ID for the evaluation | 
| Lacework.Vulnerability.Container.evalCtx.scan_request_props | String | The scan request properties for the evaluation | 
| Lacework.Vulnerability.Container.evalCtx.vuln_batch_id | String | The vulnerability batch ID for the evaluation | 
| Lacework.Vulnerability.Container.evalCtx.vuln_created_time | Date | The time at which the vulnerability was created | 
| Lacework.Vulnerability.Container.featureKey.name | String | The name of the package identified in the evaluation | 
| Lacework.Vulnerability.Container.featureKey.namespace | String | The namespace of the package identified in the evaluation | 
| Lacework.Vulnerability.Container.featureKey.version | String | The version of the package identified in the evaluation | 
| Lacework.Vulnerability.Container.featureProps.feed | String | The type of data feed used in the evaluation | 
| Lacework.Vulnerability.Container.featureProps.introduced_in | String | The Dockerfile command which introduced the vulnerability | 
| Lacework.Vulnerability.Container.featureProps.layer | String | The SHA256 hash of the layer which introduced the vulnerability | 
| Lacework.Vulnerability.Container.featureProps.src | String | The path within the container identifying the source of the vulnerability data | 
| Lacework.Vulnerability.Container.featureProps.version_format | String | The format of the version data for the vulnerable package | 
| Lacework.Vulnerability.Container.fixInfo.fix_available | Number | An integer representing whether a fix is available for the vulnerability | 
| Lacework.Vulnerability.Container.fixInfo.fixed_version | String | The version in which the vulnerability is fixed for the CVE and package | 
| Lacework.Vulnerability.Container.imageId | String | The image ID of the container identified in the evaluation | 
| Lacework.Vulnerability.Container.severity | String | The severity of the vulnerability identified in the evaluation | 
| Lacework.Vulnerability.Container.startTime | Date | The start time for the vulnerability evaluation | 
| Lacework.Vulnerability.Container.status | String | The status of the vulnerability identified in the evaluation | 
| Lacework.Vulnerability.Container.vulnId | String | The vulnerability ID \(CVE, ALAS, etc.\) | 
| Lacework.Vulnerability.Container.vulnHash | String | A unique hash of all data contained in the vulnerability | 

### lw-get-host-vulnerabilities
***
Fetch host vulnerability information from Lacework.


#### Base Command

`lw-get-host-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to begin from. (ex. "2020-01-01T01:10:00Z"). | Optional | 
| end_time | A "%Y-%m-%dT%H:%M:%SZ" structured timestamp to end at. (ex. "2020-01-01T01:10:00Z"). | Optional | 
| filters | An array of objects to add information to refine your search results. | Optional | 
| returns | An array of strings to specify which top-level fields of the response schema you want to receive. | Optional | 
| limit | An integer representing a limit on the number or results to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Lacework.Vulnerability.Host.cveProps.description | String | The CVE Properties description | 
| Lacework.Vulnerability.Host.cveProps.link | String | The CVE Properties description URL | 
| Lacework.Vulnerability.Host.endTime | Date | The end time for the vulnerability evaluation period | 
| Lacework.Vulnerability.Host.evalCtx.exception_props.status | String | The status of any exception properties for the evaluation | 
| Lacework.Vulnerability.Host.evalCtx.hostname | String | The hostname of the host assessed in the evaluation | 
| Lacework.Vulnerability.Host.evalCtx.mc_eval_guid | String | The GUID for the evaluation | 
| Lacework.Vulnerability.Host.featureKey.name | String | The name of the package identified in the evaluation | 
| Lacework.Vulnerability.Host.featureKey.namespace | String | The namespace of the package identified in the evaluation | 
| Lacework.Vulnerability.Host.featureKey.package_active | Number | An integer representing whether the package is Active on the host | 
| Lacework.Vulnerability.Host.featureKey.version_installed | String | The version of the package identified in the evaluation | 
| Lacework.Vulnerability.Host.fixInfo.fix_available | String | An integer representing whether a fix is available for the vulnerability | 
| Lacework.Vulnerability.Host.fixInfo.fixed_version | String | The version in which the vulnerability is fixed for the CVE and package | 
| Lacework.Vulnerability.Host.machineTags | String | A string representing the machine tags in key/value pairs | 
| Lacework.Vulnerability.Host.mid | String | The machine ID for the host identified in the evaluation | 
| Lacework.Vulnerability.Host.severity | String | The severity of the vulnerability identified in the evaluation | 
| Lacework.Vulnerability.Host.startTime | Date | The start time for the vulnerability evaluation period | 
| Lacework.Vulnerability.Host.status | String | The status of the vulnerability identified in the evaluation | 
| Lacework.Vulnerability.Host.vulnId | String | The vulnerability ID \(CVE, ALAS, etc.\) | 
| Lacework.Vulnerability.Host.vulnHash | String | A unique hash of all data contained in the vulnerability | 