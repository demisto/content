Integration to pull assets and other ASM related information.
This integration was integrated and tested with version xx of Cortex Xpanse.

## Configure Cortex Xpanse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex Xpanse.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL | The web UI with \`api-\` appended to front \(e.g., https://api-xsiam.paloaltonetworks.com\). For more information, see https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis. | True |
    | API Key ID | For more information, see https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-api/cortex-xdr-api-overview/get-started-with-cortex-xdr-apis.  Only standard API key type is supported. | True |
    | API Key |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | Incidents Fetch Interval |  | False |
    | Incident type |  | False |
    | Maximum number of alerts per fetch | The maximum number of alerts per fetch. Cannot exceed 100. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Alert Severities to Fetch | The severity of the alerts that will be fetched. If no severity is provided then alerts of all the severities will be fetched. Note: An alert whose status was changed to a filtered status after its creation time will not be fetched. |  |
    | Alert Statuses to fetch | The statuses of the alerts that will be fetched. If no status is provided then alerts of all the statuses will be fetched. Note: An alert whose status was changed to a filtered status after its creation time will not be fetched. | False |
    | Fetch alerts with tags (comma separated string) | The tags of the alerts that will be fetched. If no tags are provided then no tag filtering will be applied on fetched alerts. These should include the tag prefix, ex. AT:Asset Tag. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### asm-list-external-service

***
Get a list of all your external services filtered by business units, externally detected providers, domain, externally inferred CVEs, active classifications, inactive classifications, service name, service type, protocol, IP address, is active, and discovery type. Maximum result limit is 100 assets.

#### Base Command

`asm-list-external-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address on which to search. | Optional | 
| domain | Domain on which to search. | Optional | 
| is_active | Whether the service is active. Possible values are: yes, no. | Optional | 
| discovery_type | How service was discovered. Possible values are: colocated_on_ip, directly_discovery, unknown. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalService.service_id | String | External service UUID. | 
| ASM.ExternalService.service_name | String | Name of the external service. | 
| ASM.ExternalService.service_type | String | Type of the external service. | 
| ASM.ExternalService.ip_address | String | IP address of the external service. | 
| ASM.ExternalService.externally_detected_providers | String | Providers of external service. | 
| ASM.ExternalService.is_active | String | Whether the external service is active. | 
| ASM.ExternalService.first_observed | Date | Date of the first observation of the external service. | 
| ASM.ExternalService.last_observed | Date | Date of the last observation of the external service. | 
| ASM.ExternalService.port | Number | Port number of the external service. | 
| ASM.ExternalService.protocol | String | Protocol number of the external service. | 
| ASM.ExternalService.inactive_classifications | String | External service classifications that are no longer active. | 
| ASM.ExternalService.discovery_type | String | How the external service was discovered. | 
| ASM.ExternalService.business_units | String | External service associated business units. | 
| ASM.ExternalService.externally_inferred_vulnerability_score | Unknown | External service vulnerability score. | 

### asm-get-external-service

***
Get service details according to the service ID.

#### Base Command

`asm-get-external-service`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | A string representing the service ID you want to get details for. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalService.service_id | String | External service UUID. | 
| ASM.ExternalService.service_name | String | Name of the external service. | 
| ASM.ExternalService.service_type | String | Type of the external service. | 
| ASM.ExternalService.ip_address | String | IP address of the external service. | 
| ASM.ExternalService.externally_detected_providers | String | Providers of the external service. | 
| ASM.ExternalService.is_active | String | Whether the external service is active. | 
| ASM.ExternalService.first_observed | Date | Date of the first observation of the external service. | 
| ASM.ExternalService.last_observed | Date | Date of the last observation of the external service. | 
| ASM.ExternalService.port | Number | Port number of the external service. | 
| ASM.ExternalService.protocol | String | Protocol of the external service. | 
| ASM.ExternalService.inactive_classifications | String | External service classifications that are no longer active. | 
| ASM.ExternalService.discovery_type | String | How the external service was discovered. | 
| ASM.ExternalService.business_units | String | External service associated business units. | 
| ASM.ExternalService.externally_inferred_vulnerability_score | Unknown | External service vulnerability score. | 
| ASM.ExternalService.details | String | Additional details. | 

### asm-list-external-ip-address-range

***
Get a list of all your internet exposures filtered by business units and organization handles. Maximum result limit is 100 ranges.

#### Base Command

`asm-list-external-ip-address-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalIpAddressRange.range_id | String | External IP address range UUID. | 
| ASM.ExternalIpAddressRange.first_ip | String | First IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.last_ip | String | Last IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.ips_count | Number | Number of IP addresses of the external IP address range. | 
| ASM.ExternalIpAddressRange.active_responsive_ips_count | Number | The number of IPs in the external address range that are actively responsive. | 
| ASM.ExternalIpAddressRange.date_added | Date | Date the external IP address range was added. | 
| ASM.ExternalIpAddressRange.business_units | String | External IP address range associated business units. | 
| ASM.ExternalIpAddressRange.organization_handles | String | External IP address range associated organization handles. | 

### asm-get-external-ip-address-range

***
Get the external IP address range details according to the range IDs.

#### Base Command

`asm-get-external-ip-address-range`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | A string representing the range ID for which you want to get the details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalIpAddressRange.range_id | String | External IP address range UUID. | 
| ASM.ExternalIpAddressRange.first_ip | String | First IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.last_ip | String | Last IP address of the external IP address range. | 
| ASM.ExternalIpAddressRange.ips_count | Number | Number of IP addresses of the external IP address range. | 
| ASM.ExternalIpAddressRange.active_responsive_ips_count | Number | The number of IPs in the external address range that are actively responsive. | 
| ASM.ExternalIpAddressRange.date_added | Date | Date the external IP address range was added. | 
| ASM.ExternalIpAddressRange.business_units | String | External IP address range associated business units. | 
| ASM.ExternalIpAddressRange.organization_handles | String | External IP address range associated organization handles. | 
| ASM.ExternalIpAddressRange.details | String | Additional information. | 

### asm-list-asset-internet-exposure

***
Get a list of all your internet exposures filtered by IP address, domain, type, and/or if there is an active external service. Maximum result limit is 100 assets.

#### Base Command

`asm-list-asset-internet-exposure`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP address on which to search. | Optional | 
| name | Name of the asset on which to search. | Optional | 
| type | Type of the external service. Possible values are: certificate, cloud_compute_instance, on_prem, domain, unassociated_responsive_ip. | Optional | 
| has_active_external_services | Whether the internet exposure has an active external service. Possible values are: yes, no. | Optional | 
| search_from | Represents the start offset index of results. Default is 0. | Optional | 
| search_to | Represents the end offset index of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AssetInternetExposure.asm_ids | String | Attack surface management UUID. | 
| ASM.AssetInternetExposure.name | String | Name of the exposed asset. | 
| ASM.AssetInternetExposure.asset_type | String | Type of the exposed asset. | 
| ASM.AssetInternetExposure.cloud_provider | Unknown | The cloud provider used to collect these cloud assets as either GCP, AWS, or Azure. | 
| ASM.AssetInternetExposure.region | Unknown | Displays the region as provided by the cloud provider. | 
| ASM.AssetInternetExposure.last_observed | Unknown | Last time the exposure was observed. | 
| ASM.AssetInternetExposure.first_observed | Unknown | First time the exposure was observed. | 
| ASM.AssetInternetExposure.has_active_externally_services | Boolean | Whether the internet exposure is associated with an active external service\(s\). | 
| ASM.AssetInternetExposure.has_xdr_agent | String | Whether the internet exposure asset has an XDR agent. | 
| ASM.AssetInternetExposure.cloud_id | Unknown | Displays the resource ID as provided from the cloud provider. | 
| ASM.AssetInternetExposure.domain_resolves | Boolean | Whether the asset domain is resolvable. | 
| ASM.AssetInternetExposure.operation_system | Unknown | The operating system reported by the source for this asset. | 
| ASM.AssetInternetExposure.agent_id | Unknown | The endpoint ID if there is an endpoint installed on this asset. | 
| ASM.AssetInternetExposure.externally_detected_providers | String | The provider of the asset as determined by an external assessment. | 
| ASM.AssetInternetExposure.service_type | String | Type of the asset. | 
| ASM.AssetInternetExposure.externally_inferred_cves | String | If the internet exposure has associated CVEs. | 
| ASM.AssetInternetExposure.ips | String | IP addresses associated with the internet exposure. | 

### asm-get-asset-internet-exposure

***
Get internet exposure asset details according to the asset ID.

#### Base Command

`asm-get-asset-internet-exposure`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id | A string representing the asset ID for which you want to get the details. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AssetInternetExposure.asm_ids | String | Attack surface management UUID. | 
| ASM.AssetInternetExposure.name | String | Name of the exposed asset. | 
| ASM.AssetInternetExposure.type | String | Type of the exposed asset. | 
| ASM.AssetInternetExposure.last_observed | Unknown | Last time the exposure was observed. | 
| ASM.AssetInternetExposure.first_observed | Unknown | First time the exposure was observed. | 
| ASM.AssetInternetExposure.created | Date | Date the ASM issue was created. | 
| ASM.AssetInternetExposure.business_units | String | Asset associated business units. | 
| ASM.AssetInternetExposure.domain | Unknown | Asset associated domain. | 
| ASM.AssetInternetExposure.certificate_issuer | String | Asset certificate issuer. | 
| ASM.AssetInternetExposure.certificate_algorithm | String | Asset certificate algorithm. | 
| ASM.AssetInternetExposure.certificate_classifications | String | Asset certificate.classifications | 
| ASM.AssetInternetExposure.resolves | Boolean | Whether the asset has a DNS resolution. | 
| ASM.AssetInternetExposure.details | Unknown | Additional details. | 
| ASM.AssetInternetExposure.externally_inferred_vulnerability_score | Unknown | Asset vulnerability score. | 

### asm-list-alerts

***
Get a list of all your ASM alerts filtered by alert IDs, severity and/or creation time. Can also sort by creation time or severity. Maximum result limit is 100 assets.

#### Base Command

`asm-list-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id_list | Comma-separated list of integers of the alert ID. | Optional | 
| severity | Comma-separated list of strings of alert severity (valid values are low, medium, high, critical, informational). | Optional | 
| tags | Comma separated list of strings of alert tags. These should include the tag prefix, ex. AT:Asset Tag. | Optional | 
| status | Comma-separated list of strings of the alert status. Possible values are: new, under_investigation, resolved_no_longer_observed, resolved_no_risk, resolved_risk_accepted, resolved_contested_asset, resolved_remediated_automatically, resolved. | Optional | 
| business_units_list | Comma-separated list of strings of the business units. | Optional | 
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or before the specified date/time will be retrieved. | Optional | 
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or after the specified date/time will be retrieved. | Optional | 
| case_id_list | Comma-separated list of case (incident) IDs. | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 
| sort_by_severity | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc. | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Alert.alert_id | String | A unique identifier that Cortex XSIAM assigns to each alert. | 
| ASM.Alert.severity | String | The severity that was assigned to this alert when it was triggered \(Options are Informational, Low, Medium, High, Critical, or Unknown\). | 
| ASM.Alert.external_id | String | The alert ID as recorded in the detector from which this alert was sent. | 
| ASM.Alert.name | String | Summary of the ASM internet exposure alert. | 
| ASM.Alert.description | String | More detailed explanation of internet exposure alert. | 
| ASM.Alert.host_name | String | The hostname of the endpoint or server on which this alert triggered. | 
| ASM.Alert.dynamic_fields | Unknown | Alert fields pulled from Cortex XSOAR context. | 
| ASM.Alert.events | Unknown | Individual events that comprise the alert. | 
| ASM.Alert.detection_timestamp | Date | Date the alert was created. | 

### asm-get-attack-surface-rule

***
Fetches attack surface rules related to how Cortex Xpanse does assessment.

#### Base Command

`asm-get-attack-surface-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enabled_status | Enablement status to search rules with. Possible values are: On, Off. | Optional | 
| category | Comma separated list of strings attack surface rule categories. | Optional | 
| priority | Comma separated list of strings attack surface rule priorities. Options include Low, Medium, High, and Critical. | Optional | 
| attack_surface_rule_id | Comma-separated list of strings attack surface rule IDs. | Optional | 
| limit | Maximum number of results to return. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.AttackSurfaceRules.priority | unknown | Priority level for the different rules. Low, Medium, High, Critical. | 
| ASM.AttackSurfaceRules.attack_surface_rule_name | unknown | Name of the attack surface rule. | 
| ASM.AttackSurfaceRules.attack_surface_rule_id | unknown | ID of the attack surface rule. | 
| ASM.AttackSurfaceRules.description | unknown | Description of the attack surface rule. | 
| ASM.AttackSurfaceRules.category | unknown | Category of the attack surface rule. | 
| ASM.AttackSurfaceRules.remediation_guidance | unknown | Guidance for how to address various ASM risks. | 
| ASM.AttackSurfaceRules.enabled_status | unknown | Enablement status of the attack surface rule. | 
| ASM.AttackSurfaceRules.created | unknown | Creation date of the attack surface rule. | 
| ASM.AttackSurfaceRules.modified | unknown | Last modification of the attack surface rule. | 

### asm-tag-asset-assign

***
Assigns tags to a list of assets.

#### Base Command

`asm-tag-asset-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id_list | Comma-separated list of asset IDs to add tags to. | Required | 
| tags | The name of the tags to apply to supplied assets. | Required | 

#### Context Output

There is no context output for this command.
### asm-tag-asset-remove

***
Removes tags from a list of assets.

#### Base Command

`asm-tag-asset-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id_list | Comma-separated list of asset IDs to remove tags from. | Optional | 
| tags | The name of the tags to remove from supplied assets. | Optional | 

#### Context Output

There is no context output for this command.
### asm-tag-range-assign

***
Assigns tags to a list of IP ranges.

#### Base Command

`asm-tag-range-assign`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id_list | Comma-separated list of range IDs to add tags to. | Optional | 
| tags | The name of the tags to apply to supplied assets. | Optional | 

#### Context Output

There is no context output for this command.
### asm-tag-range-remove

***
Removes tags from a list of IP ranges.

#### Base Command

`asm-tag-range-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id_list | Comma-separated list of range IDs to remove tags from. | Optional | 
| tags | The name of the tags to remove from supplied IP ranges. | Optional | 

#### Context Output

There is no context output for this command.
### asm-list-incidents

***
Fetches ASM incidents that match provided filters. Incidents are an aggregation of related alerts. Note: Incident IDs may also be references as "Case IDs' elsewhere in the API.

#### Base Command

`asm-list-incidents`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id_list | Incident IDs to filter on. Note: Incident IDs may also be references as "Case IDs' elsewhere in the API. | Optional | 
| description | String to search for within the incident description field. | Optional | 
| status | Status to search incidents for. Possible values are: new, under_investigation, resolved. | Optional | 
| lte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or before the specified date/time will be retrieved. | Optional | 
| gte_creation_time | A date in the format 2019-12-31T23:59:00. Only incidents that were created on or after the specified date/time will be retrieved. | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). | Optional | 
| sort_by_severity | Sorts returned incidents by the severity of the incident. | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Incident.alert_count | Number | Number of alerts included in the incident. | 
| ASM.Incident.alerts_grouping_status | String | Whether alert grouping is enabled. | 
| ASM.Incident.assigned_user_mail | Unknown | Email of the assigned user. | 
| ASM.Incident.assigned_user_pretty_name | Unknown | Friendly name of the assigned user. | 
| ASM.Incident.creation_time | Date | Creation timestamp. | 
| ASM.Incident.critical_severity_alert_count | Number | Number of critical alerts. | 
| ASM.Incident.description | String | Description of the incident. | 
| ASM.Incident.high_severity_alert_count | Number | Number of high alerts. | 
| ASM.Incident.incident_id | String | ID of the incident. | 
| ASM.Incident.incident_name | Unknown | Incident name. | 
| ASM.Incident.incident_sources | String | Incident source. | 
| ASM.Incident.low_severity_alert_count | Number | Number of low alerts. | 
| ASM.Incident.manual_severity | Unknown | Severity override. | 
| ASM.Incident.med_severity_alert_count | Number | Number of medium alerts. | 
| ASM.Incident.modification_time | Date | Modification timestamp. | 
| ASM.Incident.notes | Unknown | Incident notes. | 
| ASM.Incident.original_tags | Unknown | Tags on the incident at creation time. | 
| ASM.Incident.resolve_comment | Unknown | Resolution comment \(optional\). | 
| ASM.Incident.resolved_timestamp | Unknown | Resolution timestamp. | 
| ASM.Incident.severity | String | Severity of the incident. | 
| ASM.Incident.starred | Boolean | Whether the incident has been starred. | 
| ASM.Incident.status | String | Status of the incident. | 
| ASM.Incident.tags | String | Tags on the incident. | 
| ASM.Incident.xdr_url | String | Link to navigate to the incident. | 
| ASM.Incident.xpanse_risk_score | Unknown | Risk score of the incident. | 

### asm-update-incident

***
Updates a given incident. Can be used to modify the status, severity, assignee, or add comments.

#### Base Command

`asm-update-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | ID of the incident to modify. | Required | 
| alert_id | Used for scoping updates such as comments to the alert level. | Optional | 
| assigned_user_mail | Email address of the user to assign incident to. This user must exist within your Expander instance. | Optional | 
| manual_severity | Administrator-defined severity for the incident. Possible values are: Low, Medium, High, Critical. | Optional | 
| status | Incident status. Possible values are: new, under_investigation, resolved. | Optional | 
| resolve_comment | Optional resolution comment when resolving the incident. | Optional | 
| comment | A comment to add to the incident. If an alert_id is supplied it will be prefixed to the comment. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.IncidentUpdate | unknown | Whether the incident update was successful. | 

### asm-update-alerts

***
Updates the state of one or more alerts.

#### Base Command

`asm-update-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id_list | Comma-separated list of integers of the alert ID. | Optional | 
| status | Updated alert status. Possible values are: new, under_investigation, resolved, resolved_contested_asset, resolved_risk_accepted, resolved_no_risk, resolved_remediated_automatically. | Optional | 
| severity | The severity of the alert. Possible values are: low, medium, high, critical. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.UpdatedAlerts | unknown | IDs of the updated alerts. | 

### ip

***
Returns enrichment for an IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.IP.ip | string | The IP address of the asset. | 
| ASM.IP.domain | string | The domain affiliated with an asset. | 
| ASM.IP.name | string | The asset name. | 
| ASM.IP.asset_type | string | The asset type. | 
| ASM.IP.first_observed | unknown | When the asset was first observed. | 
| ASM.IP.last_observed | unknown | When the asset was last observed. | 
| ASM.IP.asm_ids | unknown | The ID of the asset. | 
| ASM.IP.service_type | unknown | Affiliated service types for the asset. | 
| ASM.IP.tags | unknown | A list of tags that have been assigned to the asset. | 
| ASM.IP.asset_explainers | unknown | The asset explanation details. | 
| ASM.IP.domain_details | unknown | Additional domain details. | 
| ASM.IP.recent_ips | unknown | Details about the recent IP observations. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| IP.Address | String | IP address. | 

### domain

***
Returns enrichment for a domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to enrich. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Domain.domain | string | The domain affiliated with an asset. | 
| ASM.Domain.name | string | The asset name. | 
| ASM.Domain.asset_type | string | The asset type. | 
| ASM.Domain.first_observed | unknown | When the asset was first observed. | 
| ASM.Domain.last_observed | unknown | When the asset was last observed. | 
| ASM.Domain.asm_ids | unknown | The ID of the asset. | 
| ASM.Domain.service_type | unknown | Affiliated service types for the asset. | 
| ASM.Domain.tags | unknown | A list of tags that have been assigned to the asset. | 
| ASM.Domain.asset_explainers | unknown | The asset explanation details. | 
| ASM.Domain.domain_details | unknown | Additional domain details. | 
| ASM.Domain.recent_ips | unknown | Details about the recent IP observations. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | The reliability of the source providing the intelligence data. | 
| Domain.Name | String | The domain name, for example: "google.com". | 

### asm-get-incident

***
Returns additional details about a specific incident.

#### Base Command

`asm-get-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident to be fetched. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.Incident.incident_id | string | The ID of the incident. | 
| ASM.Incident.xpanse_risk_score | number | The Xpanse risk score of the incident. | 
| ASM.Incident.alerts | unknown | The alerts included in the incident. | 
| ASM.Incident.tags | unknown | Tags assigned to assets included in the incident. | 
| ASM.Incident.status | string | The status of the incident. | 
| ASM.Incident.severity | string | The severity of the incident. | 
| ASM.Incident.description | string | A brief description of the incident. | 
| ASM.Incident.notes | string | User-provided notes related to the incident. | 

### asm-get-external-websites

***
Get external websites assets.

#### Base Command

`asm-get-external-websites`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | search filter - can be used to get all login pages. Default is ALL. | Optional | 
| limit | Maximum number of assets to return. The default and maximum is 100. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.ExternalWebsites | unknown | A list of the websites results assets. | 
