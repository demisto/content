Integration to pull asset and other ASM related information
This integration was integrated and tested with version xx of Cortex Attack Surface Management

## Configure Cortex Attack Surface Management on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex Attack Surface Management.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Use system proxy | False |
    | Trust any certificate | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### asm-getexternalservices
***
Get a list of all your external services filtered by business units, externally detected providers, domain, externally inferred CVEs, acve classificaons, inacve classificaons, service name, service type, protocol, IP address, is acve, and discovery type. Maximum result limit is 100 assets.


#### Base Command

`asm-getexternalservices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP Address to search on. | Optional | 
| domain | Domain to search on. | Optional | 
| is_active | is the service active or not. Possible values are: yes, no. | Optional | 
| discovery_type | how service was discovered. Possible values are: colocated_on_ip, directly_discovery, unknown. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalServices.service_id | String | External service UUID | 
| ASM.GetExternalServices.service_name | String | Name of the external service | 
| ASM.GetExternalServices.service_type | String | Type of external service | 
| ASM.GetExternalServices.ip_address | String | IP address of external service | 
| ASM.GetExternalServices.externally_detected_providers | String | Providers of external service | 
| ASM.GetExternalServices.is_active | String | Is external service active or not | 
| ASM.GetExternalServices.first_observed | Date | Date of first observation of external service | 
| ASM.GetExternalServices.last_observed | Date | Date of last observation of external service | 
| ASM.GetExternalServices.port | Number | Port number of external service | 
| ASM.GetExternalServices.protocol | String | Protocol number of external service | 
| ASM.GetExternalServices.inactive_classifications | String | External service classifications that are no longer active | 
| ASM.GetExternalServices.discovery_type | String | How external service was discovered | 
| ASM.GetExternalServices.business_units | String | External service associated business units | 
| ASM.GetExternalServices.externally_inferred_vulnerability_score | Unknown | External service vulnerability score | 

### asm-getexternalservice
***
Get service details according to the service ID.


#### Base Command

`asm-getexternalservice`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | An string represenng the service ID you want get details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalService.service_id | String | External service UUID | 
| ASM.GetExternalService.service_name | String | Name of the external service | 
| ASM.GetExternalService.service_type | String | Type of external service | 
| ASM.GetExternalService.ip_address | String | IP address of external service | 
| ASM.GetExternalService.externally_detected_providers | String | Providers of external service | 
| ASM.GetExternalService.is_active | String | Is external service active or not | 
| ASM.GetExternalService.first_observed | Date | Date of first observation of external service | 
| ASM.GetExternalService.last_observed | Date | Date of last observation of external service | 
| ASM.GetExternalService.port | Number | Port number of external service | 
| ASM.GetExternalService.protocol | String | Protocol of external service | 
| ASM.GetExternalService.inactive_classifications | String | External service classifications that are no longer active | 
| ASM.GetExternalService.discovery_type | String | How external service was discovered | 
| ASM.GetExternalService.business_units | String | External service associated business units | 
| ASM.GetExternalService.externally_inferred_vulnerability_score | Unknown | External service vulnerability score | 
| ASM.GetExternalService.details | String | Additional details | 

### asm-getexternalipaddressranges
***
Get a list of all your Internet exposure filtered by business units and organization handles. Maximum result limit is 100 ranges.


#### Base Command

`asm-getexternalipaddressranges`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalIpAddressRanges.range_id | String | External IP address range UUID | 
| ASM.GetExternalIpAddressRanges.first_ip | String | First IP address of external IP address range | 
| ASM.GetExternalIpAddressRanges.last_ip | String | Last IP address of external IP address range | 
| ASM.GetExternalIpAddressRanges.ips_count | Number | Number of IP addresses of external IP address range | 
| ASM.GetExternalIpAddressRanges.active_responsive_ips_count | Number | How many IPs in external address range are actively responsive | 
| ASM.GetExternalIpAddressRanges.date_added | Date | Date the external IP address range was added | 
| ASM.GetExternalIpAddressRanges.business_units | String | External IP address range associated business units | 
| ASM.GetExternalIpAddressRanges.organization_handles | String | External IP address range associated organization handles | 

### asm-getexternalipaddressrange
***
Get external IP address range details according to the range IDs.


#### Base Command

`asm-getexternalipaddressrange`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| range_id | An string representing the range ID for which you want to get the details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetExternalIpAddressRange.range_id | String | External IP address range UUID | 
| ASM.GetExternalIpAddressRange.first_ip | String | First IP address of external IP address range | 
| ASM.GetExternalIpAddressRange.last_ip | String | Last IP address of external IP address range | 
| ASM.GetExternalIpAddressRange.ips_count | Number | Number of IP addresses of external IP address range | 
| ASM.GetExternalIpAddressRange.active_responsive_ips_count | Number | How many IPs in external address range are actively responsive | 
| ASM.GetExternalIpAddressRange.date_added | Date | Date the external IP address range was added | 
| ASM.GetExternalIpAddressRange.business_units | String | External IP address range associated business units | 
| ASM.GetExternalIpAddressRange.organization_handles | String | External IP address range associated organization handles | 
| ASM.GetExternalIpAddressRange.details | String | Additional information | 

### asm-getassetsinternetexposure
***
Get a list of all your Internet exposure filtered by ip address, domain, type, and/or if there is an active external service. Maximum result limit is 100 assets.


#### Base Command

`asm-getassetsinternetexposure`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | IP Address to search on. | Optional | 
| name | name of asset to search on. | Optional | 
| type | type of external service. Possible values are: certificate, cloud_compute_instance, on_prem, domain, unassociated_responsive_ip. | Optional | 
| has_active_external_services | does the internet exposure have an active external service. Possible values are: yes, no. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetAssetsInternetExposure.asm_ids | String | Attack surface managment UUID | 
| ASM.GetAssetsInternetExposure.name | String | Name of the exposed asset | 
| ASM.GetAssetsInternetExposure.asset_type | String | Type of the exposed asset | 
| ASM.GetAssetsInternetExposure.cloud_provider | Unknown | The cloud provider used to collect these cloud assets as either GCP, AWS, or Azure | 
| ASM.GetAssetsInternetExposure.region | Unknown | Displays the region as provided by the Cloud provider | 
| ASM.GetAssetsInternetExposure.last_observed | Unknown | Last time exposure was observed | 
| ASM.GetAssetsInternetExposure.first_observed | Unknown | First time exposure was observed | 
| ASM.GetAssetsInternetExposure.has_active_externally_services | Boolean | If the internet exposure is associated with active external service\(s\) | 
| ASM.GetAssetsInternetExposure.has_xdr_agent | String | If the internet exposure asset has an XDR agent | 
| ASM.GetAssetsInternetExposure.cloud_id | Unknown | Displays the Resource ID as provided from the cloud provider | 
| ASM.GetAssetsInternetExposure.domain_resolves | Boolean | is the asset domain resolvable | 
| ASM.GetAssetsInternetExposure.operation_system | Unknown | The operang system reported by the source for this asset | 
| ASM.GetAssetsInternetExposure.agent_id | Unknown | If there is an endpoint installed on this asset, this is the endpoint ID | 
| ASM.GetAssetsInternetExposure.externally_detected_providers | String | The provider of the asset as determined by an external assessment | 
| ASM.GetAssetsInternetExposure.service_type | String | Type of asset | 
| ASM.GetAssetsInternetExposure.externally_inferred_cves | String | If the internet exposure has associated CVEs | 
| ASM.GetAssetsInternetExposure.ips | String | IP addresses associated wih the internet exposure | 

### asm-getassetinternetexposure
***
Get Internet exposure asset details according to the asset ID.


#### Base Command

`asm-getassetinternetexposure`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asm_id | An string representing the asset ID for which you want to get the details for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ASM.GetAssetInternetExposure.asm_ids | String | Attack surface managment UUID | 
| ASM.GetAssetInternetExposure.name | String | Name of the exposed asset | 
| ASM.GetAssetInternetExposure.type | String | Type of the exposed asset | 
| ASM.GetAssetInternetExposure.last_observed | Unknown | Last time exposure was observed | 
| ASM.GetAssetInternetExposure.first_observed | Unknown | First time exposure was observed | 
| ASM.GetAssetInternetExposure.created | Date | Date the ASM Issue was created | 
| ASM.GetAssetInternetExposure.business_units | String | Asset associated business units | 
| ASM.GetAssetInternetExposure.domain | Unknown | Asset associated domain | 
| ASM.GetAssetInternetExposure.certificate_issuer | String | Asset certificate issuer | 
| ASM.GetAssetInternetExposure.certificate_algorithm | String | Asset certificate algorithm | 
| ASM.GetAssetInternetExposure.certificate_classifications | String | Asset certificate classifications | 
| ASM.GetAssetInternetExposure.resolves | Boolean | Does the asset have DNS resolution | 
| ASM.GetAssetInternetExposure.details | Unknown | Additional details | 
| ASM.GetAssetInternetExposure.externally_inferred_vulnerability_score | Unknown | Asset vulnerability score | 
