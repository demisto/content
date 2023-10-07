Use the Akamai WAF integration to manage common sets of lists used by various Akamai security products and features.

This is the modified version where a new command "akamai-update-network-list-elements" was added by the SA.

## Configure Akamai WAF on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Akamai WAF.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://example.net) | True |
    | Client token | True |
    | Access token | True |
    | Client secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### akamai-get-network-lists

***
Returns a list of all network lists available for an authenticated user who belongs to a group.

#### Base Command

`akamai-get-network-lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The network list type by which to filter the results. Possible values are: IP, GEO. | Optional | 
| search | The query by which to search for list names and list items. | Optional | 
| extended | When enabled, provides additional response data identifying who created and updated the list and when, and the network list’s deployment status in both STAGING and PRODUCTION environments. This data takes longer to provide. Possible values are: true, false. Default is true. | Optional | 
| include_elements | If enabled, the response list includes all items. For large network lists, this may slow responses and yield large response objects. The default false value when listing more than one network list omits the network list’s elements and only provides higher-level metadata. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. | 
| Akamai.NetworkLists.Lists.Type | String | The network list type. | 
| Akamai.NetworkLists.Lists.UniqueID | String | The network list unique ID. | 
| Akamai.NetworkLists.Lists.ElementCount | String | The number of network list elements. | 
| Akamai.NetworkLists.Lists.CreateDate | Date | The network list creation date. | 
| Akamai.NetworkLists.Lists.CreatedBy | String | The network list creator. | 
| Akamai.NetworkLists.Lists.ExpeditedProductionActivationStatus | String | The expedited production activation status. | 
| Akamai.NetworkLists.Lists.ExpeditedStagingActivationStatus | String | The expedited staging activation status. | 
| Akamai.NetworkLists.Lists.ProductionActivationStatus | String | The production activation status. | 
| Akamai.NetworkLists.Lists.StagingActivationStatus | String | The staging activation status. | 
| Akamai.NetworkLists.Lists.UpdateDate | String | The date that the network list was updated. | 
| Akamai.NetworkLists.Lists.UpdatedBy | String | The last user that updated the network list. | 
| Akamai.NetworkLists.Lists.Elements | String | The elements in the network list. | 

### akamai-get-network-list-by-id

***
Gets a network list by the network list ID.

#### Base Command

`akamai-get-network-list-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The network list ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. | 
| Akamai.NetworkLists.Lists.Type | String | The network list type. | 
| Akamai.NetworkLists.Lists.UniqueID | String | The network list unique ID. | 
| Akamai.NetworkLists.Lists.ElementCount | Number | The number of network list elements. | 
| Akamai.NetworkLists.Lists.CreateDate | Date | The network list creation date. | 
| Akamai.NetworkLists.Lists.CreatedBy | String | The network list creator. | 
| Akamai.NetworkLists.Lists.ExpeditedProductionActivationStatus | String | The expedited production activation status. | 
| Akamai.NetworkLists.Lists.ExpeditedStagingActivationStatus | String | The expedited staging activation status. | 
| Akamai.NetworkLists.Lists.ProductionActivationStatus | String | The production activation status. | 
| Akamai.NetworkLists.Lists.StagingActivationStatus | String | The staging activation status. | 
| Akamai.NetworkLists.Lists.UpdateDate | String | The network list update date. | 
| Akamai.NetworkLists.Lists.UpdatedBy | String | The last user who updated the network list. | 
| Akamai.NetworkLists.Lists.Elements | String | The elements in the network list. | 

### akamai-create-network-list

***
Creates a new network list. Supports TXT file upload for elements.

#### Base Command

`akamai-create-network-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_name | The network list name. | Required | 
| list_type | The network list type. Possible values are: IP, GEO. | Required | 
| elements | The network list elements. | Optional | 
| entry_id | The War Room entry ID of the sample file. | Optional | 
| description | The network list description. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.Lists.Name | String | The network list name. | 
| Akamai.NetworkLists.Lists.UniqueID | String | The network list ID. | 
| Akamai.NetworkLists.Lists.Type | String | The network list type. | 
| Akamai.NetworkLists.Lists.ElementCount | Number | The number of elements in the list. | 
| Akamai.NetworkLists.Lists.Elements | String | The elements in the list. | 

### akamai-delete-network-list

***
Deletes the specified network list.

#### Base Command

`akamai-delete-network-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network list to delete. | Required | 

#### Context Output

There is no context output for this command.
### akamai-activate-network-list

***
Activates a network list on the specified environment.

#### Base Command

`akamai-activate-network-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_ids | A comma-separated list of network list IDs to activate. For example: list (list1,list2). | Required | 
| env | The environment type to activate the network list. Possible values are: STAGING, PRODUCTION. | Required | 
| comment | A comment to be logged. | Optional | 
| notify | A comma-separated list of email addresses. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-add-elements-to-network-list

***
Adds elements to the specified network list.

#### Base Command

`akamai-add-elements-to-network-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network in which to add elements. | Required | 
| entry_id | The War Room entry ID of the sample file. | Optional | 
| elements | A comma-separated list of elements to add to the network list. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-remove-element-from-network-list

***
Removes elements from the specified network list.

#### Base Command

`akamai-remove-element-from-network-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network list from which to remove elements. | Required | 
| element | The element to remove from the network list. | Required | 

#### Context Output

There is no context output for this command.
### akamai-get-network-list-activation-status

***
Gets the activation status of the specified network list.

#### Base Command

`akamai-get-network-list-activation-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_ids | A comma-separated list of network list IDs for which to get the activation status. For example: (support list - list1,list2). | Required | 
| env | The environment type. Possible values are: PRODUCTION, STAGING. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.NetworkLists.ActivationStatus.UniqueID | String | The network list ID. | 
| Akamai.NetworkLists.ActivationStatus.StagingStatus | String | The network list environment staging activation status. | 
| Akamai.NetworkLists.ActivationStatus.ProductionStatus | String | The network list environment activation production status. | 

### akamai-update-network-list-elements

***
Updates list elements of a network list.

#### Base Command

`akamai-update-network-list-elements`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network_list_id | The ID of the network list to update. | Required | 
| elements | Comma-separated list of elements. Use BLANK to empty a list. | Required | 

#### Context Output

There is no context output for this command.
### akamai-check-group

***
Check an existing group within the context of your account.

#### Base Command

`akamai-check-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| checking_group_name | Group Name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.CheckGroup | unknown | Group ID. | 
| Akamai.CheckGroup.Found | unknown | Was the group found? | 
| Akamai.CheckGroup.groupName | unknown | The parent group name. | 
| Akamai.CheckGroup.parentGroupId | unknown | The parent group ID. | 
| Akamai.CheckGroup.groupId | unknown | The group ID. | 
| Akamai.CheckGroup.checking_group_name | unknown | Group name. | 

### akamai-create-group

***
Create a new group under a parent GID.

#### Base Command

`akamai-create-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_path | The group path separated with &gt;. | Required | 

#### Context Output

There is no context output for this command.
### akamai-create-enrollment

***
Create a new enrollment.

#### Base Command

`akamai-create-enrollment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| country | The country code (two letter format) for the country where your organization is located.. Default is US. | Required | 
| company | Company. | Required | 
| organizational_unit | Organizational unit. | Required | 
| city | The city of the admin contact. | Required | 
| contract_id | Contract ID. | Required | 
| certificate_type | Certificate type. Default is third-party. | Optional | 
| csr_cn | Common name. | Required | 
| admin_contact_address_line_one | Address of the admin contact. | Required | 
| admin_contact_first_name | The first name of the admin contact. | Required | 
| admin_contact_last_name | The last name of the admin contact. | Required | 
| admin_contact_email | The email address of the admin contact. | Required | 
| admin_contact_phone | The phone number of the admin contact. | Required | 
| tech_contact_first_name | The first name of the tech contact. | Required | 
| tech_contact_last_name | The last name  of the tech contact. | Required | 
| tech_contact_email | The email address of the tech contact. | Required | 
| tech_contact_phone | The phone number  of the tech contact. | Required | 
| org_name | The organization name. | Required | 
| org_country | The organization country name. | Required | 
| org_city | The organization city. | Required | 
| org_region | The organization region. | Required | 
| org_postal_code | The organization postal code. | Required | 
| org_phone | The organization phone number. | Required | 
| org_address_line_one | The organization address. | Required | 
| clone_dns_names | Network Configuration - Dns Name Settings - Clone DNS Names. Default is True. | Optional | 
| exclude_sans | Third Party - Exclude Sans. Default is False. | Optional | 
| change_management | Enable this will stop CPS from deploying the certificate to the network. Default is False. | Optional | 
| network_configuration_geography | Use core to specify worldwide (includes China and Russia), china+core to specify worldwide and China, and 'russia+core` to specify worldwide and Russia. Default is core. | Optional | 
| ra | The registration authority or certificate authority (CA) you want to use to obtain a certificate. Default is third-party. | Optional | 
| validation_type | Validation type, Either dv, ev, ov, or third-party. Default is third-party. | Optional | 
| enable_multi_stacked_certificates | Enable Dual-Stacked certificate deployment for this enrollment. Default is False. | Optional | 
| network_configuration_quic_enabled | Set to true to enable QUIC protocol. Default is True. | Optional | 
| network_configuration_secure_network | Set the type of deployment network you want to use. Default is enhanced-tls. | Optional | 
| network_configuration_sni_only | SNI settings for your enrollment. Set to true to enable SNI-only for the enrollment. Default is True. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollment | string | Enrollment path. | 

### akamai-list-enrollments

***
List enrollments of a specific contract.

#### Base Command

`akamai-list-enrollments`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 

#### Context Output

There is no context output for this command.
### akamai-create-domain

***
Create a domain with properties and domain controller (DC).

#### Base Command

`akamai-create-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain name. | Required | 
| group_id | Group ID. | Required | 

#### Context Output

There is no context output for this command.
### akamai-update-property

***
Update a property for a specific domain.

#### Base Command

`akamai-update-property`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | The domain name to which the new property is added. | Required | 
| property_name | New property name. | Required | 
| property_type | Property type. | Required | 
| static_type | Static type - "CNAME" or "A". | Optional | 
| static_server | Static server. | Optional | 
| server_1 | Server 1. | Optional | 
| server_2 | Server 2. | Optional | 
| weight_1 | Weight 1. | Optional | 
| weight_2 | Weight 2. | Optional | 
| property_comments | GTM property comments. | Optional | 
| dc1_id | Data center ID 1. | Optional | 
| dc2_id | Data center ID 2. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-get-change

***
Get the CPS code.

#### Base Command

`akamai-get-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_path | Enrollment path. | Required | 
| allowed_input_type_param | Currently supported values include change-management-info, lets-encrypt-challenges, post-verification-warnings, pre-verification-warnings, third-party-csr. Default is third-party-csr. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Change | unknown | Certificate Signing Request \(CSR\). | 

### akamai-update-change

***
Update the certs and trust chains.

#### Base Command

`akamai-update-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_path | The path of the changed certificate. | Required | 
| allowed_input_type_param | Allowed input type parameter. Default is third-party-cert-and-trust-chain. | Optional | 
| certificate | The updated certificate. | Optional | 
| trust_chain | The updated trust chain. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-get-enrollment-by-cn

***
Get enrollment by common name.

#### Base Command

`akamai-get-enrollment-by-cn`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| target_cn | Target common name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollment | unknown | Enrollment. | 
| Akamai.Enrollment.target_cn | unknown | Target common name. | 

### akamai-list-groups

***
Lists groups of Akamai.

#### Base Command

`akamai-list-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Group | unknown | Akmai Group | 

### akamai-get-group

***
Get group.

#### Base Command

`akamai-get-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group ID. Default is 0. | Required | 

#### Context Output

There is no context output for this command.
### akamai-get-domains

***
Get Google Tag Manager (GTM) domains.

#### Base Command

`akamai-get-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Domain | unknown | Domains. | 

### akamai-get-domain

***
Get a specific GTM domain.

#### Base Command

`akamai-get-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain name to get. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Domain | unknown | Domain. | 

### akamai-create-datacenter

***
Create a data center.

#### Base Command

`akamai-create-datacenter`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_name | Domain Name. | Required | 
| dc_name | Domain controller name. | Required | 
| dc_country | Country name. Default is US. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-clone-papi-property

***
Clone a new PAPI property.

#### Base Command

`akamai-clone-papi-property`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | ID for a specific Akamai product. | Required | 
| property_name | Property Manager API (PAPI) (Ion Standard) property name. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| property_id | Property Manager API (PAPI) (Ion Standard) property ID. | Required | 
| version | Property version. | Required | 
| check_existence_before_create | Whether to continue execution if an existing record is found without creating a new record. Default is yes. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.PropertyName | unknown | PAPI \(Ion Standard\) property name. | 
| Akamai.PapiProperty.PropertyId | unknown | PAPI \(Ion Standard\) property ID. | 
| Akamai.PapiProperty.AssetId | unknown | PAPI \(Ion Standard\) property asset ID. | 

### akamai-add-papi-property-hostname

***
Add hostnames to the PAPI property.

#### Base Command

`akamai-add-papi-property-hostname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| property_version | PAPI (Ion Standard) property version. Default is 1. | Required | 
| property_id | PAPI (Ion Standard) property ID. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| validate_hostnames | Validate hostnames. | Optional | 
| include_cert_status | Include the certificate status for the hostname. | Optional | 
| cname_from | URL of the common name. | Required | 
| edge_hostname_id | Edge hostname ID. | Required | 
| sleep_time | Sleep time in seconds between each iteration. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | ETag for concurrency control. | 

### akamai-new-papi-edgehostname

***
Add a PAPI edge hostname.

#### Base Command

`akamai-new-papi-edgehostname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | ID for a specific Akamai product. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| options | Comma-separated list of options to enable. mapDetails enables extra mapping-related information. | Optional | 
| domain_prefix | URL of domain name. | Required | 
| domain_suffix | URL of the partial domain name appended by Akamai. | Required | 
| ip_version_behavior | IP version. IPv4, IPv6, or IPv4 plus IPv6. | Required | 
| secure | SSL secured URL. | Optional | 
| secure_network | SSL secured protocol options. | Optional | 
| cert_enrollment_id | Certificate enrollment ID for the domain URL. | Optional | 
| check_existence_before_create | Whether to continue execution if an existing record is found without creating a new record. Default is yes. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.EdgeHostnames.EdgeHostnameId | unknown | Edge hostname ID. | 
| Akamai.PapiProperty.EdgeHostnames.DomainPrefix | unknown | Edge hostname domain prefix URL. | 

### akamai-get-cps-enrollmentid-by-cnname

***
Get cps certificate enrollment ID by common name.

#### Base Command

`akamai-get-cps-enrollmentid-by-cnname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| cnname | URL of common name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Cps.Enrollment.EnrollmentId | unknown | Certificate enrollment ID. | 
| Akamai.Cps.Enrollment.CN | unknown | Certificate enrollment common name. | 

### akamai-new-papi-cpcode

***
Create a new PAPI CP code.

#### Base Command

`akamai-new-papi-cpcode`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | ID for specific Akamai product. | Required | 
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| cpcode_name | Content provider codes name. | Required | 
| check_existence_before_create | Whether to continue execution if an existing record is found without creating a new record. Default is yes. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiCpcode.CpcodeId | unknown | Content provider code ID. | 

### akamai-patch-papi-property-rule-cpcode

***
Patch PAPI property default rule with a CP code.

#### Base Command

`akamai-patch-papi-property-rule-cpcode`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| property_id | PAPI (Ion Standard) property ID. | Required | 
| property_version | PAPI (Ion Standard) property version. | Optional | 
| validate_rules | Whether to validate rules. | Optional | 
| operation | JSON patch operation. Add, Remove, Replace. | Optional | 
| path | Dictionary path. | Optional | 
| cpcode_id | Content provider code ID. | Optional | 
| name | Content provider code name. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | ETag for concurrency control. | 

### akamai-patch-papi-property-rule-origin

***
Patch PAPI property default rule with an origin.

#### Base Command

`akamai-patch-papi-property-rule-origin`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| property_id | PAPI (Ion Standard) property ID. | Required | 
| property_version | PAPI (Ion Standard) property version. | Required | 
| validate_rules | Whether to validate rules. | Required | 
| operation | JSON patch operation. Add, Remove, Replace. | Required | 
| path | Dictionary path. | Required | 
| origin | value. | Required | 
| external_url | External URL FQDN. | Required | 
| gzip_compression | Gzip compression. | Optional | 
| sleep_time | Sleep time between each iteration. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | Etag for Concurrency Control. | 

### akamai-activate-papi-property

***
Activate a PAPI property.

#### Base Command

`akamai-activate-papi-property`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Configuration group ID. | Required | 
| property_id | PAPI (Ion Standard) property ID. | Required | 
| network | STAGING or PRODUCTION. | Optional | 
| notify_emails | Notification emails. | Optional | 
| property_version | PAPI (Ion Standard) property version. | Optional | 
| note | activation note. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Staging.ActivationId | unknown | Staging activation ID. | 
| Akamai.PapiProperty.Production.ActivationId | unknown | Production activation ID. | 

### akamai-clone-security-policy

***
AppSec clone security policy.

#### Base Command

`akamai-clone-security-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec configuration ID. | Required | 
| config_version | AppSec configuration version. | Required | 
| create_from_security_policy | Baseline security policy ID. | Required | 
| policy_name | New security policy name. | Required | 
| policy_prefix | Security policy ID prefix. | Optional | 
| check_existence_before_create | Whether to continue execution if an existing record is found without creating a new record. Default is yes. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Policy.PolicyName | unknown | Security policy name. | 
| Akamai.AppSecConfig.Policy.PolicyId | unknown | Security policy ID. | 

### akamai-new-match-target

***
AppSec create match target.

#### Base Command

`akamai-new-match-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec configuration ID. | Required | 
| config_version | AppSec configuration version. | Required | 
| policy_id | Security policy ID. | Required | 
| match_type | Website. | Required | 
| hostnames | Comma-separated list of hostname URLs. | Required | 
| bypass_network_lists | Comma-separated list of bypass networks. | Required | 
| file_paths | File paths. Default is /*. | Required | 
| default_file | Default is noMatch. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Policy.PolicyName | unknown | Security policy name. | 
| Akamai.AppSecConfig.Policy.PolicyId | unknown | Security policy ID. | 
| Akamai.AppSecConfig.Policy.TargetId | unknown | Match target ID. | 

### akamai-activate-appsec-config-version

***
AppSec activate appsec configuration version.

#### Base Command

`akamai-activate-appsec-config-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec configuration ID. | Required | 
| config_version | AppSec configuration version. | Required | 
| acknowledged_invalid_hosts | Default is N/A. | Required | 
| notification_emails | List of notification emails. | Required | 
| action | Activate. | Required | 
| network | STAGING or PRODUCTION. | Required | 
| note | Note to describe the activity. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Staging.ActivationId | unknown | Security configuration staging activation ID. | 
| Akamai.AppSecConfig.Production.ActivationId | unknown | Security configuration production activation ID. | 

### akamai-get-appsec-config-activation-status

***
AppSec get appsec config activation status.

#### Base Command

`akamai-get-appsec-config-activation-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activation_id | Security configuration activation ID. | Required | 
| sleep_time | Sleep time in seconds between each iteration. | Required | 
| retries | Number of retries of the consistency check to be conducted. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Staging | unknown | Staging Security Configration. | 
| Akamai.AppSecConfig.Production | unknown | Production Security Configration. | 

### akamai-get-appsec-config-latest-version

***
AppSec get appsec config latest version.

#### Base Command

`akamai-get-appsec-config-latest-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sec_config_name | Name of the security configuration. | Required | 
| sleep_time | Number of seconds to wait before the next consistency check. | Required | 
| retries | Number of retries of the consistency check to be conducted. | Required | 
| skip_consistency_check | Do not perform LatestVersion, Staging Version, Production Version consistency check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.LatestVersion | unknown | Security configuration latest version number. | 

### akamai-get-security-policy-id-by-name

***
AppSec get security policy ID by name.

#### Base Command

`akamai-get-security-policy-id-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Security Policy Name. | Required | 
| config_id | AppSec configuration ID. | Required | 
| config_version | AppSec configuration version. | Required | 
| is_baseline_policy | Whether this is the baseline security policy. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.BasePolicyName | unknown | Baseline security policy name. | 
| Akamai.AppSecConfig.BasePolicyId | unknown | Baseline security policy ID. | 
| Akamai.AppSecConfig.Policy.PolicyName | unknown | Security policy name. | 
| Akamai.AppSecConfig.Policy.PolicyId | unknown | Baseline security policy ID. | 
| Akamai.AppSecConfig.Id | unknown | AppSec security configuration ID. | 

### akamai-clone-appsec-config-version

***
AppSec_clone appsec config version

#### Base Command

`akamai-clone-appsec-config-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | AppSec configuration ID. | Required | 
| create_from_version | AppSec configuration version. | Required | 
| rule_update | Specifies whether the application rules should be migrated to the latest version. Possible values are: True, False. Default is True. | Optional | 
| do_not_clone | Do not clone to create a new version. Use in the test. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfig.Name | unknown | AppSec configuration name. | 
| Akamai.AppSecConfig.Id | unknown | AppSec Configration ID | 
| Akamai.AppSecConfig.NewVersion | unknown | AppSec Configration New Version | 

### akamai-patch-papi-property-rule-httpmethods

***
Patch PAPI property rule HTTP methods.

#### Base Command

`akamai-patch-papi-property-rule-httpmethods`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Contract ID. | Required | 
| group_id | Group ID. | Required | 
| property_id | Property ID. | Required | 
| property_version | Property Version. | Optional | 
| validate_rules | Whether to validate the Rules. | Required | 
| operation | The operation to execute. | Required | 
| path | The path of the rule. | Required | 
| value | The value of the HTTP Method in dictionary format. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.Etag | unknown | ETag for concurrency control. | 

### akamai-get-papi-property-activation-status-command

***
Get PAPI property activation status until it is active.

#### Base Command

`akamai-get-papi-property-activation-status-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| activation_id | Ion property activation ID. | Required | 
| property_id | Ion property ID. | Required | 
| sleep_time | Sleep time between retries. | Required | 
| retries | Number of retires. | Required | 

#### Context Output

There is no context output for this command.
### akamai-get-papi-edgehostname-creation-status-command

***
Get PAPI edgehostname creation status command until it is created.

#### Base Command

`akamai-get-papi-edgehostname-creation-status-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | contract ID. | Required | 
| group_id | Group id. | Required | 
| edgehostname_id | Edge hostname ID. | Required | 
| options | mapDetails. | Required | 
| sleep_time | Sleep time between each iteration. | Required | 
| retries | Number of retries. | Required | 

#### Context Output

There is no context output for this command.
### akamai-acknowledge-warning-command

***
Acknowledge the warning message for uploading the certs and trust chains of enrollments.

#### Base Command

`akamai-acknowledge-warning-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_path | The path of the changed certificate. | Required | 

#### Context Output

There is no context output for this command.
### akamai-modify-appsec-config-selected-hosts

***
Update the list of selected hostnames for a configuration version.

#### Base Command

`akamai-modify-appsec-config-selected-hosts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | A unique identifier for each configuration. | Required | 
| config_version | A unique identifier for each version of a configuration. | Required | 
| hostname_list | A list hostnames is used to modifying the configuration. | Required | 
| mode | The type of update you want to make to the evaluation hostname list.             - Use "append" to add additional hostnames.             - Use "remove" to delete the hostnames from the list.             - Use "replace" to replace the existing list with the hostnames you pass in your request. Use "append" to add additional hostnames. Use "remove" to delete the hostnames from the list. Use "replace" to replace the existing list with the hostnames you pass in your request. | Required | 

#### Context Output

There is no context output for this command.
### akamai-get-production-deployment

***
Get Production Deployment

#### Base Command

`akamai-get-production-deployment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_id | The enrollment id. | Required | 

#### Context Output

There is no context output for this command.
### akamai-get-change-history

***
Get change history

#### Base Command

`akamai-get-change-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_id | The enrollment id. | Required | 

#### Context Output

There is no context output for this command.
### akamai-patch-papi-property-rule-siteshield

***
Patch papi property default rule siteshield

#### Base Command

`akamai-patch-papi-property-rule-siteshield`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Akamai contract Identity. | Required | 
| group_id | Akamai configuration group Identity. | Required | 
| property_id | Akamai Ion Property Identity. | Required | 
| property_version | Akamai Ion Property Version Identity. | Required | 
| validate_rules | Validate the rule or not - true or false. | Required | 
| operation | Json patch operation - add / delete / replace. | Required | 
| path | Json patch Rule path. | Required | 
| ssmap | siteshiled json format data. | Required | 

#### Context Output

There is no context output for this command.
### akamai-update-appsec-config-version-notes

***
Update application secuirty configuration version notes command

#### Base Command

`akamai-update-appsec-config-version-notes`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | The ID of the application seucirty configuration. | Required | 
| config_version | The version number of the application seucirty configuration. | Required | 
| notes | The notes need to be written into the application seucirty configuration version. | Required | 

#### Context Output

There is no context output for this command.
### akamai-new-or-renew-match-target

***
New match target if no existing found otherwise update the existing match target hostnames. If there are multiple match targets found, the first one in the list will be updated

#### Base Command

`akamai-new-or-renew-match-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | A unique identifier for each configuration. | Required | 
| config_version | A unique identifier for each version of a configuration. | Required | 
| match_type | The type of the match target. | Required | 
| bypass_network_lists | bypass network lists. | Required | 
| default_file | Describes the rule to match on paths. | Required | 
| file_paths | Contains a list of file paths. | Required | 
| hostnames | A list of hostnames that need to be added into match target. | Required | 
| policy_id | Specifies the security policy to filter match targets. | Required | 

#### Context Output

There is no context output for this command.
### akamai-patch-papi-property-rule-generic

***
Generic JSON patch command for Papi Property Default Rule

#### Base Command

`akamai-patch-papi-property-rule-generic`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | A unique identifier for each configuration. | Required | 
| group_id | A unique identifier for each group. | Required | 
| property_id | A unique identifier for each Papi Property. | Required | 
| property_version | A unique identifier for each Papi Property Version. | Required | 
| validate_rules | whether validate rule or not. | Required | 
| operation | add/replace/remove. | Required | 
| path | json rule tree path for the default rule. | Required | 
| value | value to be operated against. | Required | 
| value_to_json | whether to convert value to json format. yes/no. Possible values are: yes, no. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-get-papi-property-rule

***
get papi property rule json and dump into string

#### Base Command

`akamai-get-papi-property-rule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | A unique identifier for each configuration. | Required | 
| group_id | A unique identifier for each group. | Required | 
| property_id | A unique identifier for each Papi Property. | Required | 
| property_version | A unique identifier for each Papi Property Version. | Required | 
| validate_rules | whether validate rule or not. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.PapiProperty.DefaultRule | unknown | Papi Property default rule | 

### akamai-acknowledge-pre-verification-warning

***
acknowledge pre verification warning

#### Base Command

`akamai-acknowledge-pre-verification-warning`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_path | The path that includes enrollmentId and changeId. | Required | 

#### Context Output

There is no context output for this command.
### akamai-get-papi-property-by-name

***
Get PAPI property info without the default rule. To get the default rule, use the "get-papi-property-rule" command.

#### Base Command

`akamai-get-papi-property-by-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique identifier for the contract. | Required | 
| property_name | Name of the PAPI property. | Optional | 
| group_id | Unique identifier for the group. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-list-papi-property-by-group

***
Lists properties available for the current contract and group. 

#### Base Command

`akamai-list-papi-property-by-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique identifier for the contract. | Required | 
| group_id | Unique identifier for the group. | Required | 
| context_path | Custom output context path, default is "PapiProperty.ByGroup". Default is PapiProperty.ByGroup. | Optional | 

#### Context Output

There is no context output for this command.
### akamai-get-papi-property-by-id

***
get papi property info by id without default rule. to get default rule, please use "get-papi-property-rule" command.

#### Base Command

`akamai-get-papi-property-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique identifier of the contract. | Required | 
| group_id | Unique identifier for the group. | Required | 
| property_id | Unique identifier of the property. | Required | 

#### Context Output

There is no context output for this command.
### akamai-new-papi-property-version

***
Create a new property version based on any previous version.          All data from the createFromVersion populates the new version, including its rules and hostnames. 

#### Base Command

`akamai-new-papi-property-version`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique identifier for the contract. | Required | 
| property_id | Unique identifier for the property. | Required | 
| group_id | Unique identifier for the group. | Required | 
| create_from_version | The property version on which to base the new version. | Required | 

#### Context Output

There is no context output for this command.
### akamai-list-papi-property-activations

***
This lists all activations for all versions of a property, on both production and staging networks.

#### Base Command

`akamai-list-papi-property-activations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique identifier for the contract. | Required | 
| group_id | Unique identifier for the group. | Required | 
| property_id | Unique identifier for the property. | Required | 

#### Context Output

There is no context output for this command.
### akamai-list-appsec-configuration-activation-history

***
        Lists the activation history for a configuration.          The history is an array in descending order of submitDate.          The most recent submitted activation lists first. Products: All.

#### Base Command

`akamai-list-appsec-configuration-activation-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_id | Unique identifier for the contract. | Required | 

#### Context Output

There is no context output for this command.
### akamai-list-papi-property-by-hostname

***
Lists active property hostnames for all properties available in an account.

#### Base Command

`akamai-list-papi-property-by-hostname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Filter the results by cnameFrom. Supports wildcard matches with *. | Required | 
| network | Network of activated hostnames, either STAGING or PRODUCTION. Or leave it BLANK. Possible values are: STAGING, PRODUCTION. | Optional | 
| contract_id | Unique identifier for the contract. contract_id and groupd_id need to be presented at the same time. | Optional | 
| group_id | Unique identifier for the group. Both contract_id and group_id need to be defined. | Optional | 

#### Context Output

There is no context output for this command.



### akamai-list-siteshield-map

***
Returns a list of all Site Shield maps that belong to your account.

#### Base Command

`akamai-list-siteshield-map`

#### Input

There is no input for this command.

#### Context Output
`{
  "Akamai.SiteShieldMaps": [
    {
      "acknowledgeRequiredBy": 168321944560,
      "acknowledged": false,
      "acknowledgedBy": "example@fisglobal.com",
      "acknowledgedOn": 1676034518000,
      "contacts": [
        "example@fisglobal.com",
        "example@akamai.com"
      ],
      "currentCidrs": [
        "ip1",
        "ip2"
      ],
      "id": 1910627,
      "latestTicketId": 22728,
      "mapAlias": "Americas Secure Map",
      "mcmMapRuleId": 14002,
      "proposedCidrs": [
        "ip3",
      ],
      "ruleName": "s1702.akamaiedge.net",
      "service": "S",
      "shared": false,
      "sureRouteName": "example.akamai.com",
      "type": "Production"
    }
}`

