Use the Akamai WAF integration to manage common sets of lists used by various Akamai security products and features.

This is the modified version where a new command "akamai-update-network-list-elements" was added by the SA.

## Configure Akamai WAF in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://example.net) | True |
| Client token | False |
| Access token | False |
| Client secret | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
| country | The country code (two letter format) for the country where your organization is located. Default is US. | Required |
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
| sans | Multiple sans adding into the Common name. | Optional |

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
| key_algorithm | Type of encryption. Possible values are: RSA, ECDSA. | Optional |

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
| Akamai.Group | unknown | Akmai Group. |

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

### akamai-get-client-list

***
Get a client list.

#### Base Command

`akamai-get-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_list_id | An optional URL parameter to get a specific client list. | Optional |
| name | Filters the output to show only lists that match a given name. | Optional |
| include_items | Include items in the response. Possible values are: true, false. Default is false. | Optional |
| include_deprecated | Include deprecated lists in the response. Possible values are: true, false. Default is false. | Optional |
| search | Returns results that contain the specified substring in any client list or entry details. | Optional |
| type_list | Filters the output to show only lists of the specified types. Repeat the parameter to filter by multiple types. Valid values: IP, GEO, ASN, TLS_FINGERPRINT, FILE_HASH. Possible values are: IP, GEO, ASN, TLS_FINGERPRINT, FILE_HASH, USER. | Optional |
| include_network_list | Include network lists in the response. Possible values are: true, false. Default is false. | Optional |
| page | Page number. Default is 0. | Optional |
| page_size | Page size. Default is 50. | Optional |
| limit | Limit. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.ClientList | unknown | The client list. |

### akamai-create-client-list

***
Creates a new client list.

#### Base Command

`akamai-create-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the new client list. | Required |
| type | The type of client list. Possible values are: IP, GEO, ASN, TLS_FINGERPRINT, FILE_HASH, USER. | Required |
| contract_id | The contract ID. You can get this value by running the `akamai-get-contract-group` command. | Required |
| group_id | The group ID. You can get this value by running the `akamai-get-contract-group` command. | Required |
| notes | A description of the client list. | Optional |
| tags | A list of tags to attach to the client list. | Optional |
| entry_value | The value of a single entry in the client list. | Optional |
| entry_description | A description of the entry. | Optional |
| entry_expiration_date | The expiration date for the entry. Use ISO 8601 format (e.g. 2025-09-29 or 2025-09-29T13:15:28). | Optional |
| entry_tags | A list of tags attached to the entry. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.ClientList | unknown | The client list that was created. |

### akamai-deprecate-client-list

***
Deprecates a client list.

#### Base Command

`akamai-deprecate-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_list_id | The ID of the client list to be deprecated. | Required |

#### Context Output

There is no context output for this command.

### akamai-activate-client-list

***
Activates a client list.

#### Base Command

`akamai-activate-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the client list to activate. | Required |
| network_environment | The network environment where the list will be activated. Possible values are: STAGING, PRODUCTION. | Required |
| comments | A description of the activation. | Optional |
| notification_recipients | A list of email addresses to notify. | Optional |
| siebel_ticket_id | A Siebel ticket ID. | Optional |
| include_polling | Whether to poll deactivation status until completion. Possible values are: true, false. Default is true. | Optional |
| interval | Interval in seconds between polling attempts. Default is 30. | Optional |
| timeout | Timeout in seconds for polling. Default is 60. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Activation | unknown | The activation details. |

### akamai-add-client-list-entry

***
Adds an entry to a client list.

#### Base Command

`akamai-add-client-list-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the client list. | Required |
| value | The value of the new entry. | Required |
| description | A description of the new entry. | Optional |
| expiration_date | The expiration date for the new entry. Use ISO 8601 format (e.g. 2025-09-29 or 2025-09-29T13:15:28). | Optional |
| tags | A list of tags for the new entry. | Optional |

#### Context Output

There is no context output for this command.

### akamai-remove-client-list-entry

***
Removes an entry from a client list.

#### Base Command

`akamai-remove-client-list-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the client list. | Required |
| value | A list of values to remove from the client list. | Required |

#### Context Output

There is no context output for this command.

### akamai-get-contract-group

***
Get contract groups.

#### Base Command

`akamai-get-contract-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.ContractGroup | unknown | The contract groups. |

### akamai-update-client-list

***
Updates a client list.

#### Base Command

`akamai-update-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the client list to update. | Required |
| name | The new name of the client list. | Required |
| notes | The new description of the client list. | Optional |
| tags | The new tags for the client list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.ClientList | unknown | The updated client list. |

### akamai-deactivate-client-list

***
Deactivates a client list.

#### Base Command

`akamai-deactivate-client-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the client list to deactivate. | Required |
| network_environment | The network environment where the list is deactivated. Possible values are: STAGING, PRODUCTION. | Required |
| comments | A description for the deactivation. | Optional |
| notification_recipients | A list of email addresses to notify. | Optional |
| siebel_ticket_id | A Siebel ticket ID. | Optional |
| include_polling | Whether to poll deactivation status until completion. Possible values are: true, false. Default is true. | Optional |
| interval | Interval in seconds between polling attempts. Default is 30. | Optional |
| timeout | Timeout in seconds for polling. Default is 180. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Activation | unknown | The deactivation details. |

### akamai-update-client-list-entry

***
Updates an entry in a client list.

#### Base Command

`akamai-update-client-list-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_id | The ID of the client list. | Required |
| value | The value of the entry to update. | Required |
| description | The new description for the entry. | Optional |
| expiration_date | The new expiration date for the entry. Use ISO 8601 format (e.g. 2025-09-29 or 2025-09-29T13:15:28). | Optional |
| tags | The new tags for the entry. | Optional |
| is_override | Whether to override missing entries. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.ClientList | unknown | The updated client list. |

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
AppSec_clone appsec config version.

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
| Akamai.AppSecConfig.Id | unknown | AppSec Configration ID. |
| Akamai.AppSecConfig.NewVersion | unknown | AppSec Configration New Version. |

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
| allowed_input_type_param | Enum found as the last part of Change.allowedInput[].update hypermedia URL. Possible values are: change-management-ack, lets-encrypt-challenges-completed, post-verification-warnings-ack, pre-verification-warnings-ack. Default is post-verification-warnings-ack. | Optional |

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
Get Production Deployment.

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
Get change history.

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
Patch papi property default rule siteshield.

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
Update application secuirty configuration version notes command.

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
New match target if no existing found otherwise update the existing match target hostnames. If there are multiple match targets found, the first one in the list will be updated.

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
Generic JSON patch command for Papi Property Default Rule.

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
get papi property rule json and dump into string.

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
| Akamai.PapiProperty.DefaultRule | unknown | Papi Property default rule. |

### akamai-acknowledge-pre-verification-warning

***
acknowledge pre verification warning.

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
Lists the activation history for a configuration. The history is an array in descending order of submitDate. The most recent submitted activation lists first. Products: All.

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
| group_id | Unique identifier for the group. contract_id and groupd_id need to be presented at the same time. | Optional |

#### Context Output

There is no context output for this command.

### akamai-list-siteshield-map

***
Returns a list of all Site Shield maps that belong to your account.

#### Base Command

`akamai-list-siteshield-map`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.SiteShieldMaps | List | Akamai SiteShield Maps. |

### akamai-get-cps-enrollment-deployment

***
Returns the certification/enrollment deployment status for specific a environment: production or staging.

#### Base Command

`akamai-get-cps-enrollment-deployment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_id | Unique identifier of the enrollment on which to perform the desired operation. And it can be retrieved via the akamai-list-enrollments command. | Required |
| environment | Environment where the certificate is deployed. Possible values are: production, staging. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Cps.Enrollments.Deployment | Dictionary | A collection of settings for the Akami CPS enrollments deployment. |

### akamai-list-cidr-blocks

***
List all CIDR blocks for all services you are subscribed to. To see additional CIDR blocks, subscribe yourself to more services and run this operation again.

#### Base Command

`akamai-list-cidr-blocks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| last_action | Whether a CIDR block was added, updated, or removed from service. You can use this parameter as a sorting mechanism and return only CIDR blocks with a change status of add, update, or delete. Note that a status of delete means the CIDR block is no longer in service, and you can remove it from your firewall rules. Possible values are: all, add, delete, update. | Optional |
| effective_date_gt | The ISO 8601 date the CIDR block starts serving traffic to your origin. Ensure your firewall rules are updated to allow this traffic to pass through before the effective date. Expected format MM-DD-YYYY or YYYY-MM-DD. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.CidrBlocks | List | A list of CIDR blocks. |

### akamai-update-cps-enrollment

***
Updates an enrollment with changes. Response type will vary depending on the type and impact of change. For example, changing SANs list may return HTTP 202 Accepted since the operation requires new certificate and network deployment operations, and thus cannot be completed without a change. On the contrary, for example a Technical Contact name change may return HTTP 200 OK assuming there are no active changes and the operation does not require a new certificate. Reference: https://techdocs.akamai.com/cps/reference/put-enrollment  Note: Depending on the type of the modification, additional steps might be required to complete the update. These additional steps could be carrying out a "renew" change by resubmitting the CSR, acknowledging the warnings raised then waiting for the certificate to be deployed into Production. However, these additional steps are not included in this command. You need to perform those steps once the update command is completed.

#### Base Command

`akamai-update-cps-enrollment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_id | Enrollment on which to perform the desired operation. It can be retrieved via the akamai-list-enrollments command. | Required |
| updates | The modification(s) to the enrollment in the dict format. The possible modifications are: ra, validationType, certificateType, networkConfiguration, changeManagement, csr, org, adminContact, techContact, thirdParty, enableMultiStackedCertificates. | Required |
| enrollment | Enrollment information in dict format. If provided, the script will not make another API call to get the enrollment information. If not provided, another API call will be issued to retrieve the enrollment information. | Optional |
| allow_cancel_pending_changes | Whether all pending changes are to be cancelled when updating an enrollment. Possible values are: true, false. Default is true. | Optional |
| allow_staging_bypass | Whether to bypass staging and push meta_data updates directly to the production network. Current change will also be updated with the same changes. Possible values are: true, false. Default is true. | Optional |
| deploy_not_after | Don't deploy after this date (UTC). Sample: 2021-01-31T00:00:00.000Z. | Optional |
| deploy_not_before | Don't deploy before this date (UTC). Sample: 2021-01-31T00:00:00.000Z. | Optional |
| force_renewal | Whether to force certificate renewal for enrollment. Possible values are: true, false. Default is false. | Optional |
| renewal_date_check_override | Whether CPS will automatically start a change to renew certificates in time before they expire. Possible values are: true, false. Default is true. | Optional |
| allow_missing_certificate_addition | Applicable for Third Party Dual Stack Enrollment. Whether to update a missing certificate. Option supported from v10. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollment.Changes | Dictionary | Akamai enrollment changes. |

### akamai-update-cps-enrollment-schedule

***
Updates the current deployment schedule.

#### Base Command

`akamai-update-cps-enrollment-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_path | Enrollment path found in the pending change location field. | Optional |
| enrollment_id | Enrollment ID on which to perform the desired operation. The ID can be retrieved via the akamai-list-enrollments command. | Optional |
| change_id | Change ID on which to perform the desired operation. It can be retrieved via the akamai-list-enrollments command. | Optional |
| deploy_not_after | The time after when the change will no longer be in effect. This value is an ISO-8601 timestamp. (UTC) Sample: 2021-01-31T00:00:00.000Z. | Optional |
| deploy_not_before | The time that you want the change to take effect. If you do not set this, the change occurs immediately, although most changes take some time to take effect even when they are immediately effective. This value is an ISO-8601 timestamp. (UTC) Sample: 2021-01-31T00:00:00.000Z. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollment.Changes | Dictionary | Akamai enrollment changes. |

### akamai-get-cps-change-status

***
Gets the status of a pending change.

#### Base Command

`akamai-get-cps-change-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_path | Enrollment path found in the pending change location field. | Optional |
| enrollment_id | The enrollment ID on which to perform the desired operation. It can be retrieved via the akamai-list-enrollments command. | Optional |
| change_id | The change for this enrollment on which to perform the desired operation.  It can be retrieved via the akamai-list-enrollments command. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Enrollments.Change.Status | Dictionary | Akamai enrollments change status. |

### akamai-list-cps-active-certificates

***
Lists enrollments with active certificates. Note that the rate limit for this operation is 10 requests per minute per account.

#### Base Command

`akamai-list-cps-active-certificates`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique Identifier of a contract on which to operate or view. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Cps.Active.Certificates.Enrollments | Dictionary | A collection of Active Akami CPS enrollments. |

### akamai-cancel-cps-change

***
Cancels a pending change on CPS.

#### Base Command

`akamai-cancel-cps-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| change_id | The change for this enrollment on which to perform the desired operation. Default is 0. "change_path" is used. Default is 0. | Required |
| enrollment_id | Enrollment on which to perform the desired operation. Default is 0. "change_path" is used. Default is 0. | Required |
| change_path | Change path on which to perform the desired operation. Sample: /cps/v2/enrollments/100000/changes/88888888. Note: change_path is not listed in the reference as a parameter. However it can be extracted directly from "list_enrollments_command". This should be the most common usage when generating the RestAPI's URL. | Optional |
| account_switch_key | For customers who manage more than one account, this runs the operation from another account. The Identity and Access Management API provides a list of available account switch keys. | Optional |

#### Context Output

There is no context output for this command.

### akamai-get-cps-enrollment-by-id

***
Get an enrollment in CPS by enrollment id.

#### Base Command

`akamai-get-cps-enrollment-by-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enrollment_id | Enrollment ID on which to perform the desired operation. | Required |

#### Context Output

There is no context output for this command.

### akamai-list-appsec-config

***
Lists available security configurations. Products: All.

#### Base Command

`akamai-list-appsec-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.AppSecConfigAll | unknown | A list of dictionaries for all Akamai Security Configurations. |

### akamai-list-dns-zones

***
List all zones that the current user has access to manage.

#### Base Command

`akamai-list-dns-zones`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.EdgeDns.Zones | Dictionary | A collection of Edge DNS zones. |

### akamai-list-dns-zone-recordsets

***
Lists all record sets for this zone. It works only for PRIMARY and SECONDARY zones.

#### Base Command

`akamai-list-dns-zone-recordsets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| zone | The name of the zone. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.EdgeDns.ZoneRecordSets | Dictionary | A collection of Edge DNS zone's record sets. |

### akamai-new-datastream

***
Creates a stream configuration. Within a stream configuration, you can select properties to monitor in the stream, data set fields to collect in logs, and a destination to send these log files to. Get the streamId value from the response to use in the https://{hostname}/datastream-config-api/v2/log/streams/{streamId} endpoint URL. Apart from the log and delivery frequency configurations, you can decide whether to activate the stream on making the request or later using the activate parameter. Note that only active streams collect and send logs to their destinations. NOTE: "SPLUNK" and "HTTPS" are the only two types tested.

#### Base Command

`akamai-new-datastream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stream_name | The name of the stream. | Required |
| group_id | The unique identifier of the group that has access to the product and this stream configuration. | Required |
| contract_id | The unique identifier of the contract that has access to the product. | Optional |
| properties | The unique identifier of the properties that belong to the same product and to be monitored in the stream. Note that a stream can only log data for active properties. A property can be activated in Property Manager. | Optional |
| dataset_fields | The unique identifier of the data set fields to be included in stream logs. In case of STRUCTURED format, the order of the identifiers define how the value for these fields appear in the log lines. | Optional |
| interval_in_seconds | The interval in seconds (30 or 60) after which the system bundles log lines into a file and sends it to a destination. Possible values are: 30, 60. | Optional |
| log_format | The format in which you want to receive log files. STRUCTURED or JSON are the currently available formats. When the delimiter is present in the request, STRUCTURED format needs to be defined. | Optional |
| field_delimiter | A delimiter that separates data set fields in the log lines, either SPACE or TAB. Set this only for the STRUCTURED log file format. | Optional |
| upload_file_prefix | The prefix of the log file to be used when sending to a object-based destination. It's a string of at most 200 characters. If unspecified, it defaults to ak. This member supports Dynamic time variables, but doesn't support the '.' character. | Optional |
| upload_file_suffix | The suffix of the log file that you want to send to a object-based destination. It's a static string of at most 10 characters. If unspecified, it defaults to ds. This member doesn't support Dynamic time variables, and the ., /, %, ? characters. | Optional |
| ca_cert | The certification authority (CA) certificate used to verify the origin server's certificate. If the certificate is not signed by a well-known certification authority, enter the CA certificate in the PEM format for verification. If this value is set, the mTlsEnabled property replaces it in the response as true. | Optional |
| client_cert | The PEM-formatted digital certificate you want to authenticate requests to your destination with. If you want to use mutual authentication, you need to provide both the client certificate and the client key. If you pass this member, the mTlsEnabled member replaces it in the response as true. | Optional |
| client_key | The private key in the non-encrypted PKCS8 format that authenticates with the back-end server. If you want to use mutual authentication, you need to provide both the client certificate and the client key. | Optional |
| content_type | The type of the resource passed in the request's custom header. For details, see the additional options discussed in Stream logs to a HTTPS endpoint. | Optional |
| custom_header_name | A human-readable name for the request's custom header, containing only alphanumeric, dash, and underscore characters. For details, see the additional options discussed in Stream logs to a HTTPS endpoint. | Optional |
| custom_header_value | The custom header's contents passed with the request that contains information about the client connection. For details, see the additional options discussed in Stream logs to a HTTPS endpoint. | Optional |
| compress_logs | Enables gzip compression for a log file sent to a destination. True by default. Possible values are: True, False. | Optional |
| destination_type | The destination configuration in the stream to send logs. Note: "SPLUNK" and "HTTPS" are the only two types tested. Possible values are: HTTPS, SPLUNK. Default is SPLUNK. | Optional |
| display_name | The name of the destination. | Optional |
| endpoint | The raw event Splunk URL where the logs need to be sent to. Akamaized property hostnames can be used as endpoint URLs. See Stream logs to Splunk. | Optional |
| event_collector_token | The Event Collector token for your Splunk account. See View usage of Event Collector token in the Splunk documentation. | Optional |
| tls_hostname | The hostname that verifies the server's certificate and matches the Subject Alternative Names (SANs) in the certificate. If not provided, DataStream fetches the hostname from the endpoint URL. | Optional |
| notification_emails | A list of e-mail addresses where you want to send notifications about activations and deactivations of the stream. You can omit this member and activate or deactivate the stream without notifications. | Optional |
| collect_midgress | Indicates if you've opted to capture midgress traffic within the Akamai platform, such as between two edge servers. Possible values are: True, False. | Optional |
| activate | Activates the stream at the time of the request, false by default. When Edit a stream or Patch a stream that is active, set this value to true. Possible values are: True, False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStream | unknown | Akamai DataStream. |

### akamai-list-idam-properties

***
Lists the properties and includes for the current account.

#### Base Command

`akamai-list-idam-properties`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Idam.Properties | unknown | Akamai Properties of the current account via Identity Access Management. |

### akamai-list-datastreams

***
Returns the latest versions of the stream configurations for all groups within the account.

#### Base Command

`akamai-list-datastreams`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The unique identifier of the group that has access to the product and this stream configuration. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStreams | unknown | Akamai DataStreams. |

### akamai-get-datastream

***
Returns information about any version of a stream, including details about the monitored properties, logged data set fields, and log delivery destination. If you omit the version query parameter, this operation returns the last version of the stream.

#### Base Command

`akamai-get-datastream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stream_id | Uniquely identifies the stream. | Required |
| version | Identifies the version of the stream. If omitted, the operation returns the latest version of the stream. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStreamDetails | unknown | Akamai DataStream Details. |

### akamai-list-datastream-groups

***
Returns access groups with contracts on your account. You can later use the groupId and contractId values to create and view streams or list properties by group. Set the contractId query parameter to get groups for a specific contract.

#### Base Command

`akamai-list-datastream-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Uniquely identifies the contract that belongs to a group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStreamGroups | unknown | Akamai Groups within the contract. |

### akamai-list-datastream-properties-bygroup

***
Get properties that are active on the production and staging network and available within a specific group. Run this operation to get and store the propertyId values for the Create a stream and Edit a stream operations.

#### Base Command

`akamai-list-datastream-properties-bygroup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The unique identifier of the group that has access to the product and this stream configuration. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStream.Group | unknown | List of the Active Properties within the Group. |

### akamai-delete-datastream

***
Deletes a deactivated stream. Deleting a stream means that you can't activate this stream again, and that you stop receiving logs for the properties that this stream monitors. Before deleting any stream, you need to deactivate it first. See Deactivate a stream.

#### Base Command

`akamai-delete-datastream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stream_id | Unique identifer of a stream. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStream | unknown | Akamai DataStream. |

### akamai-patch-datastream

***
Updates selected details of an existing stream. Running this operation using JSON Patch syntax creates a stream version that replaces the current one. Currently you can patch a stream using only the REPLACE operation. When updating configuration objects such as destination or deliveryConfiguration, pass a complete object to avoid overwriting current details with default values for omitted members such as tags, uploadFilePrefix, and uploadFileSuffix. Note that only active streams collect and send logs to their destinations. You need to set the activate parameter to true while patching active streams, and optionally for inactive streams if you want to activate them upon request. See Patching streams for details.

#### Base Command

`akamai-patch-datastream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stream_id | The unique identifier of the stream. | Required |
| activate | Activates the stream at the time of the request, false by default. When you Edit a stream or Patch a stream that is active, you need to set this member to true. Possible values are: true, false. | Optional |
| path | A JSON Pointer that identifies the values you want to replace in the stream configuration. This member's value is / followed by any of the configuration object's top-level member name. See Edit a stream for available members. | Required |
| value | Specifies the data to replace at the path location, any type of data including objects and arrays. Pass complete objects to avoid overwriting current details with default values for omitted members. | Required |
| value_to_json | Whether convert the value above into Json or not. Possible values are: yes, no. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStream | unknown | Akamai DataStream. |

### akamai-toggle-datastream

***
Activate/Deactivate the latest version of a DataStream.

#### Base Command

`akamai-toggle-datastream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stream_id | Uniquely identifies the stream. | Optional |
| option | activate" or "deactivate. Possible values are: activate, deactivate. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.DataStream.Activation | unknown | Akamai DataStream Activation. |

### akamai-get-client_lists

***
Get accessible client lists.

#### Base Command

`akamai-get-client_lists`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.ClientList | unknown | Akamai ClientList. |

### akamai-list-edgehostname

***
Lists all edge hostnames available under a contract.

#### Base Command

`akamai-list-edgehostname`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| contract_id | Unique identifier of a contract. | Required |
| group_id | Unique identifier of a group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Akamai.Edgehostname | unknown | Akamai Edgehostnames. |

### akamai-generic-api-call-command

***
Akamai Generic API Call.

#### Base Command

`akamai-generic-api-call-command`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| method | Type 'str'. The HTTP method, for example: GET, POST, and so on. Possible values are: GET, POST, PUT, PATCH, DELETE. | Optional |
| url_suffix | Type 'str'. The API endpoint. | Optional |
| headers | Type 'dict'. Headers to send in the request. If None, will use self._headers. | Optional |
| params | Type 'dict'. URL parameters to specify the query. | Optional |
| data | Type 'dict'. The data to send in a 'POST' request. | Optional |
| json_data | Type 'dict'. The dictionary to send in a 'POST' request. | Optional |
| files | Type 'dict'. The file data to send in a 'POST' request. | Optional |
| timeout | Type 'float' or comma separated two floats. The amount of time (in seconds) that a request will wait for a client to establish a connection to a remote machine before a timeout occurs. can be only float (Connection Timeout) or  or Comma separated two floats for Connection Timeout and Read Timeout. (Samput Input: 60, 60). | Optional |
| resp_type | Type 'str'. Determines which data format to return from the HTTP request. The default is 'json'. Other options are 'text', 'content', 'xml' or 'response'. Use 'response' to return the full response object. Possible values are: json, text, content, xml, response. | Optional |
| ok_codes | Type 'tuple'. The request codes to accept as OK, for example: 200, 201, 204. If you specify "None", will use self._ok_codes. Default is None. | Optional |
| retries | Type 'int'. How many retries should be made in case of a failure. when set to '0'- will fail on the first time. | Optional |
| status_list_to_retry | Type 'iterable'. A set of integer HTTP status codes that we should force a retry on. A retry is initiated if the request method is in ['GET', 'POST', 'PUT'] and the response status code is in 'status_list_to_retry'. | Optional |
| backoff_factor | Type 'float'. A backoff factor to apply between attempts after the second try (most errors are resolved immediately by a second try without a delay). urllib3 will sleep for: {backoff factor} * (2 ** ({number of total retries} - 1)) seconds. If the backoff_factor is 0.1, then :func:`.sleep` will sleep for [0.0s, 0.2s, 0.4s, ...] between retries. It will never be longer than :attr:`Retry.BACKOFF_MAX`. By default, backoff_factor set to 5. | Optional |
| raise_on_redirect | Type 'bool'. Whether, if the number of redirects is exhausted, to raise a MaxRetryError, or to return a response with a response code in the 3xx range. Possible values are: True, False. | Optional |
| raise_on_status | Type 'bool'. Similar meaning to 'raise_on_redirect': whether we should raise an exception, or return a response, if status falls in 'status_forcelist' range and retries have been exhausted. Possible values are: True, False. | Optional |
| empty_valid_codes | Type 'list'.A list of all valid status codes of empty responses (usually only 204, but can vary). | Optional |
| with_metrics | Type 'bool'. Whether or not to calculate execution metrics from the response. | Optional |

#### Context Output

There is no context output for this command.
