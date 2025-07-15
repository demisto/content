Use the Microsoft Defender Threat Intelligence integration to query enriched threat intelligence data such as articles, threat actor profiles, WHOIS records, and host-related infrastructure.
This integration was integrated and tested with version 14.0 of MicrosoftDefenderThreatIntelligence.

## Configure MicrosoftDefenderThreatIntelligence in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Application ID (Client ID for Client credentials mode) |  | False |
| Tenant ID (required for Client Credentials mode) |  | False |
| Client Secret (required for Client Credentials mode) | Client Secret. Required for Client Credentials mode\) | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
| Private Key |  | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
| Incident type |  | False |
| Use Client Credentials Authorization Flow | Use a self-deployed Azure application and authenticate using the Client Credentials flow. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msg-defender-threat-intel-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`msg-defender-threat-intel-auth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-auth-complete

***
Run this command to complete the authorization process.
Should be used after running the msgraph-identity-auth-start command.

#### Base Command

`msg-defender-threat-intel-auth-complete`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-article-list

***
Get articles including their properties and relationships.

#### Base Command

`msg-defender-threat-intel-article-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| article_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Filter incidents using "odata" query. | Optional |

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-article-indicators-list

***
Get indicators of threat or compromise related to the contents of an article.

#### Base Command

`msg-defender-threat-intel-article-indicators-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| article_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| article_indicator_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Filter incidents using "odata" query. | Optional |

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-profile-list

***
Get Intelligence Profiles including their properties and relationships.

#### Base Command

`msg-defender-threat-intel-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_profile_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| article_indicator_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Filter incidents using "odata" query. | Optional |

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-profile-indicators-list

***
Get Intelligence Profiles Indicators and their properties.

#### Base Command

`msg-defender-threat-intel-profile-indicators-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_profile_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| intel_profile_indicator_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Filter incidents using "odata" query. | Optional |

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-host

***
Read the properties and relationships of a host object.

#### Base Command

`msg-defender-threat-intel-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Required |
| odata | Filter incidents using "odata" query. | Optional |

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-host-whois

***
Get the specified whoisRecord resource.

#### Base Command

`msg-defender-threat-intel-host-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | hostname or IP address. | Optional |
| whois_record_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| odata | Use "odata" query to customize the response. Supports the $count, $select, $skip, and $top. | Optional |
| limit | Number of records in the list. | Optional |

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-host-whois-history

***
Get the history for a whoisRecord, as represented by a collection of whoisHistoryRecord resources.

#### Base Command

`msg-defender-threat-intel-host-whois-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | hostname or IP address. | Optional |
| whois_record_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| whois_history_record_id | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Optional |
| odata | Use "odata" query to customize the response. Supports the $count, $select, $skip, and $top. | Optional |
| limit | Number of records in the list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BaseIntegration.Output | String | \[Enter a description of the data returned in this output.\] |
