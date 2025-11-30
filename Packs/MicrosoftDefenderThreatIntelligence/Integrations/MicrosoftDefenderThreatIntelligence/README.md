**This integration requires Defender Threat Intelligence—premium version**

Use the Microsoft Defender Threat Intelligence integration to query enriched threat intelligence data such as articles, threat actor profiles, WHOIS records, and host-related infrastructure.

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
Run this command to complete the authorization process.\nShould be used after running the msg-defender-threat-intel-auth-start command.

#### Base Command

`msg-defender-threat-intel-auth-complete`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-auth-test

***
Run this command to test if the authorization process is successful.

#### Base Command

`msg-defender-threat-intel-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### msg-defender-threat-intel-auth-reset

***
Run this command to reset the authorization process.

#### Base Command

`msg-defender-threat-intel-auth-reset`

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
| article_id | Article ID to retrieve specific article details. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Use "odata" query to customize the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.Article.id | String | The unique identifier of the threat intelligence article. |
| MSGDefenderThreatIntel.Article.title | String | The title of the Microsoft Defender Threat Intelligence article. |

### msg-defender-threat-intel-article-indicators-list

***
Get indicators of threat or compromise related to the contents of an article.

#### Base Command

`msg-defender-threat-intel-article-indicators-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| article_id | The unique identifier of the article. | Optional |
| article_indicator_id | The unique identifier of a specific indicator within the article. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Use "odata" query to customize the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.ArticleIndicator.id | String | The unique identifier of the indicator associated with the article. |
| MSGDefenderThreatIntel.ArticleIndicator.artifact.id | String | The unique identifier of the artifact \(e.g., file, domain, IP\) related to the indicator. |

### msg-defender-threat-intel-profile-list

***
Get Intelligence Profiles including their properties and relationships.

#### Base Command

`msg-defender-threat-intel-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_profile_id | The unique identifier of the intelligence profile. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Use "odata" query to customize the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.Profile.id | unknown | The unique identifier of the threat actor profile. |
| MSGDefenderThreatIntel.Profile.title | String | The title or name of the threat actor profile. |

### msg-defender-threat-intel-profile-indicators-list

***
Get Intelligence Profiles Indicators and their properties.

#### Base Command

`msg-defender-threat-intel-profile-indicators-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| intel_profile_id | The unique identifier of the intelligence profile. | Optional |
| intel_profile_indicator_id | The unique identifier of a specific indicator related to an intelligence profile. | Optional |
| limit | Number of incidents in the list. | Optional |
| odata | Use "odata" query to customize the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.ProfileIndicator.id | unknown | The unique identifier of the indicator associated with the threat actor profile. |
| MSGDefenderThreatIntel.ProfileIndicator.artifact.id | String | The unique identifier of the artifact \(e.g., IP address, domain, file hash\) linked to the indicator. |

### msg-defender-threat-intel-host

***
Read the properties and relationships of a host object.

#### Base Command

`msg-defender-threat-intel-host`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The unique identifier of the host. | Required |
| odata | Use "odata" query to customize the response | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.Host.id | unknown | The unique identifier of the host object in Microsoft Defender Threat Intelligence. |
| MSGDefenderThreatIntel.Host.registrar | String | The name of the domain registrar responsible for registering the host. |
| MSGDefenderThreatIntel.Host.registrant | String | The entity \(person or organization\) that registered the host domain. |

### msg-defender-threat-intel-host-whois

***
Get the specified whoisRecord resource.

#### Base Command

`msg-defender-threat-intel-host-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | hostname or IP address. | Optional |
| whois_record_id | The unique identifier of a specific WHOIS record. | Optional |
| odata | Use "odata" query to customize the response. | Optional |
| limit | Number of records in the list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.Whois.id | unknown | The unique identifier of the WHOIS record in Microsoft Defender Threat Intelligence. |
| MSGDefenderThreatIntel.Whois.whoisServer | String | The WHOIS server that provided the domain registration information. |
| MSGDefenderThreatIntel.Whois.domainStatus | String | The current status of the domain \(e.g., active, clientHold, expired\) as reported in the WHOIS record. |

### msg-defender-threat-intel-host-whois-history

***
Get the history for a whoisRecord, as represented by a collection of whoisHistoryRecord resources.

#### Base Command

`msg-defender-threat-intel-host-whois-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | hostname or IP address. | Optional |
| whois_record_id | The unique identifier of the WHOIS record whose history you want to retrieve. | Optional |
| odata | Use "odata" query to customize the response. | Optional |
| limit | Number of records in the list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.WhoisHistory.id | unknown | The unique identifier of the historical WHOIS record. |
| MSGDefenderThreatIntel.WhoisHistory.whoisServer | String | The WHOIS server that provided the historical domain registration data. |
| MSGDefenderThreatIntel.WhoisHistory.domainStatus | String | The domain's status at the time of the historical WHOIS record \(e.g., clientTransferProhibited, inactive\). |

### msg-defender-threat-intel-host

***
Read the properties and relationships of a host object.

#### Base Command

`msg-defender-threat-intel-host-reputation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The unique identifier of the host. | Required |
| odata | Use "odata" query to customize the response. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGDefenderThreatIntel.HostReputation.id | unknown | The unique identifier of the host object in Microsoft Defender Threat Intelligence. |
| MSGDefenderThreatIntel.HostReputation.classification | String | The reputation classification of the host (e.g., Malicious, Suspicious, Unknown). |
| MSGDefenderThreatIntel.HostReputation.score | String | TA numerical score representing the confidence or severity of the host's reputation. |
